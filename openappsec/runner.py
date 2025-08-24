import asyncio
import sqlite3
import os
import socket
import json
import threading
import queue
import datetime
import time
import random
from pathlib import Path
from typing import Iterator, Optional

from tqdm import tqdm
import httpx

from analyzer import analyze_results
from config import WAFS_DICT, DATA_PATH, DB_PATH
from helper import log, prepare_data  # no global-conn DB ops here


# ---------------- DB bootstrap (avoid global conn) ----------------

def ensure_db_dir():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)

def ensure_results_table(fresh: bool = False):
    """(Re)create the results table using a fresh, local connection."""
    ensure_db_dir()
    with sqlite3.connect(DB_PATH) as c:
        try:
            c.execute("PRAGMA journal_mode=WAL;")
            c.execute("PRAGMA synchronous=OFF;")
            c.execute("PRAGMA temp_store=MEMORY;")
        except Exception:
            pass
        if fresh:
            c.execute("DROP TABLE IF EXISTS waf_comparison")
        c.execute("""
        CREATE TABLE IF NOT EXISTS waf_comparison (
            method TEXT,
            url TEXT,
            headers TEXT,
            data TEXT,
            machineName TEXT,
            DestinationURL TEXT,
            WAF_Name TEXT,
            DateTime TEXT,
            TestName TEXT,
            DataSetType TEXT,
            response_status_code INTEGER,
            isBlocked INTEGER,
            response_body TEXT
        );
        """)
    log.info(f"DB ready at {DB_PATH} (fresh={fresh})")

def _safe_text(val):
    """Convert any object to a safe, null-free string for SQLite."""
    if val is None:
        s = ""
    elif isinstance(val, bytes):
        s = val.decode("utf-8", errors="replace")
    elif isinstance(val, str):
        s = val
    else:
        try:
            s = json.dumps(val, ensure_ascii=False)
        except Exception:
            s = str(val)
    return s.replace("\x00", "\uFFFD")

def _flush_to_db(rows, db_conn):
    """Fast executemany insert; writer-thread-owned connection only."""
    if not rows:
        return 0
    out = []
    for r in rows:
        out.append((
            _safe_text(r["method"]),
            _safe_text(r["url"]),
            _safe_text(r["headers"]),
            _safe_text(r["data"]),
            _safe_text(r["machineName"]),
            _safe_text(r["DestinationURL"]),
            _safe_text(r["WAF_Name"]),
            _safe_text(r["DateTime"]),
            _safe_text(r["TestName"]),
            _safe_text(r["DataSetType"]),
            int(r["response_status_code"]),
            int(bool(r["isBlocked"]))
        ))
    with db_conn:
        db_conn.executemany("""
            INSERT INTO waf_comparison (
              method,url,headers,data,machineName,DestinationURL,WAF_Name,DateTime,
              TestName,DataSetType,response_status_code,isBlocked,response_body
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,NULL)
        """, out)
    return len(out)

def _sanitize_headers_for_http2(hdrs: dict | None) -> dict:
    """Drop hop-by-hop headers and anything illegal for HTTP/2 (e.g., Connection)."""
    hdrs = (hdrs or {}).copy()
    for k in list(hdrs.keys()):
        kl = k.lower()
        if kl in ("host", "connection", "content-length", "proxy-connection",
                  "keep-alive", "transfer-encoding", "upgrade"):
            hdrs.pop(k, None)
    return hdrs


# -------------- Streaming JSON (no full file load) --------------

def iter_payloads_from_json(path: Path, limit: Optional[int] = None) -> Iterator[dict]:
    """
    Stream items from a top-level JSON array like:
    [ {payload1}, {payload2}, ... ]

    If limit is provided (SMOKE_N), we load once, optionally shuffle,
    and slice to get a representative subset.
    Without limit, we stream to keep memory lower.
    """
    if limit is not None:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if os.getenv("SMOKE_SHUFFLE", "true").lower() in ("1", "true", "yes", "y"):
            random.shuffle(data)
        data = data[:limit]
        for item in data:
            yield item
        return

    # full streaming path for large runs
    try:
        import ijson  # type: ignore
        with open(path, "rb") as f:
            for item in ijson.items(f, "item"):
                yield item
        return
    except Exception:
        pass  # fall back

    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    for item in data:
        yield item


# -------------------- Runner --------------------

class Wafs:
    """Async HTTP runner with a single writer thread (batched inserts)."""

    def __init__(self):
        self.wafs = WAFS_DICT
        self.inverse_waf_dict = {v: k for k, v in self.wafs.items()}
        self._lock = threading.Lock()

        # ---- Tunables via env ----
        # block detection (fast path skips body inspection)
        self.fast_block_detection = os.getenv("FAST_BLOCK_DETECTION", "true").lower() in ("1", "true", "yes", "y")

        # statuses considered "blocked"
        block_status_csv = os.getenv("BLOCK_STATUS", "403,406,429")
        try:
            self.block_status = {int(x.strip()) for x in block_status_csv.split(",") if x.strip()}
        except Exception:
            self.block_status = {403, 406, 429}

        # phrases signaling a block page (used in slow path)
        default_phrases = [
            "The requested URL was rejected. Please consult with your administrator.",
            "Request blocked by",
            "Access denied",
            "ModSecurity Action",
            "403 Forbidden",
        ]
        extra_phrases = [p.strip() for p in os.getenv("BLOCK_PHRASES", "").split("||") if p.strip()]
        self.block_phrases = default_phrases + extra_phrases

        # limit how much body to peek in slow mode
        self.peek_bytes = int(os.getenv("PEEK_BYTES", "2048"))

        # HTTP timeouts
        self.connect_t = float(os.getenv("HTTP_CONNECT_TIMEOUT", "4.0"))
        self.read_t    = float(os.getenv("HTTP_READ_TIMEOUT",    "6.0"))
        self.write_t   = float(os.getenv("HTTP_WRITE_TIMEOUT",   "4.0"))
        self.pool_t    = float(os.getenv("HTTP_POOL_TIMEOUT",    "4.0"))

        # Malicious-only timeouts & retry
        self.mal_connect_t = float(os.getenv("MAL_HTTP_CONNECT_TIMEOUT", str(self.connect_t)))
        self.mal_read_t    = float(os.getenv("MAL_HTTP_READ_TIMEOUT",    "10.0"))
        self.mal_write_t   = float(os.getenv("MAL_HTTP_WRITE_TIMEOUT",   str(self.write_t)))
        self.mal_retries   = int(os.getenv("MAL_HTTP_RETRIES",           "1"))

        # Concurrency limits
        self.max_inflight       = int(os.getenv("ASYNC_MAX_INFLIGHT", "5000"))
        self.sem_concurrency    = int(os.getenv("ASYNC_CONCURRENCY", "800"))     # for Legitimate
        self.mal_sem_concurrency = int(os.getenv("MALICIOUS_CONCURRENCY", "25")) # smaller for Malicious

    def get_waf_name_by_url(self, url):
        return self.inverse_waf_dict[url]

    def check_connection(self):
        """Quick sync health checks (HTTP/1.1 is fine here)."""
        import requests
        from requests.adapters import HTTPAdapter
        s = requests.Session()
        s.mount("http://", HTTPAdapter(pool_connections=10, pool_maxsize=10))
        s.mount("https://", HTTPAdapter(pool_connections=10, pool_maxsize=10))

        failed = False
        log.info(f"Starting run. DB={DB_PATH}  Hosts={list(self.wafs.keys())}")
        log.debug("Initiating health check to confirm proper connectivity configurations.")
        for name, url in self.wafs.items():
            try:
                r = s.get(url, timeout=3)
                if r.status_code == 200:
                    log.info(f"Health check passed - WAF: {name}")
                else:
                    log.error(f"Health check failed - WAF: {name} - please allow: {url} (status={r.status_code})")
                    failed = True
            except Exception as e:
                log.error(f"Health check failed - WAF: {name} - {e}")
                failed = True

        log.debug("Initiating WAF functionality verification (basic XSS should be blocked).")
        for name, url in self.wafs.items():
            try:
                r = s.get(url + "/?a=<script>alert(1)</script>", timeout=3)
                blocked = (r.status_code in self.block_status) or any(p in r.text for p in self.block_phrases)
                if blocked:
                    log.info(f"WAF functionality check passed - WAF: {name}")
                else:
                    log.error(f"WAF functionality check failed - WAF: {name} - should block basic XSS")
                    failed = True
            except Exception as e:
                log.error(f"WAF functionality check (malicious) failed - WAF: {name} - {e}")
                failed = True

        if failed:
            raise ConnectionError("Connectivity/WAF checks failed; fix config and re-run.")
        log.info("All connectivity tests passed.")

    async def send_payloads_async(self):
        """Async HTTP scheduler with backpressure feeding a writer thread."""
        if not self.wafs:
            log.warning("WAFS_DICT is empty, skipping payload send step.")
            return

        # Fresh table using a local connection (no global conn here)
        ensure_results_table(fresh=True)

        # --- scan dataset and pre-count total requests (for % bar) ---
        test_files = list(DATA_PATH.rglob("*.json"))
        SMOKE_N = int(os.getenv("SMOKE_N", "0")) or None
        total_requests = 0
        for p in test_files:
            try:
                if SMOKE_N:
                    cnt = sum(1 for _ in iter_payloads_from_json(p, limit=SMOKE_N))
                else:
                    cnt = sum(1 for _ in iter_payloads_from_json(p))
            except Exception:
                cnt = 0
            total_requests += cnt * len(self.wafs)
        log.info(f"Submitting & running payloads: 0 / {total_requests}")

        # Async clients per WAF
        limits = httpx.Limits(max_keepalive_connections=1000, max_connections=1000)
        default_timeouts = httpx.Timeout(connect=self.connect_t, read=self.read_t, write=self.write_t, pool=self.pool_t)
        mal_timeouts     = httpx.Timeout(connect=self.mal_connect_t, read=self.mal_read_t, write=self.mal_write_t, pool=self.pool_t)

        clients = {}
        for waf_name, url in self.wafs.items():
            # Use HTTP/1.1 for BunkerWeb to avoid H2 stalls under load
            use_h2 = (waf_name.find("BunkerWeb") == -1)
            clients[url] = httpx.AsyncClient(http2=use_h2, limits=limits, timeout=default_timeouts)

        # Writer thread + queue
        q = queue.Queue(maxsize=10000)
        stop = object()
        BATCH_SIZE = 10000

        def writer():
            local = sqlite3.connect(DB_PATH)
            try:
                try:
                    local.execute("PRAGMA journal_mode=WAL;")
                    local.execute("PRAGMA synchronous=OFF;")
                    local.execute("PRAGMA temp_store=MEMORY;")
                except Exception:
                    pass

                buf = []
                while True:
                    item = q.get()
                    if item is stop:
                        break
                    buf.append(item)
                    if len(buf) >= BATCH_SIZE:
                        _flush_to_db(buf, local)
                        buf.clear()
                if buf:
                    _flush_to_db(buf, local)
            finally:
                local.close()

        wt = threading.Thread(target=writer, daemon=True)
        wt.start()

        # ---------------- Request worker ----------------

        async def one_request(
            client: httpx.AsyncClient,
            method: str,
            url: str,
            headers: dict,
            data,
            inspect_body: bool,
            timeouts: httpx.Timeout,
            retries: int,
        ):
            headers = _sanitize_headers_for_http2(headers)
            attempt = 0
            while True:
                try:
                    if self.fast_block_detection and not inspect_body:
                        # FAST path: status-only
                        r = await client.request(method, url, headers=headers, data=data, timeout=timeouts)
                        blocked = (r.status_code in self.block_status)
                        return r.status_code, blocked, ""
                    else:
                        # SLOW path: do not read full body; peek only up to self.peek_bytes
                        async with client.stream(method, url, headers=headers, data=data, timeout=timeouts) as r:
                            status = r.status_code
                            if status in self.block_status:
                                return status, True, ""

                            # Read incrementally, up to peek_bytes
                            total = 0
                            chunks = []
                            try:
                                async for chunk in r.aiter_bytes():
                                    if not chunk:
                                        break
                                    chunks.append(chunk)
                                    total += len(chunk)
                                    if total >= self.peek_bytes:
                                        break
                            except (httpx.ReadTimeout, httpx.TimeoutException):
                                text = (b"".join(chunks)[: self.peek_bytes]).decode("utf-8", "ignore") if chunks else ""
                                blocked = any(p in text for p in self.block_phrases)
                                return status, blocked, text

                            text = (b"".join(chunks)[: self.peek_bytes]).decode("utf-8", "ignore") if chunks else ""
                            blocked = any(p in text for p in self.block_phrases)
                            return status, blocked, text
                except (httpx.ConnectTimeout, httpx.ReadTimeout, httpx.WriteTimeout,
                        httpx.TimeoutException, httpx.RemoteProtocolError):
                    attempt += 1
                    if attempt > retries:
                        return 0, False, "REQUEST FAILED OR TIMED OUT"
                    await asyncio.sleep(0.05 * attempt)  # tiny backoff
                except Exception:
                    return 0, False, "REQUEST FAILED OR TIMED OUT"

        # Concurrency & backpressure
        MAX_INFLIGHT = self.max_inflight
        sem_legit = asyncio.Semaphore(self.sem_concurrency)
        sem_mal   = asyncio.Semaphore(self.mal_sem_concurrency)
        pending = set()

        async def schedule(payload, base_url, client, test_path):
            method = str(payload["method"])
            rel_url = str(payload["url"])
            headers = payload.get("headers") or {}
            data = payload.get("data")

            # Force body inspection for Malicious to catch non-403 block pages,
            # while keeping fast detection for Legitimate
            dataset_type = test_path.parent.stem
            inspect_body = (dataset_type.lower() == "malicious")

            sem      = sem_mal if inspect_body else sem_legit
            timeouts = mal_timeouts if inspect_body else default_timeouts
            retries  = self.mal_retries if inspect_body else 0

            async with sem:
                status, blocked, body = await one_request(
                    client, method, base_url + rel_url, headers, data, inspect_body, timeouts, retries
                )

            # Keep body only if we inspected (useful for later reports)
            body = body if inspect_body else ""

            q.put({
                "method": method,
                "url": rel_url,
                "headers": headers,         # raw; serialized by writer
                "data": data,               # raw; serialized by writer
                "machineName": socket.gethostname(),
                "DestinationURL": base_url,
                "WAF_Name": self.get_waf_name_by_url(base_url),
                "DateTime": datetime.datetime.now().isoformat(timespec="seconds"),
                "TestName": test_path.stem,
                "DataSetType": dataset_type,
                "response_status_code": status,
                "isBlocked": blocked,
                "response_body": body,
            })

        # Drive the loop with a simple percentage bar + x/total logging
        processed = 0
        last_log_time = time.time()
        try:
            with tqdm(total=total_requests, desc="Submitting & running payloads", unit="req") as pbar:
                for test_path in test_files:
                    for payload in iter_payloads_from_json(test_path, limit=SMOKE_N):
                        for base_url, client in clients.items():
                            task = asyncio.create_task(schedule(payload, base_url, client, test_path))
                            pending.add(task)
                            processed += 1
                            pbar.update(1)
                            # log every 5 seconds
                            now = time.time()
                            if now - last_log_time >= 5 or processed == total_requests:
                                log.info(f"Submitting & running payloads: {processed} / {total_requests}")
                                last_log_time = now

                            if len(pending) >= MAX_INFLIGHT:
                                done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)

                # drain remaining
                while pending:
                    done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
        finally:
            # Always close clients and stop writer, even on Ctrl-C
            await asyncio.gather(*(c.aclose() for c in clients.values()), return_exceptions=True)
            q.put(stop)
            wt.join(timeout=30)

        # Quick DB snapshot (optional, concise)
        self._print_db_counts()

    @staticmethod
    def _print_db_counts():
        with sqlite3.connect(DB_PATH) as c:
            rows = c.execute("""
              SELECT WAF_Name,
                     SUM(CASE WHEN response_status_code!=0 THEN 1 ELSE 0 END) AS nonzero,
                     COUNT(*) AS total,
                     SUM(CASE WHEN response_status_code=403 THEN 1 ELSE 0 END) AS blocks_403,
                     SUM(CASE WHEN isBlocked=1 THEN 1 ELSE 0 END) AS blocks_detected
              FROM waf_comparison
              GROUP BY WAF_Name
            """).fetchall()

            per_ds = c.execute("""
              SELECT WAF_Name, DataSetType,
                     SUM(CASE WHEN response_status_code!=0 THEN 1 ELSE 0 END) AS nonzero,
                     SUM(CASE WHEN isBlocked=1 THEN 1 ELSE 0 END) AS detected_blocks
              FROM waf_comparison
              GROUP BY WAF_Name, DataSetType
              ORDER BY WAF_Name, DataSetType
            """).fetchall()

        log.info("=== DB Results Snapshot ===")
        for name, nonzero, total, blocks_403, blocks_detected in rows:
            log.info(f"WAF {name}: non-zero={nonzero}/{total}  403={blocks_403}  detected_blocks={blocks_detected}")

        for name, ds, nonzero, detected in per_ds:
            log.info(f"    -> {name} [{ds}]: non-zero={nonzero}  detected_blocks={detected}")

def main():
    log.info("==== WAF Comparison Runner: START ====")
    log.info(f"Data path: {DATA_PATH} | DB: {DB_PATH}")
    wafs = Wafs()
    wafs.check_connection()
    prepare_data()
    try:
        asyncio.run(wafs.send_payloads_async())
    except KeyboardInterrupt:
        log.warning("Interrupted by user. Attempted graceful shutdown.")
    analyze_results()
    log.info("==== WAF Comparison Runner: END ====")


if __name__ == "__main__":
    main()
