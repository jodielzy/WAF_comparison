# helper.py
from colorlog import ColoredFormatter
from tqdm import tqdm
import urllib.parse
import requests
import logging
import zipfile
import json
import time
import sqlite3
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from config import DB_PATH, DATA_PATH, LEGITIMATE_URL_PATH, MALICIOUS_URL_PATH, LEGITIMATE_PATH, MALICIOUS_PATH, conn

LOG_LEVEL = logging.INFO
LOGFORMAT = "  %(log_color)s%(levelname)-8s%(reset)s | %(log_color)s%(message)s%(reset)s"
logging.root.setLevel(LOG_LEVEL)
formatter = ColoredFormatter(LOGFORMAT)
stream = logging.StreamHandler()
stream.setLevel(LOG_LEVEL)
stream.setFormatter(formatter)
log = logging.getLogger('pythonConfig')
log.setLevel(LOG_LEVEL)
log.addHandler(stream)


def make_session():
    s = requests.Session()
    adapter = HTTPAdapter(
        pool_connections=100,
        pool_maxsize=100,
        max_retries=Retry(total=1, backoff_factor=0.05, status_forcelist=[429, 500, 502, 503, 504]),
    )
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    return s


def load_data(_log_file):
    """
    Load each data set as json file and sanitize headers that break pooling.
    """
    with open(_log_file) as _file:
        data = json.load(_file)

    for item in data:
        headers = item.get("headers") or {}
        # Drop headers that sabotage connection reuse or get auto-set
        for k in list(headers.keys()):
            kl = k.lower()
            if kl in ("connection", "host", "content-length"):
                headers.pop(k)
        # Optional: make keep-alive explicit (servers usually default to it)
        headers.setdefault("Connection", "keep-alive")
        item["headers"] = headers

    return data


def zip_extract(file_to_extract):
    """Extract zip files"""
    with zipfile.ZipFile(file_to_extract, 'r') as zip_ref:
        zip_ref.extractall(DATA_PATH)


def download_file(url, _progress_bar_name):
    response = requests.get(url, stream=True)
    total_size = int(response.headers.get('content-length', 0))
    block_size = 1024  # 1 KB
    progress_bar = tqdm(total=total_size, unit='B', unit_scale=True, desc=f"Downloading {_progress_bar_name}")

    file_path = DATA_PATH / url.split("/")[-1]

    # Download the data set in zip format
    with open(file_path, 'wb') as file:
        for data in response.iter_content(block_size):
            progress_bar.update(len(data))
            file.write(data)

    progress_bar.close()

    # Extract zip data set
    zip_extract(file_path)


def prepare_data():
    if MALICIOUS_PATH.exists():
        log.debug("Malicious Data Set Already Loaded")
    else:
        download_file(MALICIOUS_URL_PATH, "Malicious Data set")
        log.info("Malicious Data Set Preparation Completed.")

    if LEGITIMATE_PATH.exists():
        log.debug("Legitimate Data Set Already Loaded")
    else:
        download_file(LEGITIMATE_URL_PATH, "Legitimate Data set")
        log.info("Legitimate Data Set Preparation Completed.")


def sendRequest(_method, _url, _headers=None, _data=None, _timeout=0.5, session=None):
    # Scrub headers that break pooling or are auto-set by requests
    if _headers:
        for key in list(_headers.keys()):
            kl = key.lower()
            if kl in ("host", "connection", "content-length"):
                _headers.pop(key)
        # Make keep-alive explicit (server may still close, but we won't)
        _headers.setdefault("Connection", "keep-alive")

    attempts = 0
    while attempts < 3:
        try:
            req_session = session or requests
            res = req_session.request(_method, url=_url, headers=_headers, data=_data, timeout=_timeout)
            return [
                res.status_code,
                "The requested URL was rejected. Please consult with your administrator." in res.text
                or res.status_code == 403,
                res.text[:2000]
            ]
        except Exception:
            attempts += 1
            time.sleep(0.1 * attempts)
    return [0, False, "REQUEST FAILED OR TIMED OUT"]


def isTableExists(_table_name):
    """
    Check if table _table_name exists in the SQLite DB.
    """
    cur = conn.cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (_table_name,))
    exists = cur.fetchone() is not None
    cur.close()
    return exists


def dropTableIfExists(_table_name):
    """
    Drop table _table_name if it exists in the SQLite DB.
    Log the drop action only if the table was present.
    """
    if isTableExists(_table_name):
        cur = conn.cursor()
        cur.execute("DROP TABLE {}".format(_table_name))
        conn.commit()  # commit changes to the DB
        log.debug(f"Starting New test, table {_table_name} was dropped")
        cur.close()
