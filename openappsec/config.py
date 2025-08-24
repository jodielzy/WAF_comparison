import sqlite3
from pathlib import Path

# Database configuration
DB_PATH = Path.home() / "waf_compare" / "waf_comparison.db"
DB_PATH.parent.mkdir(parents=True, exist_ok=True)  # Ensure ~/waf_compare exists
print(f"Using DB at: {DB_PATH}")  # Debug print

# Open SQLite connection (with safer options for WSL/Linux)
conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=30)
try:
    # On WSL, WAL often causes issues; force DELETE journal mode
    conn.execute("PRAGMA journal_mode=DELETE;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute("PRAGMA temp_store=MEMORY;")
    conn.execute("PRAGMA busy_timeout=30000;")
except Exception:
    pass

# Data set URLs
LEGITIMATE_URL_PATH = "https://downloads.openappsec.io/waf-comparison-project/legitimate.zip"
MALICIOUS_URL_PATH  = "https://downloads.openappsec.io/waf-comparison-project/malicious.zip"

# Data set Paths
DATA_PATH = Path("Data")
LEGITIMATE_PATH = DATA_PATH / "Legitimate"
MALICIOUS_PATH  = DATA_PATH / "Malicious"

# WAF configuration (edit to your hosts)
WAFS_DICT = {
    "AAP WAF":      "",
    "BunkerWeb WAF":"",
}
