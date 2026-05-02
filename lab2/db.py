"""SQLite schema for CNUCoin (per Lab 1 appendix)."""

import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).parent / "cnucoin.db"


SCHEMA = """
-- Public registry of all CNUCoin participants.
CREATE TABLE IF NOT EXISTS CnuCoinMembersTable (
    CNUCoinID   TEXT PRIMARY KEY,   -- MD5(public_key)
    PublicKey   BLOB NOT NULL,
    IsMiner     INTEGER NOT NULL DEFAULT 0,
    Label       TEXT                -- optional human-readable wallet name
);

-- Private storage for each user's secret key.
CREATE TABLE IF NOT EXISTS PrivateTable (
    CNUCoinID   TEXT PRIMARY KEY,
    PrivateKey  BLOB NOT NULL,
    PublicKey   BLOB NOT NULL,
    FOREIGN KEY (CNUCoinID) REFERENCES CnuCoinMembersTable(CNUCoinID)
);

-- E-wallet — current balance is computed from confirmed transactions,
-- but we also keep a per-user log of incoming/outgoing operations.
CREATE TABLE IF NOT EXISTS EWalletTable (
    EntryID     INTEGER PRIMARY KEY AUTOINCREMENT,
    CNUCoinID   TEXT NOT NULL,
    TADate      TEXT NOT NULL,
    "From"      TEXT,
    "To"        TEXT,
    TASum       REAL NOT NULL,
    FOREIGN KEY (CNUCoinID) REFERENCES CnuCoinMembersTable(CNUCoinID)
);

-- Transactions ledger.
CREATE TABLE IF NOT EXISTS TransactionsTable (
    TAID        INTEGER PRIMARY KEY AUTOINCREMENT,
    CNUCoinID   TEXT NOT NULL,         -- author of the transaction (sender)
    TADate      TEXT NOT NULL,
    "From"      TEXT NOT NULL,
    "To"        TEXT NOT NULL,
    TASum       REAL NOT NULL,
    TAHash      TEXT,                  -- MD5 of transaction + previous block hash/nonce
    Nonce       INTEGER NOT NULL DEFAULT 0,
    TAApproved  INTEGER NOT NULL DEFAULT 0,
    TAssign     BLOB,                  -- sender's RSA signature
    FOREIGN KEY (CNUCoinID) REFERENCES CnuCoinMembersTable(CNUCoinID)
);

-- Blockchain table — one row per mined block (= one approved transaction here).
CREATE TABLE IF NOT EXISTS BlockChainTable (
    BlockID         INTEGER PRIMARY KEY AUTOINCREMENT,
    MinerID         TEXT,                          -- miner who produced the hash
    DateTime        TEXT NOT NULL,
    BlockChainHash  TEXT NOT NULL,
    Nonce           INTEGER NOT NULL DEFAULT 0,
    BlockAssign     BLOB,                          -- miner's signature
    TAID            INTEGER,                       -- transaction this block confirms
    FOREIGN KEY (MinerID) REFERENCES CnuCoinMembersTable(CNUCoinID),
    FOREIGN KEY (TAID)    REFERENCES TransactionsTable(TAID)
);
"""


def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON")
    conn.row_factory = sqlite3.Row
    return conn


GENESIS_ID = "GENESIS"


def init_db(reset: bool = False) -> None:
    if reset and DB_PATH.exists():
        DB_PATH.unlink()
    conn = connect()
    try:
        conn.executescript(SCHEMA)
        cols = {row["name"] for row in conn.execute("PRAGMA table_info(CnuCoinMembersTable)")}
        if "Label" not in cols:
            conn.execute("ALTER TABLE CnuCoinMembersTable ADD COLUMN Label TEXT")
        # System "GENESIS" account — origin of all seed funds. It has no real
        # keypair (PublicKey = empty BLOB) and is hidden from regular member lists,
        # but it satisfies the FK from TransactionsTable.CNUCoinID and lets us
        # record initial balances as proper, visible transactions.
        conn.execute(
            "INSERT OR IGNORE INTO CnuCoinMembersTable "
            "(CNUCoinID, PublicKey, IsMiner, Label) VALUES (?, ?, 0, ?)",
            (GENESIS_ID, b"", "System Genesis"),
        )
        conn.commit()
    finally:
        conn.close()
