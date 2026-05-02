"""SQLite schema for the electronic gradebook (Variant 4).

Roles
-----
* student   — receives grades; can read their own transcript
* teacher   — assigns grades; signs each grade entry with their RSA key
* registrar — mines new blocks (the dean's-office equivalent of a miner)

The blockchain stores GRADES instead of monetary transactions. Each grade is
an entry signed by the teacher; a registrar then mines the entry into a block
via Proof-of-Work, just like in Lab 2. The chain link (each block's hash
incorporating the previous block's hash) is what gives the gradebook its
tamper-evident property: once a grade is buried under N blocks of work,
rewriting it requires redoing all N blocks.
"""

import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).parent / "gradebook.db"

ROLE_STUDENT = "student"
ROLE_TEACHER = "teacher"
ROLE_REGISTRAR = "registrar"
ROLES = {ROLE_STUDENT, ROLE_TEACHER, ROLE_REGISTRAR}


SCHEMA = """
-- Public registry of all participants (students, teachers, registrars).
CREATE TABLE IF NOT EXISTS MembersTable (
    MemberID    TEXT PRIMARY KEY,         -- MD5(public_key)
    PublicKey   BLOB NOT NULL,
    Role        TEXT NOT NULL,            -- student | teacher | registrar
    Label       TEXT NOT NULL,            -- "Іван Петренко" — required for academic context
    GroupCode   TEXT                      -- academic group, e.g. "ПЗ-21" (students only)
);

-- Private storage for each member's secret key.
CREATE TABLE IF NOT EXISTS PrivateTable (
    MemberID    TEXT PRIMARY KEY,
    PrivateKey  BLOB NOT NULL,
    PublicKey   BLOB NOT NULL,
    FOREIGN KEY (MemberID) REFERENCES MembersTable(MemberID)
);

-- Academic disciplines.
CREATE TABLE IF NOT EXISTS CoursesTable (
    CourseID    INTEGER PRIMARY KEY AUTOINCREMENT,
    Name        TEXT NOT NULL,
    Credits     REAL NOT NULL DEFAULT 3.0,
    Semester    INTEGER NOT NULL DEFAULT 1
);

-- Grades ledger — analogue of Lab 2's TransactionsTable.
CREATE TABLE IF NOT EXISTS GradesTable (
    GradeID     INTEGER PRIMARY KEY AUTOINCREMENT,
    TeacherID   TEXT NOT NULL,            -- author / signer of the entry
    StudentID   TEXT NOT NULL,            -- subject of the entry
    CourseID    INTEGER NOT NULL,
    GradeDate   TEXT NOT NULL,
    Mark        INTEGER NOT NULL,         -- 0..100 ECTS-compatible scale
    Comment     TEXT,                     -- optional teacher comment
    GradeHash   TEXT,                     -- MD5 of entry + prev block hash/nonce
    Nonce       INTEGER NOT NULL DEFAULT 0,
    Approved    INTEGER NOT NULL DEFAULT 0,
    TeacherSign BLOB,                     -- teacher's RSA signature over GradeHash
    FOREIGN KEY (TeacherID) REFERENCES MembersTable(MemberID),
    FOREIGN KEY (StudentID) REFERENCES MembersTable(MemberID),
    FOREIGN KEY (CourseID)  REFERENCES CoursesTable(CourseID)
);

-- Blockchain table — one row per mined grade.
CREATE TABLE IF NOT EXISTS BlockChainTable (
    BlockID         INTEGER PRIMARY KEY AUTOINCREMENT,
    RegistrarID     TEXT,                 -- who mined the block
    DateTime        TEXT NOT NULL,
    BlockHash       TEXT NOT NULL,        -- MD5(GradeHash | prev_BlockHash | Nonce)
    Nonce           INTEGER NOT NULL DEFAULT 0,
    RegistrarSign   BLOB,                 -- registrar's RSA signature over BlockHash
    GradeID         INTEGER,              -- grade this block confirms
    FOREIGN KEY (RegistrarID) REFERENCES MembersTable(MemberID),
    FOREIGN KEY (GradeID)     REFERENCES GradesTable(GradeID)
);
"""


def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON")
    conn.row_factory = sqlite3.Row
    return conn


def init_db(reset: bool = False) -> None:
    if reset and DB_PATH.exists():
        DB_PATH.unlink()
    conn = connect()
    try:
        conn.executescript(SCHEMA)
        conn.commit()
    finally:
        conn.close()
