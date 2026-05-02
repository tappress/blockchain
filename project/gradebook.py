"""Core logic for the electronic gradebook (Project Variant 4).

Lifecycle of a grade
--------------------
1. Teacher posts a grade for (student, course, mark, comment) via post_grade().
   The entry is hashed (MD5) over its fields plus the previous block's hash
   and nonce — chaining new entries to existing chain state — and signed by
   the teacher with their RSA private key.
2. A registrar mines the entry via mine_next(): brute-forces a Nonce so that
   MD5(GradeHash || prev_BlockHash || Nonce) starts with `difficulty` zero
   characters. The registrar signs the resulting block hash.
3. Mining a grade marks it Approved=1 in the same transaction. (Unlike Lab 2,
   we do NOT defer confirmation to the next block: a registrar is the trusted
   dean's office, not a competing miner, so there is no incentive game to
   sustain. The chain link + leading-zero rule is sufficient for tamper-
   evidence.)
4. Anyone can verify (a) the teacher's signature on the grade, (b) the block's
   PoW correctness and registrar signature, (c) the entire chain's integrity
   by re-walking it and recomputing each hash.

Grading scale: 0..100 (ECTS). Letter grades are derived in `ects_letter()`.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

import db
import crypto_utils as cu


DEFAULT_DIFFICULTY = 1            # required leading hex zeros in BlockHash


# ---------------------------------------------------------------------------
# Member registration
# ---------------------------------------------------------------------------

@dataclass
class Member:
    member_id: str
    public_key: bytes
    private_key: bytes
    role: str
    label: str
    group_code: Optional[str] = None


def register_member(
    role: str,
    label: str,
    group_code: Optional[str] = None,
) -> Member:
    """Generate keypair, derive ID, persist records.

    Role must be one of {student, teacher, registrar}. Label is the
    human-readable full name (required — academic records always have names).
    `group_code` is meaningful only for students.
    """
    if role not in db.ROLES:
        raise ValueError(f"unknown role: {role}")
    label = (label or "").strip()
    if not label:
        raise ValueError("label is required (academic records need a name)")
    if role != db.ROLE_STUDENT:
        group_code = None
    elif group_code:
        group_code = group_code.strip() or None

    private_pem, public_pem = cu.generate_rsa_keypair()
    member_id = cu.derive_user_id(public_pem)

    conn = db.connect()
    try:
        conn.execute(
            "INSERT INTO MembersTable (MemberID, PublicKey, Role, Label, GroupCode) "
            "VALUES (?, ?, ?, ?, ?)",
            (member_id, public_pem, role, label, group_code),
        )
        conn.execute(
            "INSERT INTO PrivateTable (MemberID, PrivateKey, PublicKey) VALUES (?, ?, ?)",
            (member_id, private_pem, public_pem),
        )
        conn.commit()
    finally:
        conn.close()

    return Member(member_id, public_pem, private_pem, role, label, group_code)


def set_label(member_id: str, label: str) -> None:
    label = (label or "").strip()
    if not label:
        raise ValueError("label cannot be empty")
    conn = db.connect()
    try:
        cur = conn.execute(
            "UPDATE MembersTable SET Label = ? WHERE MemberID = ?",
            (label, member_id),
        )
        if cur.rowcount == 0:
            raise ValueError(f"unknown member: {member_id}")
        conn.commit()
    finally:
        conn.close()


def list_members(role: Optional[str] = None) -> list[dict]:
    conn = db.connect()
    try:
        if role is None:
            rows = conn.execute(
                "SELECT MemberID, Role, Label, GroupCode FROM MembersTable ORDER BY rowid"
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT MemberID, Role, Label, GroupCode FROM MembersTable "
                "WHERE Role = ? ORDER BY rowid",
                (role,),
            ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Courses
# ---------------------------------------------------------------------------

def add_course(name: str, credits: float = 3.0, semester: int = 1) -> int:
    name = (name or "").strip()
    if not name:
        raise ValueError("course name is required")
    if credits <= 0:
        raise ValueError("credits must be positive")
    conn = db.connect()
    try:
        cur = conn.execute(
            "INSERT INTO CoursesTable (Name, Credits, Semester) VALUES (?, ?, ?)",
            (name, credits, semester),
        )
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


def list_courses() -> list[dict]:
    conn = db.connect()
    try:
        rows = conn.execute(
            "SELECT CourseID, Name, Credits, Semester FROM CoursesTable ORDER BY Semester, Name"
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now() -> str:
    return datetime.utcnow().isoformat(timespec="seconds")


def _latest_block(conn) -> Optional[dict]:
    row = conn.execute(
        "SELECT BlockID, BlockHash, Nonce FROM BlockChainTable ORDER BY BlockID DESC LIMIT 1"
    ).fetchone()
    return dict(row) if row else None


def _private_key(conn, member_id: str) -> bytes:
    row = conn.execute(
        "SELECT PrivateKey FROM PrivateTable WHERE MemberID = ?", (member_id,)
    ).fetchone()
    if row is None:
        raise ValueError(f"unknown member: {member_id}")
    return row["PrivateKey"]


def _public_key(conn, member_id: str) -> bytes:
    row = conn.execute(
        "SELECT PublicKey FROM MembersTable WHERE MemberID = ?", (member_id,)
    ).fetchone()
    if row is None:
        raise ValueError(f"unknown member: {member_id}")
    return row["PublicKey"]


def _member_role(conn, member_id: str) -> str:
    row = conn.execute(
        "SELECT Role FROM MembersTable WHERE MemberID = ?", (member_id,)
    ).fetchone()
    if row is None:
        raise ValueError(f"unknown member: {member_id}")
    return row["Role"]


# ---------------------------------------------------------------------------
# Posting a grade (teacher's action; Lab 2 carry-over)
# ---------------------------------------------------------------------------

def _compute_grade_hash(grade_id, teacher_id, student_id, course_id,
                        grade_date, mark, comment) -> str:
    """MD5 over the grade's own fields. Chain linkage is added at the BLOCK
    level (BlockHash mixes GradeHash with prev_BlockHash + nonce) — keeping
    teacher attestation independent of mining order so verification works
    even when grades are posted in batches and mined out-of-band."""
    payload = "|".join([
        str(grade_id),
        teacher_id,
        student_id,
        str(course_id),
        grade_date,
        str(mark),
        comment or "",
    ]).encode("utf-8")
    return cu.md5_hex(payload)


def post_grade(
    teacher_id: str,
    student_id: str,
    course_id: int,
    mark: int,
    comment: Optional[str] = None,
) -> int:
    """Build and sign a new grade entry. Returns the new GradeID.

    The teacher signs MD5 over the grade fields. They do not need to know the
    current chain state — that's the registrar's concern at mining time.
    """
    if not (0 <= mark <= 100):
        raise ValueError("mark must be in 0..100")

    conn = db.connect()
    try:
        if _member_role(conn, teacher_id) != db.ROLE_TEACHER:
            raise ValueError("author of a grade must have role=teacher")
        if _member_role(conn, student_id) != db.ROLE_STUDENT:
            raise ValueError("subject of a grade must have role=student")
        course = conn.execute(
            "SELECT CourseID, Name FROM CoursesTable WHERE CourseID = ?", (course_id,)
        ).fetchone()
        if course is None:
            raise ValueError(f"unknown course: {course_id}")

        grade_date = _now()
        clean_comment = (comment or "").strip() or None

        cur = conn.execute(
            "INSERT INTO GradesTable "
            "(TeacherID, StudentID, CourseID, GradeDate, Mark, Comment, "
            " GradeHash, Nonce, Approved) "
            "VALUES (?, ?, ?, ?, ?, ?, NULL, 0, 0)",
            (teacher_id, student_id, course_id, grade_date, mark, clean_comment),
        )
        grade_id = cur.lastrowid

        grade_hash = _compute_grade_hash(
            grade_id, teacher_id, student_id, course_id,
            grade_date, mark, clean_comment,
        )

        signature = cu.sign_data(_private_key(conn, teacher_id), grade_hash.encode("utf-8"))
        conn.execute(
            "UPDATE GradesTable SET GradeHash = ?, TeacherSign = ? WHERE GradeID = ?",
            (grade_hash, signature, grade_id),
        )
        conn.commit()
        return grade_id
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Mining (registrar's action)
# ---------------------------------------------------------------------------

def unmined_grades() -> list[dict]:
    conn = db.connect()
    try:
        rows = conn.execute(
            "SELECT GradeID, GradeDate, TeacherID, StudentID, CourseID, Mark, GradeHash "
            "FROM GradesTable WHERE Approved = 0 "
            "AND GradeID NOT IN (SELECT GradeID FROM BlockChainTable WHERE GradeID IS NOT NULL) "
            "ORDER BY GradeDate, GradeID"
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def mine_next(registrar_id: str, difficulty: int = DEFAULT_DIFFICULTY) -> dict:
    """Mine the oldest pending grade. Returns mining stats."""
    if difficulty < 1:
        raise ValueError("difficulty must be >= 1")

    conn = db.connect()
    try:
        if _member_role(conn, registrar_id) != db.ROLE_REGISTRAR:
            raise ValueError("only members with role=registrar can mine blocks")

        grade = conn.execute(
            "SELECT GradeID, GradeHash FROM GradesTable WHERE Approved = 0 "
            "AND GradeID NOT IN (SELECT GradeID FROM BlockChainTable WHERE GradeID IS NOT NULL) "
            "ORDER BY GradeDate, GradeID LIMIT 1"
        ).fetchone()
        if grade is None:
            raise ValueError("no pending grades to mine")

        prev = _latest_block(conn)
        prev_hash = prev["BlockHash"] if prev else "0"

        target = "0" * difficulty
        nonce = 0
        attempts = 0
        started = time.perf_counter()
        while True:
            payload = f"{grade['GradeHash']}|{prev_hash}|{nonce}".encode("utf-8")
            digest = cu.md5_hex(payload)
            attempts += 1
            if digest.startswith(target):
                break
            nonce += 1
        elapsed = time.perf_counter() - started

        signature = cu.sign_data(_private_key(conn, registrar_id), digest.encode("utf-8"))

        now = _now()
        conn.execute(
            "INSERT INTO BlockChainTable "
            "(RegistrarID, DateTime, BlockHash, Nonce, RegistrarSign, GradeID) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (registrar_id, now, digest, nonce, signature, grade["GradeID"]),
        )
        conn.execute(
            "UPDATE GradesTable SET Nonce = ?, Approved = 1 WHERE GradeID = ?",
            (nonce, grade["GradeID"]),
        )
        conn.commit()

        return {
            "grade_id": grade["GradeID"],
            "registrar_id": registrar_id,
            "block_hash": digest,
            "nonce": nonce,
            "attempts": attempts,
            "elapsed_seconds": elapsed,
            "difficulty": difficulty,
            "previous_hash": prev_hash,
        }
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Reading / verification
# ---------------------------------------------------------------------------

ECTS_LETTERS = [
    (90, "A"),
    (82, "B"),
    (74, "C"),
    (64, "D"),
    (60, "E"),
    (35, "FX"),
    (0,  "F"),
]


def ects_letter(mark: int) -> str:
    for threshold, letter in ECTS_LETTERS:
        if mark >= threshold:
            return letter
    return "F"


def transcript(student_id: str, only_approved: bool = True) -> list[dict]:
    """Return a student's grades, joined with course and teacher info."""
    conn = db.connect()
    try:
        sql = (
            "SELECT g.GradeID, g.GradeDate, g.Mark, g.Comment, g.Approved, g.Nonce, "
            "       c.CourseID, c.Name AS CourseName, c.Credits, c.Semester, "
            "       t.MemberID AS TeacherID, t.Label AS TeacherLabel "
            "FROM GradesTable g "
            "JOIN CoursesTable c ON c.CourseID = g.CourseID "
            "JOIN MembersTable t ON t.MemberID = g.TeacherID "
            "WHERE g.StudentID = ? "
        )
        params: tuple = (student_id,)
        if only_approved:
            sql += "AND g.Approved = 1 "
        sql += "ORDER BY c.Semester, g.GradeDate"
        rows = conn.execute(sql, params).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["Letter"] = ects_letter(d["Mark"])
            out.append(d)
        return out
    finally:
        conn.close()


def gpa(student_id: str) -> Optional[float]:
    """Credits-weighted average of approved marks, or None if no grades."""
    rows = transcript(student_id, only_approved=True)
    if not rows:
        return None
    total_credits = sum(r["Credits"] for r in rows)
    if total_credits == 0:
        return None
    weighted = sum(r["Mark"] * r["Credits"] for r in rows)
    return weighted / total_credits


def verify_grade(grade_id: int) -> bool:
    """Verify a grade's integrity:
       1. Recompute GradeHash from the current fields and check it matches the
          stored GradeHash. Silently editing Mark/Comment/etc. will break this.
       2. The teacher's RSA signature must verify against the stored GradeHash.
    """
    conn = db.connect()
    try:
        row = conn.execute(
            "SELECT GradeID, TeacherID, StudentID, CourseID, GradeDate, Mark, "
            "       Comment, GradeHash, TeacherSign FROM GradesTable WHERE GradeID = ?",
            (grade_id,),
        ).fetchone()
        if row is None:
            raise ValueError(f"unknown grade: {grade_id}")
        if not row["GradeHash"] or not row["TeacherSign"]:
            return False

        recomputed = _compute_grade_hash(
            row["GradeID"], row["TeacherID"], row["StudentID"], row["CourseID"],
            row["GradeDate"], row["Mark"], row["Comment"],
        )
        if recomputed != row["GradeHash"]:
            return False  # data tampered

        return cu.verify_signature(
            _public_key(conn, row["TeacherID"]),
            row["GradeHash"].encode("utf-8"),
            row["TeacherSign"],
        )
    finally:
        conn.close()


def verify_block(block_id: int, difficulty: int = DEFAULT_DIFFICULTY) -> bool:
    """Recompute block hash, check difficulty target and registrar signature."""
    conn = db.connect()
    try:
        block = conn.execute(
            "SELECT BlockID, RegistrarID, BlockHash, Nonce, RegistrarSign, GradeID "
            "FROM BlockChainTable WHERE BlockID = ?",
            (block_id,),
        ).fetchone()
        if block is None:
            raise ValueError(f"unknown block: {block_id}")
        prev = conn.execute(
            "SELECT BlockHash FROM BlockChainTable WHERE BlockID < ? "
            "ORDER BY BlockID DESC LIMIT 1",
            (block_id,),
        ).fetchone()
        prev_hash = prev["BlockHash"] if prev else "0"
        grade = conn.execute(
            "SELECT GradeHash FROM GradesTable WHERE GradeID = ?", (block["GradeID"],)
        ).fetchone()
        if grade is None or not grade["GradeHash"]:
            return False
        recomputed = cu.md5_hex(
            f"{grade['GradeHash']}|{prev_hash}|{block['Nonce']}".encode("utf-8")
        )
        if recomputed != block["BlockHash"]:
            return False
        if not block["BlockHash"].startswith("0" * difficulty):
            return False
        return cu.verify_signature(
            _public_key(conn, block["RegistrarID"]),
            block["BlockHash"].encode("utf-8"),
            block["RegistrarSign"],
        )
    finally:
        conn.close()


def verify_chain(difficulty: int = DEFAULT_DIFFICULTY) -> dict:
    """Walk the chain and verify every block + every grade signature.

    Returns {"ok": bool, "blocks_checked": int, "failures": list[str]}.
    """
    failures: list[str] = []
    conn = db.connect()
    try:
        blocks = conn.execute(
            "SELECT BlockID FROM BlockChainTable ORDER BY BlockID"
        ).fetchall()
    finally:
        conn.close()

    for row in blocks:
        block_id = row["BlockID"]
        try:
            if not verify_block(block_id, difficulty=difficulty):
                failures.append(f"block #{block_id}: invalid hash/signature/PoW")
        except Exception as exc:
            failures.append(f"block #{block_id}: {exc}")

    # Also verify every approved grade's teacher signature.
    conn = db.connect()
    try:
        approved = conn.execute(
            "SELECT GradeID FROM GradesTable WHERE Approved = 1"
        ).fetchall()
    finally:
        conn.close()

    for row in approved:
        gid = row["GradeID"]
        try:
            if not verify_grade(gid):
                failures.append(f"grade #{gid}: invalid teacher signature")
        except Exception as exc:
            failures.append(f"grade #{gid}: {exc}")

    return {
        "ok": not failures,
        "blocks_checked": len(blocks),
        "grades_checked": len(approved),
        "failures": failures,
    }


# ---------------------------------------------------------------------------
# Snapshot for UI / API
# ---------------------------------------------------------------------------

def dump_state() -> dict:
    conn = db.connect()
    try:
        members = [dict(r) for r in conn.execute(
            "SELECT MemberID, Role, Label, GroupCode FROM MembersTable ORDER BY rowid"
        ).fetchall()]
        courses = [dict(r) for r in conn.execute(
            "SELECT CourseID, Name, Credits, Semester FROM CoursesTable ORDER BY Semester, Name"
        ).fetchall()]
        grades = [dict(r) for r in conn.execute(
            "SELECT GradeID, TeacherID, StudentID, CourseID, GradeDate, Mark, "
            "       Comment, GradeHash, Nonce, Approved FROM GradesTable ORDER BY GradeID"
        ).fetchall()]
        blocks = [dict(r) for r in conn.execute(
            "SELECT BlockID, RegistrarID, DateTime, BlockHash, Nonce, GradeID "
            "FROM BlockChainTable ORDER BY BlockID"
        ).fetchall()]
        return {
            "members": members,
            "courses": courses,
            "grades": grades,
            "blocks": blocks,
        }
    finally:
        conn.close()
