"""End-to-end demonstration of the electronic gradebook (Variant 4)."""

import json

import db
import gradebook as gb


def banner(title: str) -> None:
    print()
    print("=" * 72)
    print(title)
    print("=" * 72)


def short(uid: str) -> str:
    return uid[:8] + "…"


def main() -> None:
    banner("1. Initialise fresh gradebook database")
    db.init_db(reset=True)
    print(f"DB created at: {db.DB_PATH}")

    banner("2. Register participants (RSA-2048 keypairs)")
    dean = gb.register_member("registrar", "Деканат")
    teacher_a = gb.register_member("teacher", "Іваненко І.І.")
    teacher_b = gb.register_member("teacher", "Петренко П.П.")
    alice = gb.register_member("student", "Коваленко О.О.", group_code="ПЗ-21")
    bob = gb.register_member("student", "Бондар Б.Б.", group_code="ПЗ-21")
    carol = gb.register_member("student", "Шевченко С.С.", group_code="ПЗ-22")

    for m in [dean, teacher_a, teacher_b, alice, bob, carol]:
        print(f"  {m.role:<10} {short(m.member_id)}  «{m.label}»"
              f"{' · ' + m.group_code if m.group_code else ''}")

    banner("3. Add courses")
    blockchain = gb.add_course("Сучасні блокчейн-технології", credits=4.0, semester=7)
    crypto = gb.add_course("Криптографія", credits=3.0, semester=6)
    algo = gb.add_course("Алгоритми та структури даних", credits=5.0, semester=3)
    for c in gb.list_courses():
        print(f"  #{c['CourseID']}  «{c['Name']}»  ({c['Credits']} кр., сем. {c['Semester']})")

    banner("4. Teachers post grades (signed with their private keys)")
    g1 = gb.post_grade(teacher_a.member_id, alice.member_id, blockchain, 92, "Добре виконана лабораторна")
    g2 = gb.post_grade(teacher_a.member_id, alice.member_id, crypto, 85)
    g3 = gb.post_grade(teacher_b.member_id, alice.member_id, algo, 78)
    g4 = gb.post_grade(teacher_a.member_id, bob.member_id, blockchain, 73)
    g5 = gb.post_grade(teacher_b.member_id, bob.member_id, algo, 65)
    g6 = gb.post_grade(teacher_a.member_id, carol.member_id, blockchain, 58)

    for gid in [g1, g2, g3, g4, g5, g6]:
        print(f"  Grade #{gid}: signature valid = {gb.verify_grade(gid)}")

    banner("5. Registrar mines (PoW) each grade in turn")
    for _ in range(6):
        stats = gb.mine_next(dean.member_id, difficulty=1)
        print(f"  ⛏ confirmed #{stats['grade_id']:<2}  "
              f"nonce={stats['nonce']:<5}  attempts={stats['attempts']:<5}  "
              f"time={stats['elapsed_seconds']*1000:.2f}мс  hash={stats['block_hash'][:14]}…")

    banner("6. Transcripts and GPAs")
    for s in [alice, bob, carol]:
        rows = gb.transcript(s.member_id)
        avg = gb.gpa(s.member_id)
        print(f"\n  {s.label} ({s.group_code}) — GPA = {avg:.2f} ({gb.ects_letter(int(avg))})")
        for r in rows:
            print(f"    sem.{r['Semester']}  {r['CourseName']:<35}  "
                  f"{r['Mark']:>3}  ({r['Letter']:<2})  ← {r['TeacherLabel']}")

    banner("7. Whole-chain integrity verification")
    result = gb.verify_chain()
    print(f"  ok={result['ok']}  blocks_checked={result['blocks_checked']}  "
          f"grades_checked={result['grades_checked']}")
    if result["failures"]:
        for f in result["failures"]:
            print(f"   FAIL: {f}")

    banner("8. Tamper detection demo: silently rewrite Carol's failing grade")
    print("  Original grade #6: Mark =", end=" ")
    conn = db.connect()
    try:
        print(conn.execute("SELECT Mark FROM GradesTable WHERE GradeID = 6").fetchone()["Mark"])
        conn.execute("UPDATE GradesTable SET Mark = 95 WHERE GradeID = 6")
        conn.commit()
    finally:
        conn.close()
    result = gb.verify_chain()
    print(f"  After tamper: chain.ok = {result['ok']}")
    for f in result["failures"][:3]:
        print(f"    {f}")

    # Show the underlying mechanism — recomputed GradeHash diverges from stored:
    conn = db.connect()
    try:
        row = conn.execute(
            "SELECT GradeID, TeacherID, StudentID, CourseID, GradeDate, Mark, "
            "       Comment, GradeHash FROM GradesTable WHERE GradeID = 6"
        ).fetchone()
    finally:
        conn.close()
    rehashed = gb._compute_grade_hash(
        row["GradeID"], row["TeacherID"], row["StudentID"], row["CourseID"],
        row["GradeDate"], row["Mark"], row["Comment"],
    )
    print(f"  Stored GradeHash:           {row['GradeHash']}")
    print(f"  Recomputed (with Mark=95):  {rehashed}")
    print(f"  → tamper detected: {row['GradeHash'] != rehashed}")

    banner("9. Final state dump")
    state = gb.dump_state()
    state["gpa"] = {
        m["MemberID"]: gb.gpa(m["MemberID"])
        for m in state["members"] if m["Role"] == db.ROLE_STUDENT
    }
    print(json.dumps(state, indent=2, default=str)[:1500] + "...\n[truncated]")


if __name__ == "__main__":
    main()
