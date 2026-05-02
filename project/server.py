"""FastAPI UI for the electronic gradebook (Project Variant 4)."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

import db
import gradebook as gb


app = FastAPI(title="Електронна залікова книжка")
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


@app.on_event("startup")
def _startup() -> None:
    db.init_db(reset=False)


# ---------------------------------------------------------------------------
# Template helpers
# ---------------------------------------------------------------------------

def _short(uid: str, n: int = 10) -> str:
    if not uid:
        return ""
    return uid[:n] + "…"


templates.env.filters["short"] = _short
templates.env.filters["letter"] = gb.ects_letter


def _label_map() -> dict[str, str]:
    conn = db.connect()
    try:
        rows = conn.execute("SELECT MemberID, Label FROM MembersTable").fetchall()
        return {r["MemberID"]: r["Label"] for r in rows}
    finally:
        conn.close()


def _course_map() -> dict[int, dict]:
    return {c["CourseID"]: c for c in gb.list_courses()}


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
def index(
    request: Request,
    student_id: Optional[str] = None,
    message: Optional[str] = None,
    error: Optional[str] = None,
):
    state = gb.dump_state()
    members = state["members"]
    students = [m for m in members if m["Role"] == db.ROLE_STUDENT]
    teachers = [m for m in members if m["Role"] == db.ROLE_TEACHER]
    registrars = [m for m in members if m["Role"] == db.ROLE_REGISTRAR]

    # Augment grades with status + course/teacher labels.
    mined_ids = {b["GradeID"] for b in state["blocks"]}
    labels = _label_map()
    courses = _course_map()
    for g in state["grades"]:
        if g["Approved"]:
            g["status"] = "approved"
        elif g["GradeID"] in mined_ids:
            g["status"] = "mined"
        else:
            g["status"] = "pending"
        g["letter"] = gb.ects_letter(g["Mark"])

    selected_student = None
    selected_transcript: list[dict] = []
    selected_gpa: Optional[float] = None
    if student_id:
        selected_student = next((m for m in students if m["MemberID"] == student_id), None)
        if selected_student:
            selected_transcript = gb.transcript(student_id, only_approved=False)
            selected_gpa = gb.gpa(student_id)

    pending_count = sum(1 for g in state["grades"] if g["status"] == "pending")

    return templates.TemplateResponse(
        request,
        "index.html",
        {
            "members": members,
            "students": students,
            "teachers": teachers,
            "registrars": registrars,
            "courses": state["courses"],
            "course_map": courses,
            "labels": labels,
            "grades": state["grades"],
            "blocks": state["blocks"],
            "pending_count": pending_count,
            "difficulty": gb.DEFAULT_DIFFICULTY,
            "selected_student": selected_student,
            "selected_transcript": selected_transcript,
            "selected_gpa": selected_gpa,
            "message": message,
            "error": error,
        },
    )


@app.post("/members")
def create_member(
    role: str = Form(...),
    label: str = Form(...),
    group_code: str = Form(default=""),
):
    try:
        member = gb.register_member(role=role, label=label, group_code=group_code or None)
    except ValueError as exc:
        return RedirectResponse(url=f"/?error={exc}", status_code=303)
    msg = f"Зареєстровано {member.role} «{member.label}»"
    return RedirectResponse(url=f"/?message={msg}", status_code=303)


@app.post("/members/{member_id}/label")
def rename_member(member_id: str, label: str = Form(...)):
    try:
        gb.set_label(member_id, label)
    except ValueError as exc:
        return RedirectResponse(url=f"/?error={exc}", status_code=303)
    return RedirectResponse(url=f"/?message=Перейменовано → {label}", status_code=303)


@app.post("/courses")
def create_course(
    name: str = Form(...),
    credits: float = Form(default=3.0),
    semester: int = Form(default=1),
):
    try:
        cid = gb.add_course(name=name, credits=credits, semester=semester)
    except ValueError as exc:
        return RedirectResponse(url=f"/?error={exc}", status_code=303)
    return RedirectResponse(url=f"/?message=Дисципліна #{cid} додана", status_code=303)


@app.post("/grades")
def submit_grade(
    teacher_id: str = Form(...),
    student_id: str = Form(...),
    course_id: int = Form(...),
    mark: int = Form(...),
    comment: str = Form(default=""),
):
    try:
        gid = gb.post_grade(teacher_id, student_id, course_id, mark, comment or None)
    except ValueError as exc:
        return RedirectResponse(url=f"/?error={exc}", status_code=303)
    return RedirectResponse(url=f"/?message=Створено оцінку #{gid} (очікує підтвердження)", status_code=303)


@app.post("/mine")
def mine(registrar_id: str = Form(...), difficulty: int = Form(default=gb.DEFAULT_DIFFICULTY)):
    try:
        stats = gb.mine_next(registrar_id, difficulty=difficulty)
    except ValueError as exc:
        return RedirectResponse(url=f"/?error={exc}", status_code=303)
    msg = (
        f"⛏ Підтверджено оцінку #{stats['grade_id']} | "
        f"nonce={stats['nonce']} | attempts={stats['attempts']} | "
        f"time={stats['elapsed_seconds']*1000:.2f}мс | "
        f"hash={stats['block_hash'][:16]}…"
    )
    return RedirectResponse(url=f"/?message={msg}", status_code=303)


@app.get("/grades/{grade_id}/verify")
def verify_grade_route(grade_id: int):
    try:
        ok = gb.verify_grade(grade_id)
    except ValueError as exc:
        return RedirectResponse(url=f"/?error={exc}", status_code=303)
    return RedirectResponse(
        url=f"/?message=Оцінка #{grade_id}: підпис {'ВАЛІДНИЙ' if ok else 'НЕВАЛІДНИЙ'}",
        status_code=303,
    )


@app.get("/blocks/{block_id}/verify")
def verify_block_route(block_id: int):
    try:
        ok = gb.verify_block(block_id)
    except ValueError as exc:
        return RedirectResponse(url=f"/?error={exc}", status_code=303)
    return RedirectResponse(
        url=f"/?message=Блок #{block_id}: {'ВАЛІДНИЙ' if ok else 'НЕВАЛІДНИЙ'}",
        status_code=303,
    )


@app.get("/chain/verify")
def verify_chain_route():
    result = gb.verify_chain()
    if result["ok"]:
        msg = (
            f"✓ Ланцюг цілісний: перевірено {result['blocks_checked']} блок(и/ів) "
            f"та {result['grades_checked']} оцінок"
        )
        return RedirectResponse(url=f"/?message={msg}", status_code=303)
    err = " | ".join(result["failures"][:3])
    return RedirectResponse(url=f"/?error=Ланцюг ПОШКОДЖЕНИЙ: {err}", status_code=303)


@app.post("/reset")
def reset():
    db.init_db(reset=True)
    return RedirectResponse(url="/?message=База даних очищена", status_code=303)


# ---------------------------------------------------------------------------
# JSON API
# ---------------------------------------------------------------------------

@app.get("/api/state")
def api_state():
    state = gb.dump_state()
    state["gpa"] = {
        m["MemberID"]: gb.gpa(m["MemberID"])
        for m in state["members"]
        if m["Role"] == db.ROLE_STUDENT
    }
    return state


@app.get("/api/transcript/{student_id}")
def api_transcript(student_id: str):
    return {
        "student_id": student_id,
        "transcript": gb.transcript(student_id, only_approved=False),
        "gpa": gb.gpa(student_id),
    }


@app.get("/api/chain/verify")
def api_verify_chain():
    return gb.verify_chain()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8000, reload=False)
