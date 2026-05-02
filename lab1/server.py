"""FastAPI UI for the CNUCoin lab — register users, send and confirm transactions."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

import db
import cnucoin


app = FastAPI(title="CNUCoin")
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


@app.on_event("startup")
def _startup() -> None:
    # Initialise schema (do NOT reset existing data).
    db.init_db(reset=False)


# ---------------------------------------------------------------------------
# Helpers exposed to templates
# ---------------------------------------------------------------------------

def _short(uid: str, n: int = 10) -> str:
    if not uid:
        return ""
    if uid in {"GENESIS"}:
        return uid
    return uid[:n] + "…"


templates.env.filters["short"] = _short


def _members_with_balances() -> list[dict]:
    rows = cnucoin.list_members()
    return [
        {
            "id": r["CNUCoinID"],
            "is_miner": bool(r["IsMiner"]),
            "label": r["Label"],
            "balance": cnucoin.get_balance(r["CNUCoinID"]),
        }
        for r in rows
    ]


def _label_map() -> dict[str, str]:
    """Map CNUCoinID → Label for templates. Includes the GENESIS sentinel so
    system-issued transactions render with a friendly name."""
    conn = db.connect()
    try:
        rows = conn.execute(
            "SELECT CNUCoinID, Label FROM CnuCoinMembersTable"
        ).fetchall()
        return {r["CNUCoinID"]: r["Label"] for r in rows if r["Label"]}
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
def index(request: Request, message: Optional[str] = None, error: Optional[str] = None):
    state = cnucoin.dump_state()
    members = _members_with_balances()
    return templates.TemplateResponse(
        request,
        "index.html",
        {
            "members": members,
            "labels": _label_map(),
            "transactions": state["transactions"],
            "blocks": state["blocks"],
            "wallet": state["wallet"],
            "message": message,
            "error": error,
        },
    )


@app.post("/users")
def create_user(
    label: str = Form(default=""),
    is_miner: Optional[str] = Form(default=None),
    initial_balance: float = Form(default=0.0),
):
    miner_flag = is_miner is not None
    user = cnucoin.register_user(
        is_miner=miner_flag, initial_balance=initial_balance, label=label or None
    )
    nice_name = user.label or user.cnucoin_id[:10] + "…"
    msg = f"Registered {nice_name} (miner={miner_flag}, balance={initial_balance})"
    return RedirectResponse(url=f"/?message={msg}", status_code=303)


@app.post("/users/{user_id}/label")
def rename_user(user_id: str, label: str = Form(default="")):
    try:
        cnucoin.set_label(user_id, label)
    except ValueError as exc:
        return RedirectResponse(url=f"/?error={exc}", status_code=303)
    msg = f"Renamed {user_id[:10]}… → {label.strip() or '(cleared)'}"
    return RedirectResponse(url=f"/?message={msg}", status_code=303)


@app.post("/transactions")
def send_transaction(
    sender: str = Form(...),
    recipient: str = Form(...),
    amount: float = Form(...),
):
    try:
        ta_id = cnucoin.create_transaction(sender, recipient, amount)
    except ValueError as exc:
        return RedirectResponse(url=f"/?error={exc}", status_code=303)
    return RedirectResponse(url=f"/?message=Created transaction TAID={ta_id}", status_code=303)


@app.post("/transactions/{ta_id}/confirm")
def confirm(ta_id: int, miner_id: str = Form(...), nonce: int = Form(default=0)):
    try:
        cnucoin.confirm_transaction(ta_id, miner_id, nonce=nonce)
    except ValueError as exc:
        return RedirectResponse(url=f"/?error={exc}", status_code=303)
    return RedirectResponse(url=f"/?message=Confirmed TAID={ta_id}", status_code=303)


@app.get("/transactions/{ta_id}/verify")
def verify(ta_id: int):
    try:
        ok = cnucoin.verify_transaction(ta_id)
    except ValueError as exc:
        return RedirectResponse(url=f"/?error={exc}", status_code=303)
    return RedirectResponse(
        url=f"/?message=TAID={ta_id} signature {'VALID' if ok else 'INVALID'}",
        status_code=303,
    )


@app.post("/reset")
def reset():
    db.init_db(reset=True)
    return RedirectResponse(url="/?message=Database reset", status_code=303)


# ---------------------------------------------------------------------------
# JSON API (for debugging / curl)
# ---------------------------------------------------------------------------

@app.get("/api/state")
def api_state():
    state = cnucoin.dump_state()
    state["balances"] = {m["id"]: m["balance"] for m in _members_with_balances()}
    return state


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8000, reload=False)
