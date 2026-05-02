"""FastAPI UI for the CNUCoin lab 2 — registration, transactions and PoW mining."""

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
    """Map CNUCoinID → Label for templates. Includes the GENESIS sentinel and
    the synthetic 'MINING' source so system-issued ledger entries render with
    a friendly name."""
    conn = db.connect()
    try:
        rows = conn.execute(
            "SELECT CNUCoinID, Label FROM CnuCoinMembersTable"
        ).fetchall()
        labels = {r["CNUCoinID"]: r["Label"] for r in rows if r["Label"]}
        labels.setdefault("MINING", "Mining reward")
        return labels
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
def index(request: Request, message: Optional[str] = None, error: Optional[str] = None):
    state = cnucoin.dump_state()
    members = _members_with_balances()
    mined_ta_ids = {b["TAID"] for b in state["blocks"]}
    for tx in state["transactions"]:
        if tx["TAApproved"]:
            tx["status"] = "approved"
        elif tx["TAID"] in mined_ta_ids:
            tx["status"] = "mined"
        else:
            tx["status"] = "pending"
    return templates.TemplateResponse(
        request,
        "index.html",
        {
            "members": members,
            "miners": [m for m in members if m["is_miner"]],
            "labels": _label_map(),
            "transactions": state["transactions"],
            "blocks": state["blocks"],
            "wallet": state["wallet"],
            "pending_count": sum(1 for t in state["transactions"] if t["status"] == "pending"),
            "difficulty": cnucoin.DEFAULT_DIFFICULTY,
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


@app.post("/mine")
def mine(miner_id: str = Form(...), difficulty: int = Form(default=cnucoin.DEFAULT_DIFFICULTY)):
    try:
        stats = cnucoin.mine_next(miner_id, difficulty=difficulty)
    except ValueError as exc:
        return RedirectResponse(url=f"/?error={exc}", status_code=303)
    parts = [
        f"⛏ Mined TAID={stats['ta_id']}",
        f"Nonce={stats['nonce']}",
        f"attempts={stats['attempts']}",
        f"time={stats['elapsed_seconds']*1000:.2f}ms",
        f"hash={stats['block_hash'][:16]}…",
    ]
    if stats["confirmed"]:
        parts.append(
            f"confirmed prior TAID={stats['confirmed']['ta_id']} "
            f"(reward {stats['confirmed']['reward']:.4f})"
        )
    return RedirectResponse(url=f"/?message={' | '.join(parts)}", status_code=303)


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


@app.get("/blocks/{block_id}/verify")
def verify_block(block_id: int):
    try:
        ok = cnucoin.verify_block(block_id)
    except ValueError as exc:
        return RedirectResponse(url=f"/?error={exc}", status_code=303)
    return RedirectResponse(
        url=f"/?message=Block {block_id} {'VALID' if ok else 'INVALID'}",
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
