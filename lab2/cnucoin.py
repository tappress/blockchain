"""CNUCoin core for Lab 2: registration, transactions and Proof-of-Work mining.

Mining model (per Lab 2 spec)
-----------------------------
* A transaction is created with TAApproved=0 and no associated block.
* A miner picks the OLDEST unmined transaction (by date/time), then searches
  for a Nonce so that MD5(TAHash || prev_BlockChainHash || Nonce) starts with
  `difficulty` leading zero characters. The lab fixes Difficulty Target so
  that the block must start with a single '0'.
* The found block is inserted into BlockChainTable, signed by the miner.
* A transaction becomes TAApproved=1 only when the NEXT block is mined on top
  of its block. Funds move on confirmation; the miner of the just-confirmed
  block receives a percentage reward.
* The very last block in the chain therefore stays "mined but unconfirmed"
  until somebody mines another block above it — exactly as in real PoW chains.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

import db
import crypto_utils as cu


DEFAULT_DIFFICULTY = 1            # required leading hex zeros (lab spec: "starts with 0")
DEFAULT_REWARD_PCT = 0.05         # miner reward = 5% of confirmed transaction amount


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

@dataclass
class User:
    cnucoin_id: str
    public_key: bytes
    private_key: bytes
    is_miner: bool
    label: Optional[str] = None


def register_user(
    is_miner: bool = False,
    initial_balance: float = 0.0,
    label: Optional[str] = None,
) -> User:
    """Generate keypair, derive ID, persist records, optionally seed balance.

    `label` is an optional human-readable wallet name shown in the UI; it does
    not affect any cryptographic identity (which is still MD5(public_key)).
    """
    private_pem, public_pem = cu.generate_rsa_keypair()
    user_id = cu.derive_user_id(public_pem)
    clean_label = (label or "").strip() or None

    conn = db.connect()
    try:
        conn.execute(
            "INSERT INTO CnuCoinMembersTable (CNUCoinID, PublicKey, IsMiner, Label) "
            "VALUES (?, ?, ?, ?)",
            (user_id, public_pem, 1 if is_miner else 0, clean_label),
        )
        conn.execute(
            "INSERT INTO PrivateTable (CNUCoinID, PrivateKey, PublicKey) VALUES (?, ?, ?)",
            (user_id, private_pem, public_pem),
        )
        if initial_balance > 0:
            ta_date = _now()
            # System-issued ("genesis") transaction — auto-approved, no signature.
            # Stored in TransactionsTable so seed funds are traceable, AND in
            # EWalletTable so the balance is immediately spendable (genesis txs
            # do not need to be mined or wait for a confirming block).
            ta_hash = cu.md5_hex(
                f"GENESIS|{user_id}|{initial_balance:.8f}|{ta_date}".encode("utf-8")
            )
            conn.execute(
                'INSERT INTO TransactionsTable '
                '(CNUCoinID, TADate, "From", "To", TASum, TAHash, Nonce, TAApproved, TAssign) '
                "VALUES (?, ?, ?, ?, ?, ?, 0, 1, NULL)",
                (db.GENESIS_ID, ta_date, db.GENESIS_ID, user_id, initial_balance, ta_hash),
            )
            conn.execute(
                'INSERT INTO EWalletTable (CNUCoinID, TADate, "From", "To", TASum) '
                "VALUES (?, ?, ?, ?, ?)",
                (user_id, ta_date, db.GENESIS_ID, user_id, initial_balance),
            )
        conn.commit()
    finally:
        conn.close()

    return User(user_id, public_pem, private_pem, is_miner, clean_label)


def set_label(user_id: str, label: Optional[str]) -> None:
    """Rename a wallet. Empty string clears the label."""
    clean = (label or "").strip() or None
    conn = db.connect()
    try:
        cursor = conn.execute(
            "UPDATE CnuCoinMembersTable SET Label = ? WHERE CNUCoinID = ?",
            (clean, user_id),
        )
        if cursor.rowcount == 0:
            raise ValueError(f"Unknown user: {user_id}")
        conn.commit()
    finally:
        conn.close()


def list_members() -> list[dict]:
    """Public registry — GENESIS system account is excluded."""
    conn = db.connect()
    try:
        rows = conn.execute(
            "SELECT CNUCoinID, IsMiner, Label FROM CnuCoinMembersTable "
            "WHERE CNUCoinID != ? ORDER BY rowid",
            (db.GENESIS_ID,),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_balance(user_id: str) -> float:
    """Confirmed balance — only entries already in EWalletTable count."""
    conn = db.connect()
    try:
        incoming = conn.execute(
            'SELECT COALESCE(SUM(TASum), 0) FROM EWalletTable WHERE "To" = ?', (user_id,)
        ).fetchone()[0]
        outgoing = conn.execute(
            'SELECT COALESCE(SUM(TASum), 0) FROM EWalletTable WHERE "From" = ?', (user_id,)
        ).fetchone()[0]
        return float(incoming) - float(outgoing)
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now() -> str:
    return datetime.utcnow().isoformat(timespec="seconds")


def _latest_block(conn) -> Optional[dict]:
    row = conn.execute(
        "SELECT BlockID, BlockChainHash, Nonce, MinerID, TAID "
        "FROM BlockChainTable ORDER BY BlockID DESC LIMIT 1"
    ).fetchone()
    return dict(row) if row else None


def _private_key(conn, user_id: str) -> bytes:
    row = conn.execute(
        "SELECT PrivateKey FROM PrivateTable WHERE CNUCoinID = ?", (user_id,)
    ).fetchone()
    if row is None:
        raise ValueError(f"Unknown user: {user_id}")
    return row["PrivateKey"]


def _public_key(conn, user_id: str) -> bytes:
    row = conn.execute(
        "SELECT PublicKey FROM CnuCoinMembersTable WHERE CNUCoinID = ?", (user_id,)
    ).fetchone()
    if row is None:
        raise ValueError(f"Unknown user: {user_id}")
    return row["PublicKey"]


# ---------------------------------------------------------------------------
# Transaction creation (Lab 1 carry-over, with no BlockChainTable side effect)
# ---------------------------------------------------------------------------

def create_transaction(sender_id: str, recipient_id: str, amount: float) -> int:
    if amount <= 0:
        raise ValueError("amount must be positive")
    if sender_id == recipient_id:
        raise ValueError("sender and recipient must differ")
    if get_balance(sender_id) < amount:
        raise ValueError("insufficient confirmed balance")

    conn = db.connect()
    try:
        _public_key(conn, sender_id)
        _public_key(conn, recipient_id)

        prev = _latest_block(conn)
        prev_hash = prev["BlockChainHash"] if prev else "0"
        prev_nonce = prev["Nonce"] if prev else 0

        ta_date = _now()
        cursor = conn.execute(
            'INSERT INTO TransactionsTable '
            '(CNUCoinID, TADate, "From", "To", TASum, TAHash, Nonce, TAApproved) '
            "VALUES (?, ?, ?, ?, ?, NULL, 0, 0)",
            (sender_id, ta_date, sender_id, recipient_id, amount),
        )
        ta_id = cursor.lastrowid

        # MD5 over concatenated fields (TAApproved excluded; TAHash/Nonce
        # replaced by the prev block's BlockChainHash/Nonce — per Lab 1 spec).
        payload = "|".join(
            [
                str(ta_id),
                str(sender_id),
                ta_date,
                str(sender_id),
                str(recipient_id),
                f"{amount:.8f}",
                str(prev_hash),
                str(prev_nonce),
            ]
        ).encode("utf-8")
        ta_hash = cu.md5_hex(payload)

        signature = cu.sign_data(_private_key(conn, sender_id), ta_hash.encode("utf-8"))
        conn.execute(
            "UPDATE TransactionsTable SET TAHash = ?, TAssign = ? WHERE TAID = ?",
            (ta_hash, signature, ta_id),
        )
        conn.commit()
        return ta_id
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Mining (the heart of Lab 2)
# ---------------------------------------------------------------------------

def unmined_transactions() -> list[dict]:
    """Transactions that have no associated block yet (pending mining).

    GENESIS-issued seed transactions are auto-approved and never mined, so
    they're filtered out via TAApproved = 0.
    """
    conn = db.connect()
    try:
        rows = conn.execute(
            'SELECT TAID, TADate, "From", "To", TASum, TAHash FROM TransactionsTable '
            "WHERE TAApproved = 0 "
            "AND TAID NOT IN (SELECT TAID FROM BlockChainTable WHERE TAID IS NOT NULL) "
            "ORDER BY TADate, TAID"
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def mine_next(
    miner_id: str,
    difficulty: int = DEFAULT_DIFFICULTY,
    reward_pct: float = DEFAULT_REWARD_PCT,
) -> dict:
    """Mine the oldest unmined transaction. Returns mining stats."""
    if difficulty < 1:
        raise ValueError("difficulty must be >= 1")

    conn = db.connect()
    try:
        miner_row = conn.execute(
            "SELECT IsMiner FROM CnuCoinMembersTable WHERE CNUCoinID = ?", (miner_id,)
        ).fetchone()
        if miner_row is None:
            raise ValueError(f"Unknown miner: {miner_id}")
        if not miner_row["IsMiner"]:
            raise ValueError("user is not registered as a miner (IsMiner = 0)")

        # 1. Pick the oldest unmined transaction (skip auto-approved genesis txs).
        tx = conn.execute(
            'SELECT TAID, TAHash, TASum, "From" AS sender, "To" AS recipient '
            "FROM TransactionsTable "
            "WHERE TAApproved = 0 "
            "AND TAID NOT IN (SELECT TAID FROM BlockChainTable WHERE TAID IS NOT NULL) "
            "ORDER BY TADate, TAID LIMIT 1"
        ).fetchone()
        if tx is None:
            raise ValueError("no unmined transactions available")

        # 2. Determine the previous block we will chain on top of.
        prev = _latest_block(conn)
        prev_hash = prev["BlockChainHash"] if prev else "0"

        # 3. Proof-of-Work: find Nonce such that MD5(TAHash || prev_hash || Nonce)
        #    starts with `difficulty` leading zeros.
        target = "0" * difficulty
        nonce = 0
        attempts = 0
        started = time.perf_counter()
        while True:
            payload = f"{tx['TAHash']}|{prev_hash}|{nonce}".encode("utf-8")
            digest = cu.md5_hex(payload)
            attempts += 1
            if digest.startswith(target):
                break
            nonce += 1
        elapsed = time.perf_counter() - started

        # 4. Sign the new block hash with the miner's private key.
        signature = cu.sign_data(_private_key(conn, miner_id), digest.encode("utf-8"))

        now = _now()
        conn.execute(
            "INSERT INTO BlockChainTable "
            "(MinerID, DateTime, BlockChainHash, Nonce, BlockAssign, TAID) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (miner_id, now, digest, nonce, signature, tx["TAID"]),
        )
        conn.execute(
            "UPDATE TransactionsTable SET Nonce = ? WHERE TAID = ?",
            (nonce, tx["TAID"]),
        )

        # 5. Mining the new block confirms the *previous* block's transaction.
        confirmed = None
        if prev and prev.get("TAID"):
            prev_tx = conn.execute(
                'SELECT "From" AS sender, "To" AS recipient, TASum, TAApproved '
                "FROM TransactionsTable WHERE TAID = ?",
                (prev["TAID"],),
            ).fetchone()
            if prev_tx and not prev_tx["TAApproved"]:
                conn.execute(
                    'INSERT INTO EWalletTable (CNUCoinID, TADate, "From", "To", TASum) '
                    "VALUES (?, ?, ?, ?, ?)",
                    (prev_tx["sender"], now, prev_tx["sender"], prev_tx["recipient"], prev_tx["TASum"]),
                )
                conn.execute(
                    'INSERT INTO EWalletTable (CNUCoinID, TADate, "From", "To", TASum) '
                    "VALUES (?, ?, ?, ?, ?)",
                    (prev_tx["recipient"], now, prev_tx["sender"], prev_tx["recipient"], prev_tx["TASum"]),
                )
                reward = round(prev_tx["TASum"] * reward_pct, 8)
                if reward > 0 and prev["MinerID"]:
                    conn.execute(
                        'INSERT INTO EWalletTable (CNUCoinID, TADate, "From", "To", TASum) '
                        "VALUES (?, ?, ?, ?, ?)",
                        (prev["MinerID"], now, "MINING", prev["MinerID"], reward),
                    )
                conn.execute(
                    "UPDATE TransactionsTable SET TAApproved = 1 WHERE TAID = ?",
                    (prev["TAID"],),
                )
                confirmed = {
                    "ta_id": prev["TAID"],
                    "miner_id": prev["MinerID"],
                    "reward": reward,
                }

        conn.commit()

        return {
            "ta_id": tx["TAID"],
            "miner_id": miner_id,
            "block_hash": digest,
            "nonce": nonce,
            "attempts": attempts,
            "elapsed_seconds": elapsed,
            "difficulty": difficulty,
            "previous_hash": prev_hash,
            "confirmed": confirmed,
        }
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

def verify_transaction(ta_id: int) -> bool:
    """Verify the sender's RSA signature on the stored TAHash."""
    conn = db.connect()
    try:
        tx = conn.execute(
            'SELECT "From" AS sender, TAHash, TAssign FROM TransactionsTable WHERE TAID = ?',
            (ta_id,),
        ).fetchone()
        if tx is None:
            raise ValueError(f"Unknown transaction: {ta_id}")
        # Genesis (system-issued) transactions have no signature — they are
        # implicitly trusted, the same way Bitcoin's coinbase output is.
        if tx["sender"] == db.GENESIS_ID:
            return tx["TAssign"] is None
        if tx["TAHash"] is None or tx["TAssign"] is None:
            return False
        return cu.verify_signature(
            _public_key(conn, tx["sender"]),
            tx["TAHash"].encode("utf-8"),
            tx["TAssign"],
        )
    finally:
        conn.close()


def verify_block(block_id: int, difficulty: int = DEFAULT_DIFFICULTY) -> bool:
    """Recompute block hash from (TAHash, prev_hash, Nonce), check difficulty
    target and miner signature."""
    conn = db.connect()
    try:
        block = conn.execute(
            "SELECT BlockID, MinerID, BlockChainHash, Nonce, BlockAssign, TAID "
            "FROM BlockChainTable WHERE BlockID = ?",
            (block_id,),
        ).fetchone()
        if block is None:
            raise ValueError(f"Unknown block: {block_id}")
        prev = conn.execute(
            "SELECT BlockChainHash FROM BlockChainTable WHERE BlockID < ? "
            "ORDER BY BlockID DESC LIMIT 1",
            (block_id,),
        ).fetchone()
        prev_hash = prev["BlockChainHash"] if prev else "0"
        ta = conn.execute(
            "SELECT TAHash FROM TransactionsTable WHERE TAID = ?", (block["TAID"],)
        ).fetchone()
        if ta is None:
            return False
        recomputed = cu.md5_hex(
            f"{ta['TAHash']}|{prev_hash}|{block['Nonce']}".encode("utf-8")
        )
        if recomputed != block["BlockChainHash"]:
            return False
        if not block["BlockChainHash"].startswith("0" * difficulty):
            return False
        return cu.verify_signature(
            _public_key(conn, block["MinerID"]),
            block["BlockChainHash"].encode("utf-8"),
            block["BlockAssign"],
        )
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Snapshot
# ---------------------------------------------------------------------------

def dump_state() -> dict:
    conn = db.connect()
    try:
        members = [dict(r) for r in conn.execute(
            "SELECT CNUCoinID, IsMiner, Label FROM CnuCoinMembersTable"
        ).fetchall()]
        wallet = [dict(r) for r in conn.execute(
            'SELECT CNUCoinID, TADate, "From", "To", TASum FROM EWalletTable ORDER BY EntryID'
        ).fetchall()]
        txs = [dict(r) for r in conn.execute(
            'SELECT TAID, CNUCoinID, TADate, "From", "To", TASum, TAHash, '
            "Nonce, TAApproved FROM TransactionsTable ORDER BY TAID"
        ).fetchall()]
        chain = [dict(r) for r in conn.execute(
            "SELECT BlockID, MinerID, DateTime, BlockChainHash, Nonce, TAID "
            "FROM BlockChainTable ORDER BY BlockID"
        ).fetchall()]
        return {"members": members, "wallet": wallet, "transactions": txs, "blocks": chain}
    finally:
        conn.close()
