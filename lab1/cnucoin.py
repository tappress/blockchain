"""CNUCoin core: user registration, balances, transactions and chain linking."""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

import db
import crypto_utils as cu


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
            # System-issued ("genesis") transaction. It has no signature
            # because GENESIS is not a real cryptographic identity; verify
            # treats it as inherently trusted.
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
    """Balance = sum of inbound entries minus outbound entries in the wallet."""
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
# Transactions and blockchain linking
# ---------------------------------------------------------------------------

def _now() -> str:
    return datetime.utcnow().isoformat(timespec="seconds")


def _last_block(conn) -> Optional[dict]:
    row = conn.execute(
        "SELECT BlockChainHash, Nonce FROM BlockChainTable ORDER BY BlockID DESC LIMIT 1"
    ).fetchone()
    return dict(row) if row else None


def _get_private_key(conn, user_id: str) -> bytes:
    row = conn.execute(
        "SELECT PrivateKey FROM PrivateTable WHERE CNUCoinID = ?", (user_id,)
    ).fetchone()
    if row is None:
        raise ValueError(f"Unknown user: {user_id}")
    return row["PrivateKey"]


def _get_public_key(conn, user_id: str) -> bytes:
    row = conn.execute(
        "SELECT PublicKey FROM CnuCoinMembersTable WHERE CNUCoinID = ?", (user_id,)
    ).fetchone()
    if row is None:
        raise ValueError(f"Unknown user: {user_id}")
    return row["PublicKey"]


def create_transaction(sender_id: str, recipient_id: str, amount: float) -> int:
    """
    Build and sign a transaction.

    Per the lab spec, after filling the transaction fields we concatenate them
    (excluding TAApproved), substituting BlockChainHash / Nonce from the latest
    block in BlockChainTable in place of the transaction's own TAHash / Nonce,
    hash the result with MD5, and store the digest as both TAHash on the
    transaction and BlockChainHash on a new (unconfirmed) block row. The sender
    signs the digest with their private key.

    Returns the new TAID.
    """
    if amount <= 0:
        raise ValueError("amount must be positive")
    if sender_id == recipient_id:
        raise ValueError("sender and recipient must differ")

    if get_balance(sender_id) < amount:
        raise ValueError("insufficient funds")

    conn = db.connect()
    try:
        # Verify both parties exist.
        _get_public_key(conn, sender_id)
        _get_public_key(conn, recipient_id)

        prev = _last_block(conn)
        prev_hash = prev["BlockChainHash"] if prev else "0"
        prev_nonce = prev["Nonce"] if prev else 0

        ta_date = _now()
        # Insert preliminary row to get an auto-incremented TAID.
        cursor = conn.execute(
            'INSERT INTO TransactionsTable '
            '(CNUCoinID, TADate, "From", "To", TASum, TAHash, Nonce, TAApproved) '
            "VALUES (?, ?, ?, ?, ?, NULL, 0, 0)",
            (sender_id, ta_date, sender_id, recipient_id, amount),
        )
        ta_id = cursor.lastrowid

        # Concatenate fields (TAApproved excluded; TAHash/Nonce replaced by
        # BlockChainHash/Nonce of the previous block).
        payload = "|".join(
            [
                str(ta_id),
                str(sender_id),
                ta_date,
                str(sender_id),       # From
                str(recipient_id),    # To
                f"{amount:.8f}",
                str(prev_hash),       # in place of TAHash
                str(prev_nonce),      # in place of Nonce
            ]
        ).encode("utf-8")

        ta_hash = cu.md5_hex(payload)

        # Sender signs the hash digest.
        private_pem = _get_private_key(conn, sender_id)
        signature = cu.sign_data(private_pem, ta_hash.encode("utf-8"))

        conn.execute(
            "UPDATE TransactionsTable SET TAHash = ?, TAssign = ? WHERE TAID = ?",
            (ta_hash, signature, ta_id),
        )
        # Append an unconfirmed block carrying this hash. Miner / Nonce / signature
        # will be filled in when the next lab confirms it.
        conn.execute(
            "INSERT INTO BlockChainTable (DateTime, BlockChainHash, Nonce, TAID) "
            "VALUES (?, ?, 0, ?)",
            (ta_date, ta_hash, ta_id),
        )
        conn.commit()
        return ta_id
    finally:
        conn.close()


def confirm_transaction(ta_id: int, miner_id: str, nonce: int = 0) -> None:
    """
    Mark transaction as approved by a miner. In Lab 1 there is no real PoW yet,
    so we accept any miner and any nonce. The miner signs the block hash.

    Approval flips TAApproved=1 and moves funds in EWalletTable.
    """
    conn = db.connect()
    try:
        miner = conn.execute(
            "SELECT IsMiner FROM CnuCoinMembersTable WHERE CNUCoinID = ?", (miner_id,)
        ).fetchone()
        if miner is None or not miner["IsMiner"]:
            raise ValueError("confirming user is not a registered miner")

        tx = conn.execute(
            'SELECT TAID, "From" AS sender, "To" AS recipient, TASum, TAApproved '
            "FROM TransactionsTable WHERE TAID = ?",
            (ta_id,),
        ).fetchone()
        if tx is None:
            raise ValueError(f"Unknown transaction: {ta_id}")
        if tx["TAApproved"]:
            return  # already confirmed

        block = conn.execute(
            "SELECT BlockID, BlockChainHash FROM BlockChainTable WHERE TAID = ?",
            (ta_id,),
        ).fetchone()
        if block is None:
            raise ValueError("no block row pending for this transaction")

        miner_pk = _get_private_key(conn, miner_id)
        block_signature = cu.sign_data(miner_pk, block["BlockChainHash"].encode("utf-8"))

        conn.execute(
            "UPDATE BlockChainTable SET MinerID = ?, Nonce = ?, BlockAssign = ?, "
            "DateTime = ? WHERE BlockID = ?",
            (miner_id, nonce, block_signature, _now(), block["BlockID"]),
        )
        conn.execute(
            "UPDATE TransactionsTable SET TAApproved = 1, Nonce = ? WHERE TAID = ?",
            (nonce, ta_id),
        )
        # Move funds in the wallet ledger.
        ts = _now()
        conn.execute(
            'INSERT INTO EWalletTable (CNUCoinID, TADate, "From", "To", TASum) '
            "VALUES (?, ?, ?, ?, ?)",
            (tx["sender"], ts, tx["sender"], tx["recipient"], tx["TASum"]),
        )
        conn.execute(
            'INSERT INTO EWalletTable (CNUCoinID, TADate, "From", "To", TASum) '
            "VALUES (?, ?, ?, ?, ?)",
            (tx["recipient"], ts, tx["sender"], tx["recipient"], tx["TASum"]),
        )
        conn.commit()
    finally:
        conn.close()


def verify_transaction(ta_id: int) -> bool:
    """Re-derive the transaction hash and verify the sender's signature."""
    conn = db.connect()
    try:
        tx = conn.execute(
            'SELECT TAID, CNUCoinID, TADate, "From" AS sender, "To" AS recipient, '
            "TASum, TAHash, TAssign FROM TransactionsTable WHERE TAID = ?",
            (ta_id,),
        ).fetchone()
        if tx is None:
            raise ValueError(f"Unknown transaction: {ta_id}")

        # Genesis (system-issued) transactions have no signature — they are
        # implicitly trusted, the same way Bitcoin's coinbase output is.
        if tx["sender"] == db.GENESIS_ID:
            return tx["TAssign"] is None

        # Locate the previous block (the one BEFORE this transaction's block).
        block = conn.execute(
            "SELECT BlockID FROM BlockChainTable WHERE TAID = ?", (ta_id,)
        ).fetchone()
        prev = conn.execute(
            "SELECT BlockChainHash, Nonce FROM BlockChainTable "
            "WHERE BlockID < ? ORDER BY BlockID DESC LIMIT 1",
            (block["BlockID"],),
        ).fetchone() if block else None

        prev_hash = prev["BlockChainHash"] if prev else "0"
        prev_nonce = prev["Nonce"] if prev else 0

        payload = "|".join(
            [
                str(tx["TAID"]),
                str(tx["CNUCoinID"]),
                tx["TADate"],
                str(tx["sender"]),
                str(tx["recipient"]),
                f"{float(tx['TASum']):.8f}",
                str(prev_hash),
                str(prev_nonce),
            ]
        ).encode("utf-8")

        if cu.md5_hex(payload) != tx["TAHash"]:
            return False

        sender_pub = _get_public_key(conn, tx["sender"])
        return cu.verify_signature(sender_pub, tx["TAHash"].encode("utf-8"), tx["TAssign"])
    finally:
        conn.close()


def dump_state() -> dict:
    """Snapshot the whole DB state for reporting."""
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
