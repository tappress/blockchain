"""Lab 2 demo — Proof-of-Work mining over the CNUCoin chain.

Difficulty Target = block hash must start with one '0' character (per spec).
A higher difficulty (3–4 zeros) can be requested via DIFFICULTY env var.
"""

import json
import os

import db
import cnucoin


DIFFICULTY = int(os.environ.get("DIFFICULTY", "1"))


def banner(title: str) -> None:
    print()
    print("=" * 72)
    print(title)
    print("=" * 72)


def short(uid: str) -> str:
    return uid[:8] + "…" + uid[-4:] if uid and uid != "GENESIS" else (uid or "")


def show_balances(users: dict) -> None:
    for label, uid in users.items():
        print(f"  {label:<7} {short(uid)}  balance = {cnucoin.get_balance(uid):.4f}")


def report_mining(stats: dict) -> None:
    print(
        f"  ⛏  TAID={stats['ta_id']}  Nonce={stats['nonce']}  "
        f"attempts={stats['attempts']}  time={stats['elapsed_seconds']*1000:.2f}ms"
    )
    print(f"      block hash = {stats['block_hash']}")
    if stats["confirmed"]:
        c = stats["confirmed"]
        print(
            f"      ✔ confirmed prior TAID={c['ta_id']} "
            f"(reward {c['reward']:.4f} → miner {short(c['miner_id'])})"
        )
    else:
        print("      (no prior block to confirm — first block in the chain)")


def main() -> None:
    banner(f"Lab 2 — Proof-of-Work demo (difficulty = {DIFFICULTY} leading zero(s))")
    db.init_db(reset=True)

    banner("1. Register users")
    alice = cnucoin.register_user(initial_balance=200.0)
    bob = cnucoin.register_user(initial_balance=50.0)
    carol = cnucoin.register_user(initial_balance=25.0)
    miner = cnucoin.register_user(is_miner=True)
    miner2 = cnucoin.register_user(is_miner=True)
    users = {
        "Alice": alice.cnucoin_id,
        "Bob": bob.cnucoin_id,
        "Carol": carol.cnucoin_id,
        "Miner1": miner.cnucoin_id,
        "Miner2": miner2.cnucoin_id,
    }
    show_balances(users)

    banner("2. Create three pending transactions")
    t1 = cnucoin.create_transaction(alice.cnucoin_id, bob.cnucoin_id, 30.0)
    t2 = cnucoin.create_transaction(alice.cnucoin_id, carol.cnucoin_id, 20.0)
    t3 = cnucoin.create_transaction(alice.cnucoin_id, bob.cnucoin_id, 15.0)
    print(f"  TAID {t1}: Alice→Bob 30")
    print(f"  TAID {t2}: Alice→Carol 20")
    print(f"  TAID {t3}: Alice→Bob 15")
    print(f"  unmined queue: {[t['TAID'] for t in cnucoin.unmined_transactions()]}")

    banner("3. Mine block #1 (chains T1; no prior block to confirm)")
    s1 = cnucoin.mine_next(miner.cnucoin_id, difficulty=DIFFICULTY)
    report_mining(s1)

    banner("4. Mine block #2 (chains T2; this confirms T1, pays Miner1)")
    s2 = cnucoin.mine_next(miner2.cnucoin_id, difficulty=DIFFICULTY)
    report_mining(s2)

    banner("5. Mine block #3 (chains T3; this confirms T2, pays Miner2)")
    s3 = cnucoin.mine_next(miner.cnucoin_id, difficulty=DIFFICULTY)
    report_mining(s3)
    print("  (T3 stays unconfirmed until a 4th block is mined.)")

    banner("6. Final confirmed balances")
    show_balances(users)

    banner("7. Verification")
    for ta in [t1, t2, t3]:
        print(f"  Tx #{ta} signature valid: {cnucoin.verify_transaction(ta)}")
    for bid in [1, 2, 3]:
        print(f"  Block #{bid} valid: {cnucoin.verify_block(bid, difficulty=DIFFICULTY)}")

    banner("8. State snapshot")
    state = cnucoin.dump_state()
    print(json.dumps(
        {"transactions": state["transactions"], "blocks": state["blocks"]},
        indent=2,
        default=str,
    ))

    banner("9. Mining stats summary")
    for label, s in [("Block 1", s1), ("Block 2", s2), ("Block 3", s3)]:
        print(
            f"  {label}: nonce={s['nonce']:>6}  attempts={s['attempts']:>6}  "
            f"time={s['elapsed_seconds']*1000:>8.2f}ms  hash={s['block_hash'][:16]}…"
        )


if __name__ == "__main__":
    main()
