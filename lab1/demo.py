"""End-to-end Lab 1 demonstration: register users, send a transaction, verify."""

import json

import db
import cnucoin


def banner(title: str) -> None:
    print()
    print("=" * 72)
    print(title)
    print("=" * 72)


def short(uid: str) -> str:
    return uid[:8] + "…" + uid[-4:]


def main() -> None:
    banner("1. Initialising fresh CNUCoin database")
    db.init_db(reset=True)
    print(f"DB created at: {db.DB_PATH}")

    banner("2. Registering users (with seeded balances)")
    alice = cnucoin.register_user(label="Alice", initial_balance=100.0)
    bob = cnucoin.register_user(label="Bob", initial_balance=50.0)
    carol = cnucoin.register_user(label="Carol", initial_balance=25.0)
    miner = cnucoin.register_user(label="Miner", is_miner=True, initial_balance=0.0)

    for u in [alice, bob, carol, miner]:
        print(f"  {u.label:<6} ID={short(u.cnucoin_id)}  miner={u.is_miner}  "
              f"balance={cnucoin.get_balance(u.cnucoin_id):.2f}")

    banner("3. Members visible in the public registry")
    for m in cnucoin.list_members():
        print(f"  {(m['Label'] or '—'):<8} {short(m['CNUCoinID'])}  IsMiner={bool(m['IsMiner'])}")

    banner("4. Alice sends 30 CNUCoin to Bob — first transaction")
    ta_id = cnucoin.create_transaction(alice.cnucoin_id, bob.cnucoin_id, 30.0)
    print(f"  Created transaction TAID={ta_id}")
    print(f"  Signature valid?  {cnucoin.verify_transaction(ta_id)}")

    banner("5. Miner confirms the transaction")
    cnucoin.confirm_transaction(ta_id, miner.cnucoin_id, nonce=0)
    print("  Transaction approved.")

    banner("6. Balances after transaction")
    for label, u in [("Alice", alice), ("Bob", bob), ("Carol", carol)]:
        print(f"  {label:<6} {short(u.cnucoin_id)}  balance={cnucoin.get_balance(u.cnucoin_id):.2f}")

    banner("7. Second transaction — Bob -> Carol 10 CNUCoin (chain linkage)")
    ta_id_2 = cnucoin.create_transaction(bob.cnucoin_id, carol.cnucoin_id, 10.0)
    cnucoin.confirm_transaction(ta_id_2, miner.cnucoin_id, nonce=0)
    print(f"  TAID={ta_id_2}, signature valid? {cnucoin.verify_transaction(ta_id_2)}")

    banner("8. Final state dump")
    state = cnucoin.dump_state()
    print(json.dumps(state, indent=2, default=str))


if __name__ == "__main__":
    main()
