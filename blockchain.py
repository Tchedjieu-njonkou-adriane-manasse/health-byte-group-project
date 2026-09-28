"""
blockchain.py
--------------
A lightweight, self-contained hash-chain ("blockchain") used to make every
create/update action on a patient's medical record tamper-evident.

Each action performed on the platform (create consultation, add prescription,
add lab result, update patient info, etc.) is written as one immutable
"block" into the `ledger` table. Every block stores:

    - a hash of the actual record data at the time of the action
    - the hash of the previous block (its "chain link")
    - its own hash, computed from everything above

Because each block's hash depends on the previous block's hash, altering or
deleting any past record breaks the chain from that point forward. The
Verify Integrity feature recomputes every hash and checks the chain link by
link, exactly like the diagram: ACTION HASHED -> BLOCKCHAIN -> VERIFY
INTEGRITY -> VALID / ALTERED.

This is a genuine hash chain (Merkle-style linking, SHA-256), implemented
locally in SQLite rather than on a distributed network -- appropriate for a
single-institution academic/demo project while still demonstrating the real
integrity-verification mechanism blockchains provide.
"""

import hashlib
import json
import time


GENESIS_HASH = "0" * 64


def _hash_data(data: dict) -> str:
    """Deterministically hash a dict of record data."""
    encoded = json.dumps(data, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _compute_block_hash(index, timestamp, patient_id, actor_id, actor_role,
                         action_type, record_type, record_id, data_hash,
                         previous_hash) -> str:
    payload = f"{index}|{timestamp}|{patient_id}|{actor_id}|{actor_role}|" \
              f"{action_type}|{record_type}|{record_id}|{data_hash}|{previous_hash}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def get_last_block(db):
    row = db.execute(
        "SELECT * FROM ledger ORDER BY id DESC LIMIT 1"
    ).fetchone()
    return row


def add_block(db, patient_id, actor_id, actor_role, action_type,
              record_type, record_id, data: dict):
    """
    Append a new block to the ledger recording an action taken on a
    patient's record. Commits the insert. Returns the new block's hash.
    """
    last_block = get_last_block(db)
    index = (last_block["id"] + 1) if last_block else 1
    previous_hash = last_block["block_hash"] if last_block else GENESIS_HASH
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    data_hash = _hash_data(data)

    block_hash = _compute_block_hash(
        index, timestamp, patient_id, actor_id, actor_role,
        action_type, record_type, record_id, data_hash, previous_hash
    )

    db.execute(
        """INSERT INTO ledger
           (patient_id, actor_id, actor_role, action_type, record_type,
            record_id, data_hash, previous_hash, block_hash, timestamp)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (patient_id, actor_id, actor_role, action_type, record_type,
         record_id, data_hash, previous_hash, block_hash, timestamp)
    )
    db.commit()
    return block_hash


def verify_chain(db, patient_id=None):
    """
    Recompute every block's hash and check the previous_hash linkage.
    If patient_id is given, only blocks for that patient are RETURNED,
    but the check still walks the *entire* global chain, since tampering
    with any block (even another patient's) breaks the shared chain from
    that point on.

    Returns: (overall_valid: bool, blocks: list[dict])
    """
    rows = db.execute("SELECT * FROM ledger ORDER BY id ASC").fetchall()

    overall_valid = True
    expected_previous = GENESIS_HASH
    results = []

    for row in rows:
        recomputed_hash = _compute_block_hash(
            row["id"], row["timestamp"], row["patient_id"], row["actor_id"],
            row["actor_role"], row["action_type"], row["record_type"],
            row["record_id"], row["data_hash"], row["previous_hash"]
        )

        link_ok = (row["previous_hash"] == expected_previous)
        hash_ok = (recomputed_hash == row["block_hash"])
        block_valid = link_ok and hash_ok

        if not block_valid:
            overall_valid = False

        if patient_id is None or row["patient_id"] == patient_id:
            results.append({
                "id": row["id"],
                "timestamp": row["timestamp"],
                "actor_id": row["actor_id"],
                "actor_role": row["actor_role"],
                "action_type": row["action_type"],
                "record_type": row["record_type"],
                "record_id": row["record_id"],
                "block_hash": row["block_hash"],
                "previous_hash": row["previous_hash"],
                "valid": block_valid,
            })

        expected_previous = row["block_hash"]

    return overall_valid, results
