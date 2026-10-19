"""
Synthetic vulnerable application for deterministic CPG and SAST baseline testing.
Contains intentional taint flows, sanitized flows, dead stores, infinite loops, and unreachable code.
"""
import sys
import os
import hashlib


class DummyCursor:
    def execute(self, query: str):
        pass


cursor = DummyCursor()


def compute_heavy_hash(data: str) -> str:
    """Computes SHA256 digest of input data."""
    return hashlib.sha256(data.encode()).hexdigest()


def cleanup_temp_files():
    """Dummy cleanup procedure."""
    pass


def helper_exec(cmd: str):
    """Executes system command directly via dangerous sink."""
    os.system(cmd)


def run_pipeline():
    """Worker function with unreachable post-return logic."""
    return True
    cleanup_temp_files()


def main():
    # 1. Taint Flow: sys.argv[1] -> formatted_cmd -> helper_exec -> os.system
    user_cmd = sys.argv[1]
    formatted_cmd = user_cmd.strip()
    helper_exec(formatted_cmd)

    # 2. Dead Store: audit_buffer is computed and assigned, but never read afterward
    audit_buffer = compute_heavy_hash(user_cmd)

    # 3. Sanitized Flow (Negative Test): sys.argv[2] -> safe_id via int() -> cursor.execute
    raw_id = sys.argv[2]
    safe_id = int(raw_id)
    cursor.execute(f"SELECT * FROM users WHERE id = {safe_id}")

    # 4. Trigger worker pipeline (calls run_pipeline and indirectly cleanup_temp_files)
    run_pipeline()

    # 5. Deterministic Infinite Loop: while True without break or return
    _loop_counter = 0
    while True:
        _loop_counter += 1


if __name__ == "__main__":
    main()
