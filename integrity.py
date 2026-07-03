import os
import hashlib
import platform
import getpass
from datetime import datetime, timezone

AUDIT_LOG = "forensic_audit.log"
def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

def sha256_of_source(source_path, block_size=65536):
    """Compute SHA-256 of a raw device or file without writing to it."""
    h = hashlib.sha256()
    try:
        fd = os.open(source_path, os.O_RDONLY)
        with os.fdopen(fd, 'rb') as f:
            while True:
                block = f.read(block_size)
                if not block:
                    break
                h.update(block)
    except PermissionError:
        return "PERMISSION_DENIED"
    except OSError as e:
        return f"ERROR:{e}"
    return h.hexdigest()
def write_audit_log(output_dir, entry):
    log_path = os.path.join(output_dir, AUDIT_LOG)
    with open(log_path, 'a') as f:
        f.write(entry + "\n")
    return log_path

def begin_case(source_path, output_dir, case_name):
    os.makedirs(output_dir, exist_ok=True)
    print("\n[INTEGRITY] Computing SHA-256 of source evidence (read-only)...")
    print("            This may take a moment for large drives.\n")

    pre_hash = sha256_of_source(source_path)

    entry = (
        f"\n{'='*60}\n"
        f"  CASE NAME      : {case_name}\n"
        f"  EVIDENCE SOURCE: {source_path}\n"
        f"  EXAMINER       : {getpass.getuser()}\n"
        f"  HOST           : {platform.node()} ({platform.system()} {platform.release()})\n"
        f"  SCAN STARTED   : {_now()}\n"
        f"  PRE-SCAN HASH  : SHA-256:{pre_hash}\n"
        f"  ACCESS MODE    : READ-ONLY (O_RDONLY)\n"
        f"{'='*60}"
    )

    log_path = write_audit_log(output_dir, entry)

    print(f"[INTEGRITY] Pre-scan SHA-256  : {pre_hash}")
    print(f"[INTEGRITY] Audit log         : {log_path}\n")

    return pre_hash

def end_case(source_path, output_dir, pre_hash, recovered_count, report_path):
    """
    Call AFTER scanning. Re-hashes the source and compares
    to pre-scan hash. Writes final audit entry.
    Returns True if integrity is confirmed, False if violated.
    """
    print("\n[INTEGRITY] Verifying evidence source was not modified...")

    post_hash = sha256_of_source(source_path)
    integrity_ok = (pre_hash == post_hash) and not pre_hash.startswith("ERROR")

    status = "INTEGRITY CONFIRMED - Source unchanged" if integrity_ok \
             else "*** INTEGRITY VIOLATION *** Source hash mismatch!"

    entry = (
        f"\n  SCAN ENDED     : {_now()}\n"
        f"  POST-SCAN HASH : SHA-256:{post_hash}\n"
        f"  FILES RECOVERED: {recovered_count}\n"
        f"  REPORT         : {report_path}\n"
        f"  VERDICT        : {status}\n"
        f"{'='*60}"
    )

    log_path = write_audit_log(output_dir, entry)

    if integrity_ok:
        print(f"[INTEGRITY] Post-scan SHA-256 : {post_hash}")
        print(f"[INTEGRITY] ✓ VERIFIED — Evidence source was NOT modified.")
    else:
        print(f"[INTEGRITY] Post-scan SHA-256 : {post_hash}")
        print(f"[INTEGRITY] ✗ WARNING — Hash mismatch! Source may have been altered.")

    print(f"[INTEGRITY] Full audit log    : {log_path}\n")
    return integrity_ok
