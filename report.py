"""
report.py — Forensic report generator.
Produces recovery_report.json and recovery_report.csv.
Memory Deleted File Recovery Tool
"""

import csv
import json
import os
from datetime import datetime, timezone

from utils import C, fmt_size, now_str
from scanner import Artifact


def _artifact_dict(a: Artifact) -> dict:
    return {
        "id"              : a.index,
        "file_name"       : a.file_name,
        "original_path"   : a.original_path,
        "file_size_bytes" : a.file_size,
        "file_size"       : fmt_size(a.file_size),
        "file_type"       : a.file_type,
        "created_date"    : a.created_date,
        "recovery_status" : a.status,
        "sha256"          : a.sha256,
        "offset_bytes"    : a.offset_bytes,
        "recovery_location": a.saved_path,
    }


def generate_json(
    artifacts    : list[Artifact],
    evidence_path: str,
    evidence_hash: str,
    stats        : dict,
    out_path     : str,
) -> str:
    """Generate a JSON forensic report."""
    report = {
        "report_generated" : now_str(),
        "tool"             : "Memory Deleted File Recovery Tool v1.0.0",
        "evidence"         : {
            "path"   : evidence_path,
            "sha256" : evidence_hash,
        },
        "statistics"       : stats,
        "artifacts"        : [_artifact_dict(a) for a in artifacts],
    }
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, default=str)
    return out_path


def generate_csv(artifacts: list[Artifact], out_path: str) -> str:
    """Generate a CSV forensic report."""
    fields = [
        "id", "file_name", "original_path", "file_size_bytes", "file_size",
        "file_type", "created_date", "recovery_status", "sha256",
        "offset_bytes", "recovery_location",
    ]
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows([_artifact_dict(a) for a in artifacts])
    return out_path


def print_report_paths(json_path: str, csv_path: str):
    """Print report save paths to terminal."""
    print()
    print(f"  {C.BOLD}{C.GREEN}[OK]{C.RESET}  JSON Report : {C.CYAN}{json_path}{C.RESET}")
    print(f"  {C.BOLD}{C.GREEN}[OK]{C.RESET}  CSV  Report : {C.CYAN}{csv_path}{C.RESET}")
    print()
