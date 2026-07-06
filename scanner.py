"""
scanner.py - File carving engine.
Scans memory dump / disk image using signature-based detection.
Operates strictly READ-ONLY on the evidence source.
Memory Deleted File Recovery Tool
"""

import os
import io
import zipfile
import logging
from dataclasses import dataclass, field
from typing import Optional

from tqdm import tqdm

from utils import sha256_bytes, fmt_size, C


# ──────────────────────────────────────────────────────────────
#  File Signature Table
#  Each entry: (header, footer, extension, max_size_bytes)
# ──────────────────────────────────────────────────────────────

FILE_SIGNATURES: list[tuple] = [
    # Images
    (b"\xFF\xD8\xFF",              b"\xFF\xD9",               "jpg",  15_000_000),
    (b"\x89PNG\r\n\x1a\n",         b"IEND\xaeB\x60\x82",      "png",  15_000_000),
    (b"GIF87a",                    b"\x00;",                  "gif",  10_000_000),
    (b"GIF89a",                    b"\x00;",                  "gif",  10_000_000),
    # Documents
    (b"%PDF",                      b"%%EOF",                   "pdf",  50_000_000),
    # Office / Archives (ZIP-based — refined by content below)
    (b"PK\x03\x04",                None,                      "zip",  100_000_000),
    # RAR
    (b"Rar!\x1a\x07\x00",          None,                      "rar",  200_000_000),
    (b"Rar!\x1a\x07\x01\x00",      None,                      "rar",  200_000_000),
    # Video
    (b"\x00\x00\x00\x18ftypmp42",  None,                      "mp4",  500_000_000),
    (b"\x00\x00\x00\x18ftypisom",  None,                      "mp4",  500_000_000),
    (b"\x00\x00\x00\x20ftyp",      None,                      "mp4",  500_000_000),
    (b"\x00\x00\x00\x1Cftyp",      None,                      "mp4",  500_000_000),
]

# OOXML markers inside ZIP to identify DOCX / XLSX / PPTX
OOXML_MAP: dict[bytes, tuple] = {
    b"word/document.xml":      ("docx", "DOCX"),
    b"xl/workbook.xml":        ("xlsx", "XLSX"),
    b"ppt/presentation.xml":   ("pptx", "PPTX"),
    b"word/":                  ("docx", "DOCX"),
    b"xl/":                    ("xlsx", "XLSX"),
    b"ppt/":                   ("pptx", "PPTX"),
}

CHUNK_SIZE = 4 * 1024 * 1024    # 4 MB read window
OVERLAP    = 8192                # overlap between chunks for split signatures

# Text detection — only scan isolated regions NOT already claimed by binary sigs
TEXT_MIN_RUN    = 80             # minimum consecutive printable bytes for a text block
TEXT_MAX_SIZE   = 200_000        # max bytes per text artifact


# ──────────────────────────────────────────────────────────────
#  Artifact dataclass
# ──────────────────────────────────────────────────────────────

@dataclass
class Artifact:
    """Represents one carved file artifact."""
    index         : int   = 0
    file_name     : str   = "unknown"
    original_path : str   = "Unknown"
    file_size     : int   = 0
    file_type     : str   = ""
    ext           : str   = ""
    created_date  : str   = "Unknown"
    sha256        : str   = ""
    status        : str   = "Recoverable"
    offset_bytes  : int   = 0
    raw_data      : bytes = field(default=b"", repr=False)
    db_id         : int   = 0
    saved_path    : str   = "Not Recovered"


# ──────────────────────────────────────────────────────────────
#  Scanner
# ──────────────────────────────────────────────────────────────

class MemoryScanner:
    """
    Scans a memory dump or disk image using file carving.
    Opens the evidence strictly O_RDONLY — never writes to it.
    """

    def __init__(self, evidence_path: str, logger: logging.Logger):
        self.evidence_path = evidence_path
        self.logger        = logger
        self._artifacts: list[Artifact] = []

    def scan(self) -> list[Artifact]:
        """Run the full carving scan. Returns list of Artifact objects."""
        self._artifacts = []
        seen_hashes: set[str] = set()
        # Track byte ranges already claimed by binary signatures
        # so text scanner doesn't re-scan them as TXT
        claimed_ranges: list[tuple[int, int]] = []

        try:
            evidence_size = os.path.getsize(self.evidence_path)
        except OSError as e:
            self.logger.error(f"Cannot stat evidence: {e}")
            raise

        self.logger.info(f"Scan started: {self.evidence_path} ({fmt_size(evidence_size)})")

        try:
            fd = os.open(self.evidence_path, os.O_RDONLY)
        except PermissionError:
            self.logger.error("Permission denied — run with sudo for raw devices.")
            raise
        except OSError as e:
            self.logger.error(f"Cannot open evidence: {e}")
            raise

        buffer     = b""
        global_off = 0
        bytes_read = 0

        bar = tqdm(
            total=evidence_size,
            unit="B",
            unit_scale=True,
            unit_divisor=1024,
            desc="  Scanning",
            ascii=True,          # <-- fixes garbled characters in any terminal
            bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}]",
            ncols=72,
        )

        with os.fdopen(fd, "rb") as f:
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break

                buffer     += chunk
                bytes_read += len(chunk)
                bar.update(len(chunk))

                # ── Binary signature carving ──────────────────────
                for header, footer, ext, max_size in FILE_SIGNATURES:
                    pos = 0
                    while True:
                        start = buffer.find(header, pos)
                        if start == -1:
                            break

                        abs_start = global_off + start

                        if footer:
                            end = buffer.find(footer, start + len(header))
                            if end == -1:
                                pos = start + 1
                                continue
                            end += len(footer)
                        else:
                            end = min(start + max_size, len(buffer))

                        blob = buffer[start:end]
                        if len(blob) < 32:
                            pos = start + 1
                            continue

                        h = sha256_bytes(blob)
                        if h not in seen_hashes:
                            seen_hashes.add(h)
                            artifact = self._build_artifact(blob, ext, h, abs_start)
                            self._artifacts.append(artifact)
                            claimed_ranges.append((abs_start, abs_start + len(blob)))
                            self.logger.info(
                                f"Found [{artifact.file_type}] {artifact.file_name} "
                                f"@ offset {abs_start:,} ({fmt_size(len(blob))})"
                            )

                        pos = start + 1

                # ── Text carving (only in unclaimed regions) ──────
                self._scan_text(buffer, global_off, seen_hashes, claimed_ranges)

                global_off += len(buffer) - OVERLAP
                buffer      = buffer[-OVERLAP:]

        bar.close()
        self.logger.info(f"Scan complete — {len(self._artifacts)} artifacts found.")
        return self._artifacts

    # ── Artifact builder ──────────────────────────────────────

    def _build_artifact(self, blob: bytes, ext: str, h: str, offset: int) -> Artifact:
        file_type = ext.upper()
        fname     = f"artifact_{offset}_{h[:8]}.{ext}"

        if ext == "zip":
            ext, file_type = self._refine_ooxml(blob)
            fname = f"artifact_{offset}_{h[:8]}.{ext}"

        return Artifact(
            index        = len(self._artifacts) + 1,
            file_name    = fname,
            original_path= "Unknown",
            file_size    = len(blob),
            file_type    = file_type,
            ext          = ext,
            created_date = "Unknown",
            sha256       = h,
            status       = "Recoverable",
            offset_bytes = offset,
            raw_data     = blob,
        )

    def _refine_ooxml(self, data: bytes) -> tuple[str, str]:
        """Distinguish DOCX / XLSX / PPTX inside a ZIP blob."""
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                names_str = " ".join(zf.namelist()).encode()
                for marker, (ext, ftype) in OOXML_MAP.items():
                    if marker in names_str:
                        return ext, ftype
        except Exception:
            pass
        return "zip", "ZIP"

    # ── Text heuristic ────────────────────────────────────────

    def _scan_text(
        self,
        buffer      : bytes,
        base_off    : int,
        seen        : set[str],
        claimed     : list[tuple[int, int]],
    ):
        """
        Find plain-text runs in unclaimed regions of the buffer.
        A 'text run' is TEXT_MIN_RUN+ consecutive printable ASCII/UTF-8 bytes.
        Only runs that contain at least one newline (real text, not binary)
        are accepted as TXT artifacts.
        """
        n   = len(buffer)
        i   = 0

        while i < n - TEXT_MIN_RUN:
            b = buffer[i]
            # Printable ASCII or common control chars (tab, LF, CR)
            if not (32 <= b <= 126 or b in (9, 10, 13)):
                i += 1
                continue

            # Find extent of printable run
            end = i
            while end < n and (32 <= buffer[end] <= 126 or buffer[end] in (9, 10, 13)):
                end += 1

            run_len = end - i
            if run_len < TEXT_MIN_RUN:
                i = end + 1
                continue

            abs_start = base_off + i

            # Must contain at least one newline to be considered real text
            # (eliminates base64-looking blobs embedded in binary files)
            run_bytes = buffer[i:end]
            if b"\n" not in run_bytes and b"\r" not in run_bytes:
                i = end + 1
                continue

            # Skip if this region is already claimed by a binary artifact
            if self._is_claimed(abs_start, abs_start + run_len, claimed):
                i = end + 1
                continue

            blob = run_bytes[:TEXT_MAX_SIZE]
            h    = sha256_bytes(blob)
            if h not in seen:
                seen.add(h)
                fname = f"artifact_{abs_start}_{h[:8]}.txt"
                a = Artifact(
                    index        = len(self._artifacts) + 1,
                    file_name    = fname,
                    original_path= "Unknown",
                    file_size    = len(blob),
                    file_type    = "TXT",
                    ext          = "txt",
                    created_date = "Unknown",
                    sha256       = h,
                    status       = "Recoverable",
                    offset_bytes = abs_start,
                    raw_data     = blob,
                )
                self._artifacts.append(a)
                self.logger.info(
                    f"Found [TXT] {fname} @ offset {abs_start:,} ({fmt_size(len(blob))})"
                )

            i = end + 1

    @staticmethod
    def _is_claimed(start: int, end: int, claimed: list[tuple[int, int]]) -> bool:
        """Check if [start, end) overlaps with any claimed range."""
        for cs, ce in claimed:
            if start < ce and end > cs:
                return True
        return False
