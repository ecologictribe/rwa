"""File storage, path containment security, and statutory age utilities (SRS 9.1).

Enforces:
- Path traversal prevention using strict is_relative_to(UPLOAD_DIR) validation
- Pure-Python minimal PDF generator for archival documents
- Canonical HRRS Act 2012 Sec. 16(i) age calculation with February 29 leap-day handling
"""

from __future__ import annotations

import shutil
from datetime import date
from pathlib import Path

from fastapi import HTTPException, UploadFile, status

from . import config


def is_at_least_21(dob: date, today: date) -> bool:
    """Sec. 16(i): Member must have completed 21 years of age on admission date.
    Correctly handles Feb 29 leap day births when the 21st anniversary is non-leap.
    """
    try:
        twenty_first = dob.replace(year=dob.year + 21)
    except ValueError:
        # Born on Feb 29; 21 years later is not a leap year, so anniversary is Feb 28
        twenty_first = dob.replace(year=dob.year + 21, day=28)
    return twenty_first <= today


def get_safe_upload_path(storage_path: str | None) -> Path | None:
    """Safely resolve an upload/storage path against UPLOAD_DIR.
    Returns None if the path attempts directory traversal or escapes UPLOAD_DIR.
    """
    if not storage_path:
        return None
    # Normalize slashes and strip leading slashes
    clean = storage_path.replace("\\", "/").strip("/")
    if clean.startswith("uploads/"):
        clean = clean[len("uploads/"):]
    target = (config.UPLOAD_DIR / clean).resolve()
    base = config.UPLOAD_DIR.resolve()
    try:
        if not target.is_relative_to(base):
            return None
    except AttributeError:
        # Fallback for Python < 3.9 if ever needed
        if not str(target).startswith(str(base)):
            return None
    return target


def ensure_pdf_file_exists(target_path: Path, title: str, category: str, version: int, checksum: str) -> None:
    """If a document version PDF does not exist on disk, synthesize a valid standard PDF."""
    if target_path.exists() and target_path.is_file():
        return
    target_path.parent.mkdir(parents=True, exist_ok=True)
    # PDF literal escaping
    clean_title = title.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
    clean_cat = category.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
    clean_sum = checksum.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
    content = (
        f"BT /F1 16 Tf 50 770 Td ({clean_title}) Tj ET\n"
        f"BT /F1 12 Tf 50 740 Td (Category: {clean_cat} | Version: v{version}) Tj ET\n"
        f"BT /F1 10 Tf 50 715 Td (Statutory Record under HRRS Act 2012 Sec. 37) Tj ET\n"
        f"BT /F1 9 Tf 50 690 Td (SHA-256 Checksum: {clean_sum}) Tj ET\n"
        f"BT /F1 9 Tf 50 670 Td (Haryana Registration and Regulation of Societies Act, 2012) Tj ET\n"
        f"BT /F1 9 Tf 50 650 Td (Official Society Document Vault - Pramana Production Node) Tj ET\n"
    )
    bcontent = content.encode("latin1", "replace")
    body = (
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
        b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>\nendobj\n"
        b"4 0 obj\n<< /Length " + str(len(bcontent)).encode("ascii") + b" >>\nstream\n" + bcontent + b"endstream\nendobj\n"
        b"5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n"
    )
    xref_offset = len(body)
    xref = (
        b"xref\n0 6\n"
        b"0000000000 65535 f \n"
        b"0000000009 00000 n \n"
        b"0000000058 00000 n \n"
        b"0000000115 00000 n \n"
        b"0000000224 00000 n \n"
        b"0000000300 00000 n \n"
        b"trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n" + str(xref_offset).encode("ascii") + b"\n%%EOF\n"
    )
    target_path.write_bytes(body + xref)


def calculate_statutory_quorum(active_members: int) -> int:
    """HRRS Rules 2012 Rule 16: Minimum 40% quorum of voting members.
    Enforces exact legal ceiling arithmetic: ceil(0.40 * N) = (2 * N + 4) // 5.
    Prevents truncation artifacts where 40% of 41 (16.4) incorrectly truncates to 16 (39.02%).
    """
    if active_members <= 0:
        return 0
    return (2 * active_members + 4) // 5


def term_progress(start: date, end: date, today: date) -> tuple[int, int, int]:
    """Returns (elapsed_pct, days_left, total_days) with half-up rounding and zero-division guard."""
    total = max((end - start).days, 1)
    elapsed = min(max((today - start).days, 0), total)
    pct = (elapsed * 100 + total // 2) // total
    return pct, max(total - elapsed, 0), total


def compute_taleb_diagnostics(durations: list[float]) -> dict:
    """Nassim Nicholas Taleb Extremistan & Fat-Tail Diagnostics (Pramāna Sovereign Standard).

    Computes:
    - Sample size (N)
    - Mean and Median (p50)
    - p90 percentile
    - Maximum-to-Sum Ratio: R_n = X_max / sum(X_i)
    - Mean Absolute Deviation: MAD = sum(|X_i - Mean|) / N
    - Relative MAD: MAD / Mean (robust dispersion ratio)
    - Is Extremistan: True if R_n >= 0.15 (indicating heavy tail / chronic asset monopolization)
    """
    if not durations:
        return {
            "count": 0, "mean": 0.0, "median": 0.0, "p90": 0.0,
            "max": 0.0, "r_n": 0.0, "mad": 0.0, "rel_mad": 0.0, "is_extremistan": False,
        }
    sorted_d = sorted(durations)
    n = len(sorted_d)
    total_sum = sum(sorted_d)
    mean_val = total_sum / n
    max_val = sorted_d[-1]
    r_n = (max_val / total_sum) if total_sum > 0 else 0.0

    # Median (p50)
    mid = n // 2
    median_val = sorted_d[mid] if n % 2 != 0 else (sorted_d[mid - 1] + sorted_d[mid]) / 2.0

    # p90
    p90_idx = int(0.90 * (n - 1))
    p90_val = sorted_d[p90_idx]

    # Mean Absolute Deviation (MAD)
    mad_val = sum(abs(x - mean_val) for x in sorted_d) / n
    rel_mad = (mad_val / mean_val) if mean_val > 0 else 0.0

    # Taleb Extremistan threshold: R_n >= 0.15 indicates single event dominance
    is_extremistan = r_n >= 0.15
    return {
        "count": n,
        "mean": round(mean_val, 2),
        "median": round(median_val, 2),
        "p90": round(p90_val, 2),
        "max": round(max_val, 2),
        "r_n": round(r_n, 4),
        "mad": round(mad_val, 2),
        "rel_mad": round(rel_mad, 4),
        "is_extremistan": is_extremistan,
    }

