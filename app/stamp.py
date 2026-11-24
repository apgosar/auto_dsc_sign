"""Acrobat-style visible signature appearance.

Mimics the default stamp Adobe Acrobat draws for a certificate signature:

    +-----------------------------------------------+
    | VINIT          | Digitally signed by VINIT     |
    | DHIRAJ         | DHIRAJ SANGOI                 |
    | SANGOI         | Date: 2026.11.24 13:43:58     |
    |                | +05'30'                       |
    +-----------------------------------------------+

Left column: signer name, one or more words per line, in the largest font that fits.
Right column: "Digitally signed by <name>", "Date: yyyy.mm.dd HH:MM:SS +hh'mm'" and optional
Reason/Location lines, word-wrapped at the largest font that fits. Helvetica (a standard PDF
font, no embedding needed), black text, no border.
"""
from __future__ import annotations

from datetime import datetime
from zoneinfo import ZoneInfo

import pymupdf

FONT_RES_NAME = "/Helv"
LEADING = 1.16          # line height as a multiple of font size
PAD = 0.04              # padding as a fraction of the box height (min 2pt)
LEFT_SHARE = 0.46       # share of the width used by the name column
GAP_SHARE = 0.03        # gap between the columns
MAX_NAME_FONT = 40.0
MAX_DETAIL_FONT = 14.0
MIN_FONT = 3.0


def _width(text: str, size: float) -> float:
    return pymupdf.get_text_length(text, fontname="helv", fontsize=size)


def acrobat_date(ts: datetime, tz_name: str) -> str:
    """2026.11.24 13:43:58 +05'30' (Acrobat's format)."""
    local = ts.astimezone(ZoneInfo(tz_name))
    off = local.utcoffset()
    total = int(off.total_seconds()) if off else 0
    sign = "+" if total >= 0 else "-"
    hh, mm = divmod(abs(total) // 60, 60)
    return local.strftime("%Y.%m.%d %H:%M:%S") + f" {sign}{hh:02d}'{mm:02d}'"


# --------------------------------------------------------------------------- layout helpers
def _split_words(words: list[str], k: int) -> list[str]:
    """Split words into k lines of roughly equal character length (keeps order)."""
    if k >= len(words):
        return words[:]
    total = sum(len(w) for w in words) + len(words) - 1
    target = total / k
    lines, cur = [], []
    for i, w in enumerate(words):
        remaining_words = len(words) - i
        remaining_lines = k - len(lines)
        cand = " ".join(cur + [w])
        if cur and (len(cand) > target * 1.15 or remaining_words < remaining_lines):
            lines.append(" ".join(cur))
            cur = [w]
        else:
            cur.append(w)
    if cur:
        lines.append(" ".join(cur))
    while len(lines) > k:  # merge overflow into the last line
        lines[-2] = lines[-2] + " " + lines.pop()
    return lines


def _fit_name(name: str, width: float, height: float) -> tuple[list[str], float]:
    words = name.split() or [name or "Signer"]
    best: tuple[list[str], float] = ([" ".join(words)], MIN_FONT)
    for k in range(1, min(len(words), 4) + 1):
        lines = _split_words(words, k)
        widest = max(_width(l, 1.0) for l in lines) or 1.0
        size = min(width / widest, height / (len(lines) * LEADING), MAX_NAME_FONT)
        if size > best[1]:
            best = (lines, size)
    return best


def _wrap(text: str, size: float, width: float) -> list[str]:
    out, cur = [], ""
    for word in text.split():
        cand = f"{cur} {word}".strip()
        if not cur or _width(cand, size) <= width:
            cur = cand
        else:
            out.append(cur)
            cur = word
        # a single word wider than the column: hard-break it
        while _width(cur, size) > width and len(cur) > 1:
            cut = len(cur)
            while cut > 1 and _width(cur[:cut], size) > width:
                cut -= 1
            out.append(cur[:cut])
            cur = cur[cut:]
    if cur:
        out.append(cur)
    return out


def _fit_details(paragraphs: list[str], width: float, height: float) -> tuple[list[str], float]:
    size = MAX_DETAIL_FONT
    while size > MIN_FONT:
        lines = [l for p in paragraphs for l in _wrap(p, size, width)]
        if len(lines) * size * LEADING <= height:
            return lines, size
        size -= 0.25
    return [l for p in paragraphs for l in _wrap(p, MIN_FONT, width)], MIN_FONT


# --------------------------------------------------------------------------- content stream
def _pdf_str(text: str) -> bytes:
    raw = text.encode("cp1252", errors="replace")
    raw = raw.replace(b"\\", b"\\\\").replace(b"(", b"\\(").replace(b")", b"\\)")
    return b"(" + raw + b")"


def _text_block(lines: list[str], size: float, x: float, top: float) -> list[bytes]:
    cmds = [b"BT", f"{FONT_RES_NAME} {size:.2f} Tf".encode(), f"{size * LEADING:.2f} TL".encode()]
    # first baseline: top minus the font ascent (~0.8 em for Helvetica)
    cmds.append(f"{x:.2f} {top - size * 0.80:.2f} Td".encode())
    for i, line in enumerate(lines):
        if i:
            cmds.append(b"T*")
        cmds.append(_pdf_str(line) + b" Tj")
    cmds.append(b"ET")
    return cmds


def build_appearance_stream(width: float, height: float, *, name: str, timestamp: datetime,
                            tz_name: str, reason: str = "", location: str = "") -> bytes:
    """Return the raw content stream (bytes) for a width x height appearance box."""
    width, height = float(width), float(height)  # pyHanko hands us Decimal values
    pad = max(2.0, height * PAD)
    inner_w, inner_h = width - 2 * pad, height - 2 * pad
    gap = width * GAP_SHARE
    left_w = inner_w * LEFT_SHARE
    right_w = inner_w - left_w - gap

    name_lines, name_size = _fit_name(name, left_w, inner_h)
    details = [f"Digitally signed by {name}", f"Date: {acrobat_date(timestamp, tz_name)}"]
    if reason:
        details.append(f"Reason: {reason}")
    if location:
        details.append(f"Location: {location}")
    detail_lines, detail_size = _fit_details(details, right_w, inner_h)

    # vertically centre each column
    name_block_h = len(name_lines) * name_size * LEADING
    detail_block_h = len(detail_lines) * detail_size * LEADING
    name_top = pad + inner_h - (inner_h - name_block_h) / 2
    detail_top = pad + inner_h - (inner_h - detail_block_h) / 2

    cmds = [b"q", b"0 g"]
    cmds += _text_block(name_lines, name_size, pad, name_top)
    cmds += _text_block(detail_lines, detail_size, pad + left_w + gap, detail_top)
    cmds.append(b"Q")
    return b"\n".join(cmds)


def make_xobject(width: float, height: float, **kwargs):
    """Build the pyHanko form XObject (StreamObject) for the appearance."""
    from pyhanko.pdf_utils import generic
    from pyhanko.pdf_utils.writer import init_xobject_dictionary

    font = generic.DictionaryObject({
        generic.pdf_name("/Type"): generic.pdf_name("/Font"),
        generic.pdf_name("/Subtype"): generic.pdf_name("/Type1"),
        generic.pdf_name("/BaseFont"): generic.pdf_name("/Helvetica"),
        generic.pdf_name("/Encoding"): generic.pdf_name("/WinAnsiEncoding"),
    })
    resources = generic.DictionaryObject({
        generic.pdf_name("/Font"): generic.DictionaryObject({generic.pdf_name(FONT_RES_NAME): font}),
    })
    return init_xobject_dictionary(build_appearance_stream(width, height, **kwargs), width, height, resources)
