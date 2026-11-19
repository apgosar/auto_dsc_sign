"""Signature box coordinate math for the three placement modes.

Coordinate systems
------------------
* "display" space: what the user sees (PDF.js viewport / PyMuPDF ``page.rect``):
  origin top-left of the CropBox, page rotation applied, units = PDF points.
* "unrotated" MuPDF space: same but without /Rotate (what ``search_for`` returns).
* PDF user space: origin bottom-left of the MediaBox, Y up — what pyHanko's
  ``SigFieldSpec.box`` expects.

display --(derotation_matrix)--> unrotated --(~transformation_matrix)--> PDF user space.
The ``~transformation_matrix`` step performs the Y-axis flip (pdf_y = page_height - web_y)
and also accounts for CropBox offsets.
"""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass

import pymupdf


class PlacementError(ValueError):
    """User-facing placement problem (bad page number, text not found, ...)."""


@dataclass
class SigBox:
    page_index: int  # 0-based
    x1: float
    y1: float
    x2: float
    y2: float
    rotation: int = 0  # page /Rotate, so the stamp can be drawn upright

    def as_tuple(self) -> tuple[float, float, float, float]:
        return (self.x1, self.y1, self.x2, self.y2)

    def to_dict(self) -> dict:
        return asdict(self)


MIN_SIZE = 20.0
POSITIONS = {"bottom-left", "bottom-right", "bottom-center", "top-left", "top-right", "custom"}
ANCHOR_PLACEMENTS = {"above", "below", "right", "overlay"}
ANCHOR_MATCHES = {"first", "last", "all"}
DEFAULT_MARGIN = 36.0  # 0.5 inch
ANCHOR_GAP = 4.0


# --------------------------------------------------------------------------- helpers
def _clamp_display_rect(page: pymupdf.Page, rect: pymupdf.Rect) -> pymupdf.Rect:
    """Keep the rect fully on the visible page, shifting (and if needed shrinking) it."""
    pr = page.rect
    w = min(rect.width, pr.width)
    h = min(rect.height, pr.height)
    x0 = min(max(rect.x0, pr.x0), pr.x1 - w)
    y0 = min(max(rect.y0, pr.y0), pr.y1 - h)
    return pymupdf.Rect(x0, y0, x0 + w, y0 + h)


def display_rect_to_pdf_box(page: pymupdf.Page, rect: pymupdf.Rect) -> SigBox:
    rect = _clamp_display_rect(page, rect)
    unrot = rect * page.derotation_matrix
    pdf = unrot * ~page.transformation_matrix
    pdf.normalize()
    return SigBox(page.number, round(pdf.x0, 2), round(pdf.y0, 2), round(pdf.x1, 2), round(pdf.y1, 2),
                  rotation=page.rotation % 360)


def _check_size(width: float, height: float) -> None:
    if width < MIN_SIZE or height < MIN_SIZE:
        raise PlacementError(f"Signature width/height must be at least {MIN_SIZE:.0f} pt.")
    if width > 2000 or height > 2000:
        raise PlacementError("Signature width/height is unreasonably large.")


def parse_page_spec(spec: str, page_count: int) -> list[int]:
    """'first' | 'last' | 'all' | '1,3,8' | '2-5,9' -> sorted unique 0-based indices."""
    spec = (spec or "").strip().lower()
    if spec in ("", "first"):
        return [0]
    if spec == "last":
        return [page_count - 1]
    if spec == "all":
        return list(range(page_count))
    if not re.fullmatch(r"[\d,\-\s]+", spec):
        raise PlacementError(f"Invalid page list '{spec}'. Use e.g. 8 or 1,3,8 or 2-5.")
    pages: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, _, b = part.partition("-")
            if not a.strip().isdigit() or not b.strip().isdigit():
                raise PlacementError(f"Invalid page range '{part}'.")
            lo, hi = int(a), int(b)
            if lo > hi:
                lo, hi = hi, lo
            pages.update(range(lo, hi + 1))
        else:
            pages.add(int(part))
    if not pages:
        raise PlacementError("No page numbers given.")
    bad = [p for p in sorted(pages) if p < 1 or p > page_count]
    if bad:
        raise PlacementError(f"Page(s) {', '.join(map(str, bad))} out of range (document has {page_count} pages).")
    return sorted(p - 1 for p in pages)


# --------------------------------------------------------------------------- mode 1: visual
def place_visual(doc: pymupdf.Document, *, page_number: int, x_pct: float, y_pct: float,
                 w_pct: float, h_pct: float) -> list[SigBox]:
    if page_number < 1 or page_number > doc.page_count:
        raise PlacementError(f"Page {page_number} out of range (document has {doc.page_count} pages).")
    for name, v in (("x_pct", x_pct), ("y_pct", y_pct), ("w_pct", w_pct), ("h_pct", h_pct)):
        if not (0.0 <= v <= 1.0):
            raise PlacementError(f"{name} must be between 0 and 1.")
    if w_pct <= 0 or h_pct <= 0:
        raise PlacementError("Draw a signature box on the page first.")
    page = doc[page_number - 1]
    pr = page.rect
    x0 = pr.x0 + x_pct * pr.width
    y0 = pr.y0 + y_pct * pr.height  # web Y grows downward, same as display space
    rect = pymupdf.Rect(x0, y0, x0 + w_pct * pr.width, y0 + h_pct * pr.height)
    if rect.width < 5 or rect.height < 5:
        raise PlacementError("Signature box is too small.")
    return [display_rect_to_pdf_box(page, rect)]


# --------------------------------------------------------------------------- mode 2: preset
def place_preset(doc: pymupdf.Document, *, pages: str, position: str, width: float, height: float,
                 margin_x: float = DEFAULT_MARGIN, margin_y: float = DEFAULT_MARGIN) -> list[SigBox]:
    position = position.lower()
    if position not in POSITIONS:
        raise PlacementError(f"Unknown position '{position}'.")
    _check_size(width, height)
    if margin_x < 0 or margin_y < 0:
        raise PlacementError("Margins cannot be negative.")
    boxes: list[SigBox] = []
    for idx in parse_page_spec(pages, doc.page_count):
        page = doc[idx]
        pr = page.rect
        W, H = pr.width, pr.height
        if position == "bottom-left":
            x0, y0 = margin_x, H - margin_y - height
        elif position == "bottom-right":
            x0, y0 = W - margin_x - width, H - margin_y - height
        elif position == "bottom-center":
            x0, y0 = (W - width) / 2, H - margin_y - height
        elif position == "top-left":
            x0, y0 = margin_x, margin_y
        elif position == "top-right":
            x0, y0 = W - margin_x - width, margin_y
        else:  # custom: X from left edge, Y from bottom edge (PDF convention)
            x0, y0 = margin_x, H - margin_y - height
        rect = pymupdf.Rect(pr.x0 + x0, pr.y0 + y0, pr.x0 + x0 + width, pr.y0 + y0 + height)
        boxes.append(display_rect_to_pdf_box(page, rect))
    return boxes


# --------------------------------------------------------------------------- mode 3: text anchor
def place_anchor(doc: pymupdf.Document, *, text: str, placement: str, match: str,
                 width: float, height: float, gap: float = ANCHOR_GAP) -> list[SigBox]:
    text = (text or "").strip()
    if not text:
        raise PlacementError("Enter the anchor text to search for.")
    placement, match = placement.lower(), match.lower()
    if placement not in ANCHOR_PLACEMENTS:
        raise PlacementError(f"Unknown anchor placement '{placement}'.")
    if match not in ANCHOR_MATCHES:
        raise PlacementError(f"Unknown match behaviour '{match}'.")
    _check_size(width, height)

    hits: list[tuple[pymupdf.Page, pymupdf.Rect]] = []
    for page in doc:
        for r in page.search_for(text):  # unrotated page coordinates
            hits.append((page, r * page.rotation_matrix))  # -> display coordinates
    if not hits:
        raise PlacementError(
            f"Text marker \"{text}\" was not found in the PDF. Scanned/image-only PDFs have no "
            "searchable text; use Visual or Page/Preset mode instead."
        )
    if match == "first":
        hits = hits[:1]
    elif match == "last":
        hits = hits[-1:]

    boxes: list[SigBox] = []
    for page, a in hits:
        a.normalize()
        cx, cy = (a.x0 + a.x1) / 2, (a.y0 + a.y1) / 2
        if placement == "above":
            rect = pymupdf.Rect(cx - width / 2, a.y0 - gap - height, cx + width / 2, a.y0 - gap)
        elif placement == "below":
            rect = pymupdf.Rect(cx - width / 2, a.y1 + gap, cx + width / 2, a.y1 + gap + height)
        elif placement == "right":
            rect = pymupdf.Rect(a.x1 + gap, cy - height / 2, a.x1 + gap + width, cy + height / 2)
        else:  # overlay, centred on the text
            rect = pymupdf.Rect(cx - width / 2, cy - height / 2, cx + width / 2, cy + height / 2)
        boxes.append(display_rect_to_pdf_box(page, rect))
    return boxes


# --------------------------------------------------------------------------- dispatcher
def _num(params: dict, key: str, default: float | None = None) -> float:
    v = params.get(key, default)
    if v is None or v == "":
        if default is None:
            raise PlacementError(f"Missing parameter '{key}'.")
        v = default
    try:
        return float(v)
    except (TypeError, ValueError):
        raise PlacementError(f"Parameter '{key}' must be a number.") from None


def compute_boxes(pdf_path: str, mode: str, params: dict, max_signatures: int) -> list[SigBox]:
    try:
        doc = pymupdf.open(pdf_path)
    except Exception as exc:  # noqa: BLE001
        raise PlacementError(f"Could not open PDF: {exc}") from None
    try:
        if doc.needs_pass:
            raise PlacementError("Password-protected PDFs are not supported.")
        if doc.page_count == 0:
            raise PlacementError("PDF has no pages.")
        if mode == "visual":
            boxes = place_visual(
                doc,
                page_number=int(_num(params, "page_number", 1)),
                x_pct=_num(params, "x_pct"),
                y_pct=_num(params, "y_pct"),
                w_pct=_num(params, "w_pct"),
                h_pct=_num(params, "h_pct"),
            )
        elif mode == "preset":
            pages = str(params.get("pages", "last"))
            if pages == "specific":
                pages = str(params.get("page_list", ""))
            boxes = place_preset(
                doc,
                pages=pages,
                position=str(params.get("position", "bottom-right")),
                width=_num(params, "width", 180),
                height=_num(params, "height", 65),
                margin_x=_num(params, "margin_x", DEFAULT_MARGIN),
                margin_y=_num(params, "margin_y", DEFAULT_MARGIN),
            )
        elif mode == "anchor":
            boxes = place_anchor(
                doc,
                text=str(params.get("text", "")),
                placement=str(params.get("placement", "above")),
                match=str(params.get("match", "first")),
                width=_num(params, "width", 180),
                height=_num(params, "height", 65),
            )
        else:
            raise PlacementError(f"Unknown placement mode '{mode}'.")
    finally:
        doc.close()
    if len(boxes) > max_signatures:
        raise PlacementError(
            f"This would add {len(boxes)} signatures; the limit is {max_signatures} per document."
        )
    return boxes
