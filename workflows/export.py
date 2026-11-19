"""Excel export of the findings in scope: a summary with charts, one row per application, and the detail rows.

``build_workbook`` is a pure function: it takes the frames that ``ui.state.filtered`` returns (already
scoped by the sidebar) and returns the .xlsx file as bytes. ``application_summary`` is the per-application
count behind both the workbook and the "By application" table on the Overview page.

openpyxl (write-only mode) writes the summary, the charts, the styles and the first row of every
table. The remaining table rows, about 190,000 for the full reports, are rendered as sheet XML with
pyarrow and spliced into the saved file (see "fast row splicing"): openpyxl alone needs minutes.
"""
from __future__ import annotations

import math
import re
import zipfile
from collections.abc import Iterable, Sequence
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from io import BytesIO
from xml.etree import ElementTree

import numpy as np
import pandas as pd
import pyarrow as pa
import pyarrow.compute as pc
from openpyxl import Workbook
from openpyxl.cell import WriteOnlyCell
from openpyxl.cell.cell import ERROR_CODES, ILLEGAL_CHARACTERS_RE
from openpyxl.chart import BarChart, Reference
from openpyxl.formatting.rule import DataBarRule
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.utils import get_column_letter

from tools import classifier, environment as env
from tools.data_loader import CS_CONTROLS

SUMMARY, APPLICATIONS, TOP, VULNS, MBSS, CS = (
    "Summary", "Applications", "Top 15 applications", "Open vulnerabilities", "MBSS failed checks", "CS gaps per server")
SHEETS = [SUMMARY, APPLICATIONS, TOP, VULNS, MBSS, CS]

SEVERITIES = ["Critical", "High", "Medium", "Low", "Minimal"]
SLA_STATES = ["Breached", "Due soon", "Within SLA"]
CRITICALITIES = ["Critical", "High", "Medium", "Low", "Minimal"]
GAP_STATES = ["Gap", "Partial"]
STAFF_COLUMNS = ("Application Delegate", "Section Manager", "Department Director")  # policies.yaml never_send
TOP_N = 15
MAX_DATA_ROWS = 1_048_576 - 1  # Excel's row limit, minus the header row

# The dashboard palette (ui/charts.py), without the "#".
PURPLE, PURPLE_LIGHT, RED, ORANGE, AMBER = "6A3FC4", "B9A5EA", "D03B3B", "EB6834", "C98500"
SEVERITY_COLORS = ["3A1780", "5F33B8", "7F59D3", "9C7FE0", "B9A5EA"]
SLA_COLORS = [RED, AMBER, PURPLE]
CONTROL_COLORS = ["3A1780", "6A3FC4", "9C7FE0", "EB6834", "C98500", "D03B3B"]

# Detail sheet columns, in order; columns a frame does not have are skipped. Long scanner output
# (Results, Description, Posture Evidence) and free-text comments are left out on purpose.
_PLACE = ["Platform", "Applications", "Report Application", "Device Name", "Host Name", "Environment", "Env Source"]
VULN_COLUMNS = _PLACE + ["Severity", "SLA Status", "Ageing in Days", "SLA Days", "SLA Remaining Days", "Title",
                         "Qualys ID", "Topic", "OS Family", "Operating System", "Port Number", "Related CVEs",
                         "Zero day", "Date First Found", "Date Last Found", "Last Scan Date Time", "Solution"]
MBSS_COLUMNS = _PLACE + ["Criticality", "OS Family", "Qualys Control ID", "Control Description", "Policy ID",
                         "Days Failing", "Posture Modified Date", "Evaluation Date", "Last Compliance Scan Date Time",
                         "Remediation"]
CS_COLUMNS = _PLACE + ["Gaps", "Controls with a gap"] + [f"{control} State" for control in CS_CONTROLS]

_HEADER_FONT = Font(bold=True, color="FFFFFF")
_HEADER_FILL = PatternFill("solid", fgColor=PURPLE)
_HEADER_ALIGN = Alignment(wrap_text=True, vertical="center")
_TITLE_FONT = Font(bold=True, size=16, color="1D1033")
_SECTION_FONT = Font(bold=True, size=12, color=PURPLE)
_BOLD = Font(bold=True)
_MUTED = Font(italic=True, color="6F6781")
_WRAP = Alignment(wrap_text=True, vertical="top")


# ------------------------------------------------------------------ counting ----
def _per_app(frame: pd.DataFrame, column: str | None = None, values: Sequence = (), servers: bool = False) -> pd.Series:
    """Rows (or distinct servers) per application, optionally only where ``column`` is in ``values``."""
    if frame.empty or (column is not None and column not in frame):
        return pd.Series(dtype="int64")
    if column is not None:
        frame = frame[frame[column].isin(values)]
    grouped = frame.groupby("Applications", observed=True)
    counts = grouped["Device Name"].nunique() if servers else grouped.size()
    return counts.set_axis(counts.index.astype(object))


_COUNTED = ("Applications", "Device Name", "Platform", "Environment", "Env Source", "Severity", "SLA Status", "Topic",
            "Criticality", "Gaps", *(f"{control} State" for control in CS_CONTROLS))


def _for_counting(frame: pd.DataFrame) -> pd.DataFrame:
    """Only the columns that are counted, with categorical keys: grouping 100k rows 27 times gets cheap."""
    if frame.empty:
        return frame
    slim = frame[[c for c in _COUNTED if c in frame]]
    return slim.assign(Applications=slim["Applications"].astype("category"),
                       **{"Device Name": slim["Device Name"].astype("category")})


def application_summary(vulns: pd.DataFrame, mbss: pd.DataFrame, cs: pd.DataFrame, devices: pd.DataFrame,
                        changes: pd.DataFrame | None = None) -> pd.DataFrame:
    """One row per application with server, vulnerability, MBSS and CS control counts.

    Every application seen in any of the four frames gets a row, so column totals match the inputs.
    ``changes`` is optional week-over-week data with "New" and "Fixed" counts per application (an
    "Applications" column or index), such as a per-application vulnerability comparison from a report
    history module; when given, the two columns are added after "Due soon". Sorted by findings past
    SLA, then open findings, MBSS failed checks and servers with a CS gap.
    """
    vulns, mbss, cs, devices = (_for_counting(frame) for frame in (vulns, mbss, cs, devices))
    frames = [frame for frame in (devices, vulns, mbss, cs) if not frame.empty]
    names: set[str] = set()
    for frame in frames:
        names.update(frame["Applications"].dropna().unique())
    out = pd.DataFrame(index=pd.Index(sorted(names), name="Application"))

    placed = [frame[["Applications", "Platform"]] for frame in frames if "Platform" in frame]
    if placed:
        platforms = pd.concat([frame.astype("string") for frame in placed]).dropna().drop_duplicates()
        out["Platform"] = platforms.groupby("Applications")["Platform"].agg(lambda v: ", ".join(sorted(map(str, v))))
    else:
        out["Platform"] = ""

    out["Servers"] = _per_app(devices, servers=True)
    out["Production"] = _per_app(devices, "Environment", [env.PROD], servers=True)
    out["Development"] = _per_app(devices, "Environment", [env.DEV], servers=True)
    out["Environment unconfirmed"] = _per_app(devices, "Env Source", [env.SRC_ASSUMED], servers=True)

    out["Servers with open vulnerabilities"] = _per_app(vulns, servers=True)
    out["Open findings"] = _per_app(vulns)
    for severity in SEVERITIES:
        out[severity] = _per_app(vulns, "Severity", [severity])
    out["Past SLA"] = _per_app(vulns, "SLA Status", ["Breached"])
    out["Due soon"] = _per_app(vulns, "SLA Status", ["Due soon"])
    if changes is not None:   # week-over-week: findings new / fixed since the previous report
        by_app = changes.set_index("Applications") if "Applications" in changes.columns else changes
        for column in ("New", "Fixed"):
            out[column] = by_app[column] if column in by_app else 0
    out["OS issues"] = _per_app(vulns, "Topic", [classifier.OS])
    out["Application issues"] = _per_app(vulns, "Topic", [classifier.APP])

    out["Servers with MBSS failures"] = _per_app(mbss, servers=True)
    out["MBSS failed checks"] = _per_app(mbss)
    out["MBSS Critical"] = _per_app(mbss, "Criticality", ["Critical"])
    out["MBSS High"] = _per_app(mbss, "Criticality", ["High"])

    out["Servers in the CS report"] = _per_app(cs, servers=True)
    out["Servers with a CS gap"] = _per_app(cs[cs["Gaps"] > 0] if "Gaps" in cs else cs.iloc[0:0], servers=True)
    for control in CS_CONTROLS:
        out[f"{control} gaps"] = _per_app(cs, f"{control} State", GAP_STATES, servers=True)

    counts = out.columns.drop("Platform")
    out[counts] = out[counts].fillna(0).astype("int64")
    out["Platform"] = out["Platform"].fillna("")
    out = out.reset_index()[["Platform", "Application", *counts]]
    return out.sort_values(["Past SLA", "Open findings", "MBSS failed checks", "Servers with a CS gap", "Application"],
                           ascending=[False, False, False, False, True], ignore_index=True)


def cs_gap_servers(cs: pd.DataFrame) -> pd.DataFrame:
    """Servers with at least one CS control gap, with a readable list of the controls that have one."""
    if cs.empty:
        return cs
    rows = cs[cs["Gaps"] > 0].copy()
    gaps = rows[[f"{control} State" for control in CS_CONTROLS]].isin(GAP_STATES).to_numpy()
    names = list(CS_CONTROLS)
    rows["Controls with a gap"] = [", ".join(n for n, gap in zip(names, row) if gap) for row in gaps]
    return rows


# ------------------------------------------------------------------- writing ----
def _cell(ws, value, font: Font | None = None, fill: PatternFill | None = None, number_format: str | None = None,
          alignment: Alignment | None = None) -> WriteOnlyCell:
    cell = WriteOnlyCell(ws, value=value)
    if font:
        cell.font = font
    if fill:
        cell.fill = fill
    if number_format:
        cell.number_format = number_format
    if alignment:
        cell.alignment = alignment
    return cell


def _text(ws, value) -> WriteOnlyCell:
    """A string cell that Excel never reads as a formula or an error code (scanner text can start with "=")."""
    cell = WriteOnlyCell(ws, value=None if value is None else str(value))
    cell.data_type = "s"
    return cell


def _values(ws, series: pd.Series) -> list:
    """Column values ready for openpyxl: None for blanks, plain Python types, safe strings."""
    if pd.api.types.is_datetime64_any_dtype(series):
        if getattr(series.dt, "tz", None) is not None:
            series = series.dt.tz_localize(None)
        return series.astype(object).where(series.notna(), None).tolist()
    if pd.api.types.is_numeric_dtype(series) or pd.api.types.is_bool_dtype(series):
        return series.astype(object).where(series.notna(), None).tolist()
    text = series.astype("string").str.replace(ILLEGAL_CHARACTERS_RE.pattern, "", regex=True)
    values = text.astype(object).where(text.notna(), None).tolist()
    risky = ((text.str.startswith("=") & text.str.len().gt(1)) | text.isin(list(ERROR_CODES))).fillna(False)
    for position in risky.to_numpy(dtype=bool).nonzero()[0]:
        values[position] = _text(ws, values[position])
    return values


def _width(series: pd.Series, header: str) -> float:
    lengths = series.head(2000).astype("string").str.len().dropna()
    content = float(lengths.quantile(0.9)) if len(lengths) else 0.0
    return min(max(content, min(len(header), 14), 6) + 2, 60)


def _write_table(ws, frame: pd.DataFrame, bulk: dict[str, pd.DataFrame] | None = None) -> None:
    """Header + rows with a frozen, wrapped header and an autofilter.

    With ``bulk``, openpyxl writes only the header and the first row (which fixes each column's
    style); the other rows are left in ``bulk[sheet title]`` for ``_splice_rows`` to add after saving.
    """
    columns = list(frame.columns)
    for index, column in enumerate(columns, 1):
        ws.column_dimensions[get_column_letter(index)].width = _width(frame[column], str(column))
    ws.freeze_panes = "A2"
    ws.row_dimensions[1].height = 45
    ws.append([_cell(ws, str(column), _HEADER_FONT, _HEADER_FILL, alignment=_HEADER_ALIGN) for column in columns])
    frame = frame.head(MAX_DATA_ROWS).reset_index(drop=True)
    written = frame if bulk is None else frame.head(1)
    values = []
    for column in columns:
        column_values = _values(ws, written[column])
        if bulk is not None and pd.api.types.is_datetime64_any_dtype(written[column]):
            # A styled cell even when blank, so the date format can be copied to the spliced rows.
            column_values = [_cell(ws, value, number_format=DATE_FORMAT) for value in column_values]
        values.append(column_values)
    for row in zip(*values):
        ws.append(row)
    if bulk is not None:
        bulk[ws.title] = frame.iloc[1:]
    ws.auto_filter.ref = f"A1:{get_column_letter(max(len(columns), 1))}{len(frame) + 1}"


# ------------------------------------------------------- fast row splicing ----
# openpyxl without lxml writes about 10,000 cells a second, so the ~3.7 million detail cells would
# take minutes. The detail rows are therefore rendered as sheet XML with pyarrow string kernels and
# spliced into the saved file. Their text goes into a shared-strings table: titles, solutions and
# application names repeat on thousands of rows and are stored once, which keeps the file small.
DATE_FORMAT = "yyyy-mm-dd hh:mm"
_EXCEL_EPOCH = pd.Timestamp("1899-12-30")
_CHUNK_ROWS = 20_000
_NS = {"main": "http://schemas.openxmlformats.org/spreadsheetml/2006/main",
       "rel": "http://schemas.openxmlformats.org/package/2006/relationships",
       "r": "http://schemas.openxmlformats.org/officeDocument/2006/relationships"}
_SST_PATH = "xl/sharedStrings.xml"
_SST_TYPE = "application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml"
_SST_REL = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/sharedStrings"


def _join(*parts) -> pa.Array:
    """Element-wise concatenation of string arrays and constants; null where any part is null."""
    typed = [pa.scalar(part, pa.large_string()) if isinstance(part, str)
             else part if part.type == pa.large_string() else part.cast(pa.large_string()) for part in parts]
    return pc.binary_join_element_wise(*typed, pa.scalar("", pa.large_string()))


def _utf8(array: pa.Array) -> memoryview:
    """The UTF-8 bytes of a null-free string array, end to end, without building Python strings."""
    offsets = np.frombuffer(array.buffers()[1], dtype=np.int64)
    return memoryview(array.buffers()[2])[offsets[array.offset]:offsets[array.offset + len(array)]]


def _shared_item(text: str) -> str:
    escaped = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return f'<si><t xml:space="preserve">{escaped}</t></si>' if text != text.strip() else f"<si><t>{escaped}</t></si>"


class _Splicer:
    """Renders rows as sheet XML and collects their text in one shared-strings table."""

    def __init__(self) -> None:
        self.strings: dict[str, int] = {}

    def _cell_ends(self, series: pd.Series, style: str) -> pa.Array:
        """Everything after the cell reference (style, type, value, closing tag); null where blank."""
        if pd.api.types.is_datetime64_any_dtype(series):
            if getattr(series.dt, "tz", None) is not None:
                series = series.dt.tz_localize(None)
            serial = ((series - _EXCEL_EPOCH) / pd.Timedelta(days=1)).to_numpy(dtype="float64", na_value=np.nan)
            values, kind = pc.cast(pa.array(serial, from_pandas=True), pa.large_string()), ""
        elif pd.api.types.is_bool_dtype(series):
            values, kind = pc.cast(pa.array(series.astype("Int64"), type=pa.int8()), pa.large_string()), ' t="b"'
        elif pd.api.types.is_numeric_dtype(series):
            if pd.api.types.is_float_dtype(series):
                series = series.where(series.abs() != float("inf"))
            values, kind = pc.cast(pa.array(series, from_pandas=True), pa.large_string()), ""
        else:
            codes, uniques = pd.factorize(series.astype("string"))
            cleaned = (pd.Series(uniques, dtype="string").str.replace(ILLEGAL_CHARACTERS_RE.pattern, "", regex=True)
                       .str.slice(0, 32767))   # Excel's limit per cell
            ids = np.array([self.strings.setdefault(text, len(self.strings)) for text in cleaned.tolist()],
                           dtype=np.int64)
            values = pc.cast(pa.array(ids, type=pa.int64()).take(pa.array(codes, mask=codes < 0)), pa.large_string())
            kind = ' t="s"'
        return _join(f'"{style}{kind}><v>', values, "</v></c>")

    def rows(self, frame: pd.DataFrame, styles: dict[str, str], first_row: int) -> Iterable[memoryview]:
        """<row> elements for ``frame``, numbered from ``first_row``, as UTF-8 chunks."""
        letters = [get_column_letter(index) for index in range(1, len(frame.columns) + 1)]
        columns = [(letter, self._cell_ends(frame[column], styles.get(letter, "")))
                   for letter, column in zip(letters, frame.columns)]
        for start in range(0, len(frame), _CHUNK_ROWS):
            count = min(_CHUNK_ROWS, len(frame) - start)
            numbers = pc.cast(pa.array(range(first_row + start, first_row + start + count)), pa.large_string())
            cells = [pc.fill_null(_join(f'<c r="{letter}', numbers, ends.slice(start, count)), "")
                     for letter, ends in columns]
            yield _utf8(_join('<row r="', numbers, '">', *cells, "</row>"))

    def shared_strings(self) -> bytes:
        items = "".join(map(_shared_item, self.strings))
        return f'<sst xmlns="{_NS["main"]}" uniqueCount="{len(self.strings)}">{items}</sst>'.encode("utf-8")


def _sheet_paths(archive: zipfile.ZipFile) -> dict[str, str]:
    """Sheet title -> path of its XML inside the .xlsx."""
    workbook = ElementTree.fromstring(archive.read("xl/workbook.xml"))
    rels = ElementTree.fromstring(archive.read("xl/_rels/workbook.xml.rels"))
    targets = {rel.get("Id"): rel.get("Target") for rel in rels.findall("rel:Relationship", _NS)}
    paths = {}
    for sheet in workbook.findall("main:sheets/main:sheet", _NS):
        target = targets[sheet.get(f"{{{_NS['r']}}}id")]
        paths[sheet.get("name")] = target.lstrip("/") if target.startswith("/") else f"xl/{target}"
    return paths


def _splice_rows(blob: bytes, bulk: dict[str, pd.DataFrame]) -> bytes:
    """Add the rows held in ``bulk`` (row 3 onwards) to the saved workbook."""
    source = zipfile.ZipFile(BytesIO(blob))
    pending = {path: bulk[title] for title, path in _sheet_paths(source).items()
               if title in bulk and not bulk[title].empty}
    if not pending:
        return blob
    if _SST_PATH in source.namelist():   # openpyxl write-only uses inline strings; never expected
        raise RuntimeError("The workbook already has a shared-strings table.")
    splicer, out = _Splicer(), BytesIO()
    package = {"[Content_Types].xml": "", "xl/_rels/workbook.xml.rels": ""}   # rewritten at the end
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED, compresslevel=3) as target:
        for info in source.infolist():
            data = source.read(info.filename)
            if info.filename in package:
                package[info.filename] = data.decode("utf-8")
            elif info.filename not in pending:
                target.writestr(info, data)
            else:
                frame = pending[info.filename].reset_index(drop=True)
                head, tail = data.decode("utf-8").split("</sheetData>", 1)
                styles = {letter: f' s="{style}"' for letter, style in
                          re.findall(r'<c r="([A-Z]+)2" s="(\d+)"', head[head.index('<row r="2"'):])}
                if "<dimension" not in head:
                    last = f"{get_column_letter(len(frame.columns))}{len(frame) + 2}"
                    head = head.replace("<sheetViews>", f'<dimension ref="A1:{last}" /><sheetViews>', 1)
                with target.open(info.filename, "w") as stream, \
                        ThreadPoolExecutor(max_workers=1) as writer:
                    stream.write(head.encode("utf-8"))
                    # zlib releases the GIL: compress one chunk while the next one is rendered.
                    written = None
                    for chunk in splicer.rows(frame, styles, first_row=3):
                        if written is not None:
                            written.result()
                        written = writer.submit(stream.write, chunk)
                    if written is not None:
                        written.result()
                    stream.write(("</sheetData>" + tail).encode("utf-8"))
        types, rels = package["[Content_Types].xml"], package["xl/_rels/workbook.xml.rels"]
        if splicer.strings:
            target.writestr(_SST_PATH, splicer.shared_strings())
            types = types.replace("</Types>", f'<Override PartName="/{_SST_PATH}" ContentType="{_SST_TYPE}" /></Types>')
            rels = rels.replace("</Relationships>", f'<Relationship Type="{_SST_REL}" Target="sharedStrings.xml" '
                                                    'Id="rIdSharedStrings" /></Relationships>')
        target.writestr("xl/_rels/workbook.xml.rels", rels)
        target.writestr("[Content_Types].xml", types)
    return out.getvalue()


def _detail(frame: pd.DataFrame, columns: Sequence[str], staff_columns: Sequence[str], include_staff: bool,
            order: dict[str, list[str]], tiebreak: Sequence[str], descending: Sequence[str] = ()) -> pd.DataFrame:
    """Only the useful columns, sorted, with "Applications" shown as "Application"."""
    keep = [c for c in columns if c in frame.columns and c not in staff_columns]
    if include_staff:
        keep += [c for c in staff_columns if c in frame.columns]
    out = frame[keep] if not frame.empty else pd.DataFrame(columns=keep)
    keys = [c for c in (*descending, *order, *tiebreak) if c in out.columns]
    if keys and not out.empty:
        ranks = {name: {value: i for i, value in enumerate(values)} for name, values in order.items()}
        out = out.sort_values(keys, ascending=[c not in descending for c in keys], kind="stable",
                              key=lambda s: s.map(ranks[s.name]) if s.name in ranks else s)
    return out.rename(columns={"Applications": "Application"})


def _bar_chart(ws, title: str, header_row: int, last_row: int, first_col: int, last_col: int,
               colors: Sequence[str], *, horizontal: bool, stacked: bool, percent: bool = False) -> BarChart:
    """A bar chart over a block of rows: categories in column A, one series per column."""
    chart = BarChart()
    chart.type = "bar" if horizontal else "col"
    chart.grouping = "stacked" if stacked else "clustered"
    if stacked:
        chart.overlap = 100
    chart.gapWidth = 60
    chart.title = title
    chart.add_data(Reference(ws, min_col=first_col, max_col=last_col, min_row=header_row, max_row=last_row),
                   titles_from_data=True)
    chart.set_categories(Reference(ws, min_col=1, min_row=header_row + 1, max_row=last_row))
    for series, color in zip(chart.series, colors):
        series.graphicalProperties.solidFill = color
        series.graphicalProperties.line.solidFill = color
    chart.title.overlay = False   # unset, Excel draws the title over the plot area
    chart.x_axis.delete = False   # openpyxl 3.1 hides the axes unless told otherwise
    chart.y_axis.delete = False
    if horizontal:
        chart.x_axis.scaling.orientation = "maxMin"   # first row at the top ...
        chart.y_axis.crosses = "max"                  # ... and the value axis still at the bottom
    if percent:
        chart.y_axis.number_format = "0%"
        chart.y_axis.scaling.min, chart.y_axis.scaling.max = 0, 1
    if first_col == last_col:
        chart.legend = None
    else:
        chart.legend.position = "b"
        chart.legend.overlay = False
    chart.width, chart.height = 16, 10
    return chart


class _Rows:
    """Appends rows to a write-only sheet and keeps the row number, for chart references."""

    def __init__(self, ws):
        self.ws, self.row = ws, 0

    def add(self, *values) -> int:
        self.ws.append(list(values))
        self.row += 1
        return self.row

    def blank(self, count: int = 1) -> None:
        for _ in range(count):
            self.add()

    def section(self, title: str) -> int:
        return self.add(_cell(self.ws, title, _SECTION_FONT))

    def header(self, *labels: str) -> int:
        return self.add(*(_cell(self.ws, label, _HEADER_FONT, _HEADER_FILL, alignment=_HEADER_ALIGN)
                          for label in labels))

    def note(self, text: str, last_column: str = "H", chars_per_line: int = 125) -> int:
        """A wrapped note across columns A..last_column."""
        lines = max(1, math.ceil(len(text) / chars_per_line))
        self.ws.row_dimensions[self.row + 1].height = 15 * lines + 2
        row = self.add(_cell(self.ws, text, _MUTED, alignment=_WRAP))
        self.ws.merged_cells.add(f"A{row}:{last_column}{row}")
        return row


def _share(part: int, whole: int) -> float | None:
    return part / whole if whole else None


def _write_summary(ws, vulns, mbss, cs, devices, apps: pd.DataFrame, *, scope: str, report_dates: dict[str, str],
                   generated_at: datetime, due_soon_days: int | None, notes: list[str]) -> None:
    for letter, width in zip("ABCDEFG", (46, 16, 14, 14, 13, 13, 11)):
        ws.column_dimensions[letter].width = width
    rows, pct = _Rows(ws), "0.0%"

    rows.add(_cell(ws, "Security posture export", _TITLE_FONT))
    rows.add(_cell(ws, "Generated", _BOLD), f"{generated_at:%d %b %Y %H:%M}")
    rows.add(_cell(ws, "Scope", _BOLD), _text(ws, scope))
    for label, value in report_dates.items():
        rows.add(_cell(ws, label, _BOLD), _text(ws, value))
    rows.blank()
    rows.section("Read me")
    for note in notes:
        rows.note(note)
    rows.blank()

    servers = devices["Device Name"].nunique() if not devices.empty else 0
    production = int((devices["Environment"] == env.PROD).sum()) if not devices.empty else 0
    development = int((devices["Environment"] == env.DEV).sum()) if not devices.empty else 0
    assumed = int((devices["Env Source"] == env.SRC_ASSUMED).sum()) if not devices.empty else 0
    breached = int((vulns["SLA Status"] == "Breached").sum()) if not vulns.empty else 0
    due_soon = int((vulns["SLA Status"] == "Due soon").sum()) if not vulns.empty else 0
    vuln_servers = vulns["Device Name"].nunique() if not vulns.empty else 0
    gap_servers = int((cs["Gaps"] > 0).sum()) if not cs.empty else 0
    rows.section("Headline numbers")
    rows.header("Measure", "Count", "Share")
    for label, count, share in [
        ("Applications", len(apps), None),
        ("Servers in scope", servers, None),
        ("Production servers", production, _share(production, servers)),
        ("Development servers", development, _share(development, servers)),
        ("Environment unconfirmed (counted as Production)", assumed, _share(assumed, servers)),
        ("Open vulnerabilities", len(vulns), None),
        ("Unique findings (titles)", vulns["Title"].nunique() if "Title" in vulns else 0, None),
        ("Servers with open vulnerabilities", vuln_servers, _share(vuln_servers, servers)),
        ("Past SLA", breached, _share(breached, len(vulns))),
        (f"Due soon (≤{due_soon_days} days left)" if due_soon_days is not None else "Due soon", due_soon,
         _share(due_soon, len(vulns))),
        ("MBSS failed checks", len(mbss), None),
        ("Servers with MBSS failures", mbss["Device Name"].nunique() if not mbss.empty else 0, None),
        ("Servers in the CS Controls report", cs["Device Name"].nunique() if not cs.empty else 0, None),
        ("Servers with a CS control gap", gap_servers, _share(gap_servers, len(cs))),
    ]:
        rows.add(label, count, _cell(ws, share, number_format=pct) if share is not None else None)
    rows.blank()

    # The four charts sit in a 2 x 2 grid here; their data are the tables below the grid.
    grid_top = rows.row + 1
    rows.blank(46)
    charts: dict[str, BarChart] = {}

    rows.section("Open vulnerabilities by severity and SLA status")
    if vulns.empty:
        rows.add(_cell(ws, "No vulnerability data in scope.", _MUTED))
    else:
        table = pd.crosstab(vulns["Severity"], vulns["SLA Status"]).reindex(index=SEVERITIES, columns=SLA_STATES,
                                                                              fill_value=0)
        header = rows.header("Severity", *SLA_STATES, "Total")
        for severity, counts in table.iterrows():
            last = rows.add(severity, *map(int, counts), int(counts.sum()))
        rows.add(_cell(ws, "Total", _BOLD), *map(int, table.sum()), int(table.to_numpy().sum()))
        charts["severity"] = _bar_chart(ws, "Open vulnerabilities by severity and SLA status", header, last,
                                        2, 1 + len(SLA_STATES), SLA_COLORS, horizontal=False, stacked=True)
    rows.blank()

    rows.section("MBSS failed checks by criticality")
    if mbss.empty:
        rows.add(_cell(ws, "No MBSS data in scope.", _MUTED))
    else:
        rows.header("Criticality", "Failed checks", "Servers")
        present = set(mbss["Criticality"].dropna())
        for level in [c for c in CRITICALITIES if c in present] + sorted(present - set(CRITICALITIES)):
            part = mbss[mbss["Criticality"] == level]
            rows.add(level, len(part), part["Device Name"].nunique())
        rows.add(_cell(ws, "Total", _BOLD), len(mbss), mbss["Device Name"].nunique())
    rows.blank()

    rows.section("CS control coverage per control (exceptions and servers not in scope are left out)")
    if cs.empty:
        rows.add(_cell(ws, "No CS Controls data in scope.", _MUTED))
    else:
        header = rows.header("Control", "Servers in scope", "Implemented", "Gap or partial", "Exception",
                             "Not in scope", "Coverage")
        for control in CS_CONTROLS:
            states = cs[f"{control} State"].value_counts()
            implemented, partial, gap = (int(states.get(s, 0)) for s in ("Implemented", "Partial", "Gap"))
            in_scope = implemented + partial + gap
            last = rows.add(control, in_scope, implemented, partial + gap, int(states.get("Exception", 0)),
                            int(states.get("Not in scope", 0)),
                            _cell(ws, _share(implemented, in_scope), number_format="0%"))
        charts["coverage"] = _bar_chart(ws, "CS control coverage (implemented / in scope)", header, last, 7, 7,
                                        [PURPLE], horizontal=False, stacked=False, percent=True)
    rows.blank()

    rows.section(f"Top {TOP_N} applications by findings past SLA")
    breached_apps = apps[apps["Past SLA"] > 0].head(TOP_N)
    if breached_apps.empty:
        rows.add(_cell(ws, "Nothing is past SLA in this scope.", _MUTED))
    else:
        header = rows.header("Application", "Past SLA", "Open findings")
        for _, app in breached_apps.iterrows():
            last = rows.add(_text(ws, app["Application"]), int(app["Past SLA"]), int(app["Open findings"]))
        charts["past_sla"] = _bar_chart(ws, f"Top {TOP_N} applications by findings past SLA", header, last, 2, 2,
                                        [RED], horizontal=True, stacked=False)
    rows.blank()

    rows.section(f"Production and development servers, top {TOP_N} applications")
    top = apps.head(TOP_N)
    if top.empty or devices.empty:
        rows.add(_cell(ws, "No servers in scope.", _MUTED))
    else:
        production = devices[devices["Environment"] == env.PROD]
        assumed = production["Env Source"] == env.SRC_ASSUMED
        split = pd.DataFrame({"confirmed": _per_app(production[~assumed], servers=True),
                              "unconfirmed": _per_app(production[assumed], servers=True),
                              "development": _per_app(devices, "Environment", [env.DEV], servers=True)})
        split = split.reindex(top["Application"]).fillna(0).astype("int64")
        header = rows.header("Application", "Production (confirmed)", "Production (unconfirmed)", "Development")
        for application, counts in split.iterrows():
            last = rows.add(_text(ws, application), *map(int, counts))
        charts["environment"] = _bar_chart(ws, f"Production and development servers, top {TOP_N} applications",
                                           header, last, 2, 4, [PURPLE, PURPLE_LIGHT, ORANGE],
                                           horizontal=True, stacked=True)

    for key, anchor in (("severity", f"A{grid_top}"), ("past_sla", f"E{grid_top}"),
                        ("coverage", f"A{grid_top + 23}"), ("environment", f"E{grid_top + 23}")):
        if key in charts:
            ws.add_chart(charts[key], anchor)


def _write_applications(ws, apps: pd.DataFrame, bulk: dict[str, pd.DataFrame]) -> None:
    _write_table(ws, apps, bulk)
    last = len(apps) + 1
    for index, column in enumerate(apps.columns, 1):
        if column in ("Platform", "Application") or apps.empty:
            continue
        letter = get_column_letter(index)
        ws.conditional_formatting.add(
            f"{letter}2:{letter}{last}",
            DataBarRule(start_type="num", start_value=0, end_type="max",
                        color=RED if column == "Past SLA" else PURPLE_LIGHT))


def _write_top(ws, apps: pd.DataFrame) -> None:
    """The per-application charts, for the top 15 applications only."""
    top = apps.head(TOP_N)
    gap_columns = [f"{control} gaps" for control in CS_CONTROLS]
    table = top[["Application", *SEVERITIES, "Production", "Development", *gap_columns]]
    ws.column_dimensions["A"].width = 36
    for index in range(2, len(table.columns) + 1):
        ws.column_dimensions[get_column_letter(index)].width = 12
    rows = _Rows(ws)
    rows.note(f"Top {TOP_N} applications, in the order of the Applications sheet (most findings past SLA first). "
              "Every application is on the Applications sheet.", last_column="L")
    header = rows.header(*table.columns)
    if table.empty:
        rows.add(_cell(ws, "No applications in scope.", _MUTED))
        return
    for values in table.itertuples(index=False):
        last = rows.add(_text(ws, values[0]), *map(int, values[1:]))
    env_col = 2 + len(SEVERITIES)
    gap_col = env_col + 2
    charts = [
        _bar_chart(ws, "Open vulnerabilities by severity", header, last, 2, 1 + len(SEVERITIES), SEVERITY_COLORS,
                   horizontal=True, stacked=True),
        _bar_chart(ws, "Production and development servers", header, last, env_col, env_col + 1, [PURPLE, ORANGE],
                   horizontal=True, stacked=True),
        _bar_chart(ws, "Servers with a CS control gap, per control", header, last, gap_col,
                   gap_col + len(gap_columns) - 1, CONTROL_COLORS, horizontal=True, stacked=True),
    ]
    for number, chart in enumerate(charts):
        chart.height = 11
        ws.add_chart(chart, f"A{last + 3 + number * 25}")


def build_workbook(vulns: pd.DataFrame, mbss: pd.DataFrame, cs: pd.DataFrame, devices: pd.DataFrame, *,
                   scope: str = "All platforms", report_dates: dict[str, str] | None = None,
                   due_soon_days: int | None = None, staff_columns: Iterable[str] = STAFF_COLUMNS,
                   include_staff: bool = False, changes: pd.DataFrame | None = None,
                   generated_at: datetime | None = None) -> bytes:
    """Build the export workbook for the frames in scope and return it as .xlsx bytes.

    ``staff_columns`` are the personal-data columns (guardrails/policies.yaml -> llm_input.never_send);
    they stay out of the detail sheets unless ``include_staff`` is True. ``changes`` is optional
    week-over-week data per application (see ``application_summary``).
    """
    staff_columns = list(staff_columns)
    apps = application_summary(vulns, mbss, cs, devices, changes)
    vuln_rows = _detail(vulns, VULN_COLUMNS, staff_columns, include_staff,
                        {"SLA Status": SLA_STATES, "Severity": SEVERITIES}, ["Applications", "Device Name", "Title"])
    mbss_rows = _detail(mbss, MBSS_COLUMNS, staff_columns, include_staff,
                        {"Criticality": CRITICALITIES}, ["Applications", "Device Name", "Qualys Control ID"])
    cs_rows = _detail(cs_gap_servers(cs), CS_COLUMNS, staff_columns, include_staff, {},
                      ["Applications", "Device Name"], descending=["Gaps"])

    servers = devices["Device Name"].nunique() if not devices.empty else 0
    assumed = int((devices["Env Source"] == env.SRC_ASSUMED).sum()) if not devices.empty else 0
    staff = ", ".join(staff_columns)
    notes = [
        f"{assumed:,} of {servers:,} servers have no confirmed environment (Env Source = Assumed) and are counted as "
        "Production, so the production / development split is only as good as the environment mapping (Settings "
        "page). The Applications sheet counts them in the \"Environment unconfirmed\" column.",
        (f"Staff-name columns ({staff}) are included on request: they are personal data." if include_staff else
         f"Staff-name columns ({staff}) are left out: they are personal data "
         "(guardrails/policies.yaml, llm_input.never_send)."),
        "Past SLA: older than the SLA for its severity, or marked Non-Compliant in the report. Due soon: still "
        f"inside SLA with {due_soon_days if due_soon_days is not None else 'a few'} days or fewer left.",
        "For servers in the AI Platforms Inventory the platform name replaces the report's application name; the "
        "report's own label is in the Report Application column of the detail sheets.",
        f"Charts cover the top {TOP_N} applications by findings past SLA. Every application is on the Applications "
        "sheet; the detail sheets hold every open finding, every failed MBSS check and every server with a CS gap.",
        "Scanner output (Results, Description), comments and MBSS posture evidence are left out to keep the file "
        "small; Solution and Remediation text are kept.",
        ("New / Fixed compare this report with the previous one." if changes is not None else
         "Week-over-week New / Fixed columns are not available yet: no report history is kept in this build."),
    ]
    for name, frame in ((VULNS, vuln_rows), (MBSS, mbss_rows), (CS, cs_rows)):
        if len(frame) > MAX_DATA_ROWS:
            notes.append(f"{name}: only the first {MAX_DATA_ROWS:,} of {len(frame):,} rows fit in one Excel sheet.")

    workbook = Workbook(write_only=True)
    workbook.properties.title = "Security posture export"
    workbook.properties.creator = "Security Posture Dashboard"
    sheets = {name: workbook.create_sheet(name) for name in SHEETS}
    _write_summary(sheets[SUMMARY], vulns, mbss, cs, devices, apps, scope=scope, report_dates=report_dates or {},
                   generated_at=generated_at or datetime.now(), due_soon_days=due_soon_days, notes=notes)
    bulk: dict[str, pd.DataFrame] = {}
    _write_applications(sheets[APPLICATIONS], apps, bulk)
    _write_top(sheets[TOP], apps)
    for name, frame in ((VULNS, vuln_rows), (MBSS, mbss_rows), (CS, cs_rows)):
        _write_table(sheets[name], frame, bulk)
    buffer = BytesIO()
    workbook.save(buffer)
    return _splice_rows(buffer.getvalue(), bulk)
