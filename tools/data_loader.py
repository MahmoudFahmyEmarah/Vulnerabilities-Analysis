"""Find, validate, normalise and cache the three security reports.

* Vulnerability report  -> one row per open finding per server
* MBSS report           -> one row per failed baseline control per server
* CS Controls report    -> one row per server with the state of each security control

Excel parsing is slow, so every file is parsed once and stored as Parquet under
.cache/, keyed by path, size and modification time. A changed file is re-parsed.
Next to each Parquet file sit two small files: ``.meta.json`` (the report date, row count and
skipped sheets) and ``.summary-*.parquet`` (per-server counts for the weekly trend).

A file's week comes from its data, not from the file system: the latest "Last Scan Date Time"
(vulnerabilities) or "Evaluation Date" (MBSS). The CS report has no date column, so it uses the
date the workbook was last saved, or the file's modification time.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import zipfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable

import pandas as pd

import settings

log = logging.getLogger(__name__)

LOADER_VERSION = "4"  # bump when normalisation changes, to invalidate cached Parquet

VULN = "vulnerabilities"
MBSS = "mbss"
CS = "cs_controls"
KIND_LABEL = {VULN: "Vulnerability report", MBSS: "MBSS report", CS: "CS Controls report"}

_NAME_HINT = {VULN: r"vulnerab", MBSS: r"mbss", CS: r"cs[\s_\-]*control"}
_HEADER_HINT = {VULN: {"Qualys ID", "Severity"}, MBSS: {"MBSS Score"}, CS: {"Antivirus", "SIEM"}}

# Column names that changed between report versions -> the name used in this app.
ALIASES = {
    "Department": "Department Name",
    "Application Name": "Applications",
    "Application": "Applications",
}

REQUIRED = {
    VULN: ["Applications", "Device Name", "Title", "Severity", "Overall Status", "Ageing in Days",
           "SLA Breached?", "Operating System", "Description", "Solution", "Results"],
    MBSS: ["Applications", "Device Name", "Overall Status", "Criticality", "Control Description",
           "Qualys Control ID", "Remediation"],
    CS: ["Applications", "Device Name", "Antivirus", "EDR Server", "SIEM", "VM Integration",
         "Qualys Agent", "PAM-NIAM-ISE"],
}

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Minimal"]

# CS control name -> (status column, score column or None)
CS_CONTROLS = {
    "Antivirus": ("Antivirus", "AV Score"),
    "EDR": ("EDR Server", "EDR Score"),
    "SIEM": ("SIEM", "SIEM Score"),
    "Vulnerability scan": ("VM Integration", "VM Score"),
    "Qualys agent": ("Qualys Agent", None),
    "PAM": ("PAM-NIAM-ISE", "PAM Score"),
}
CS_STATES = ["Implemented", "Partial", "Gap", "Exception", "Not in scope"]
_CS_IMPLEMENTED = {"implemented", "scanned with authentication"}
_CS_NOT_IN_SCOPE = {"not applicable", "out of scope", "scanned - authentication not applicable", ""}


class SchemaError(ValueError):
    """The file does not look like the expected report."""


# Column that dates each report (its "week"). The CS report has none.
REPORT_DATE_COLUMN = {VULN: "Last Scan Date Time", MBSS: "Evaluation Date"}
FILE_DATE = "file date"

# What identifies one finding across weeks.
FINDING_KEY = {VULN: ["Device Name", "Qualys ID", "Port Number"], MBSS: ["Device Name", "Qualys Control ID"],
               CS: ["Device Name"]}


@dataclass(frozen=True)
class FileInfo:
    """One report file and the date of the data inside it."""
    path: Path
    kind: str
    report_date: datetime          # always set: falls back to the file date
    date_source: str               # the column the date came from, or FILE_DATE
    rows: int | None = None
    skipped_sheets: tuple[str, ...] = ()
    error: str | None = None


# ---------------------------------------------------------------- discovery ----
def sniff_kind(path: Path) -> str | None:
    """Work out which report a file is: by name first, then by its header row."""
    name = path.name.lower()
    for kind, pattern in _NAME_HINT.items():
        if re.search(pattern, name):
            return kind
    try:
        import openpyxl

        workbook = openpyxl.load_workbook(path, read_only=True)
        header = {str(cell) for cell in next(workbook.worksheets[0].iter_rows(values_only=True)) if cell}
        workbook.close()
    except Exception:  # noqa: BLE001 - unreadable file is simply "not a report"
        return None
    for kind, columns in _HEADER_HINT.items():
        if columns <= header:
            return kind
    return None


def describe_files(folder: Path) -> dict[str, list[FileInfo]]:
    """Report files in ``folder`` grouped by kind, newest report date first.

    "Newest" is the date of the data inside the file (see FileInfo), so uploading last week's
    file after this week's does not make the old one the default. The first call for a new file
    parses it once (the result is cached); later calls read a small sidecar file.
    """
    found: dict[str, list[FileInfo]] = {VULN: [], MBSS: [], CS: []}
    if not folder.exists():
        return found
    for path in folder.glob("*.xls*"):
        if path.name.startswith("~$"):
            continue
        kind = sniff_kind(path)
        if kind:
            found[kind].append(file_info(kind, path))
    for infos in found.values():
        infos.sort(key=lambda info: (info.report_date, info.path.stat().st_mtime), reverse=True)
    return found


def discover_files(folder: Path) -> dict[str, list[Path]]:
    """Report files in ``folder`` grouped by kind, newest report date first."""
    return {kind: [info.path for info in infos] for kind, infos in describe_files(folder).items()}


# ------------------------------------------------------------------ reading ----
def _cache_stem(kind: str, path: Path) -> str:
    stat = path.stat()
    key = f"{path.resolve()}|{stat.st_size}|{stat.st_mtime_ns}|{LOADER_VERSION}"
    return f"{kind}-{hashlib.sha1(key.encode()).hexdigest()[:16]}"


def _cache_file(kind: str, path: Path) -> Path:
    return settings.cache_dir() / f"{_cache_stem(kind, path)}.parquet"


def _write_atomic(target: Path, write: Callable[[Path], None]) -> None:
    """Write to a temporary file first, so a crash or a second user never leaves a half-written cache."""
    temporary = target.with_name(f"{target.name}.{os.getpid()}.tmp")
    try:
        write(temporary)
        os.replace(temporary, target)
    finally:
        temporary.unlink(missing_ok=True)


def _read_sheets(path: Path) -> dict[str, pd.DataFrame]:
    try:
        return pd.read_excel(path, sheet_name=None, engine="calamine")
    except ImportError:
        return pd.read_excel(path, sheet_name=None)


def _clean_platform(values: pd.Series) -> pd.Series:
    return values.astype("string").str.strip().str.rstrip(":").str.strip()


def _combine(path: Path, kind: str, skipped: list[str] | None = None) -> pd.DataFrame:
    """Read every sheet, apply aliases, check required columns, add Platform.

    A sheet without the required columns (a summary or pivot sheet) is skipped and named in
    ``skipped``; the file is rejected only when no sheet has them.
    """
    frames, problems = [], []
    for sheet, frame in _read_sheets(path).items():
        if frame.empty:
            continue
        frame = frame.loc[:, [c for c in frame.columns if not str(c).startswith("Unnamed")]]
        frame = frame.rename(columns={old: new for old, new in ALIASES.items()
                                      if old in frame.columns and new not in frame.columns})
        missing = [column for column in REQUIRED[kind] if column not in frame.columns]
        if missing:
            problems.append(f"sheet '{sheet}' is missing columns: {', '.join(missing)}. "
                            f"Found: {', '.join(map(str, frame.columns[:12]))} ...")
            continue
        department = frame["Department Name"] if "Department Name" in frame.columns else pd.Series(sheet, index=frame.index)
        frame["Platform"] = _clean_platform(department).fillna(sheet)
        frames.append(frame)
    if not frames and problems:
        raise SchemaError(f"{path.name}: {problems[0]}")
    if not frames:
        raise SchemaError(f"{path.name} has no data rows.")
    for problem in problems:
        log.warning("%s: skipped %s", path.name, problem)
        if skipped is not None:
            skipped.append(problem)
    combined = pd.concat(frames, ignore_index=True)
    for column in ("Applications", "Device Name"):
        combined[column] = combined[column].astype("string").str.strip()
    combined = combined.dropna(subset=["Device Name"])
    combined["Applications"] = combined["Applications"].fillna("(no application)")
    return combined


def _to_parquet_safe(frame: pd.DataFrame) -> pd.DataFrame:
    for column in frame.columns:
        if frame[column].dtype == object:
            frame[column] = frame[column].astype("string")
    return frame


def _load(kind: str, path: Path, prepare) -> pd.DataFrame:
    cache = _cache_file(kind, path)
    if cache.exists():
        return pd.read_parquet(cache)
    skipped: list[str] = []
    frame = _to_parquet_safe(prepare(_combine(path, kind, skipped)))
    _write_atomic(cache, lambda target: frame.to_parquet(target, index=False))
    _write_meta(kind, path, frame, skipped)
    return frame


def _dates(values: pd.Series) -> pd.Series:
    return pd.to_datetime(values, errors="coerce", format="mixed")


# ------------------------------------------------------------- report dates ----
_INFO: dict[str, FileInfo] = {}   # in-process copy of the .meta.json files


def _meta_file(kind: str, path: Path) -> Path:
    return settings.cache_dir() / f"{_cache_stem(kind, path)}.meta.json"


def file_date(path: Path) -> datetime:
    """When the workbook was last saved (kept when the file is copied or uploaded), else its mtime."""
    try:
        with zipfile.ZipFile(path) as archive:
            core = archive.read("docProps/core.xml").decode("utf-8", "replace")
        found = re.search(r"<dcterms:modified[^>]*>([^<]+)</dcterms:modified>", core)
        if found:
            saved = pd.Timestamp(found.group(1).strip())
            return (saved.tz_convert(None) if saved.tzinfo else saved).to_pydatetime()
    except Exception:  # noqa: BLE001 - not a zip, no core properties, odd date: use the file system
        pass
    return datetime.fromtimestamp(path.stat().st_mtime)


def report_date(kind: str, frame: pd.DataFrame) -> datetime | None:
    """Latest date in the report's date column (the week the data belongs to), or None."""
    column = REPORT_DATE_COLUMN.get(kind)
    if not column or column not in frame or frame.empty:
        return None
    latest = pd.to_datetime(frame[column], errors="coerce").max()
    return None if pd.isna(latest) else latest.to_pydatetime()


def _write_meta(kind: str, path: Path, frame: pd.DataFrame, skipped: list[str]) -> FileInfo:
    from_data = report_date(kind, frame)
    info = FileInfo(path, kind, from_data or file_date(path),
                    REPORT_DATE_COLUMN[kind] if from_data else FILE_DATE, len(frame), tuple(skipped))
    payload = {"kind": kind, "report_date": info.report_date.isoformat(), "date_source": info.date_source,
               "rows": info.rows, "skipped_sheets": list(info.skipped_sheets)}
    _write_atomic(_meta_file(kind, path), lambda target: target.write_text(json.dumps(payload), "utf-8"))
    _INFO[_cache_stem(kind, path)] = info
    return info


def _read_meta(kind: str, path: Path) -> FileInfo | None:
    meta = _meta_file(kind, path)
    if not meta.exists():
        return None
    try:
        payload = json.loads(meta.read_text("utf-8"))
        return FileInfo(path, kind, datetime.fromisoformat(payload["report_date"]), payload["date_source"],
                        payload.get("rows"), tuple(payload.get("skipped_sheets", ())))
    except (ValueError, KeyError, TypeError):
        return None


def file_info(kind: str, path: Path) -> FileInfo:
    """Report date, row count and skipped sheets of one file.

    The first call parses the workbook (and caches it as Parquet, so the dashboard's own read is
    then quick); later calls read the .meta.json sidecar. A file that cannot be read is dated by
    its file date and carries the error.
    """
    stem = _cache_stem(kind, path)
    if stem in _INFO:
        return _INFO[stem]
    info = _read_meta(kind, path)
    if info is None:
        try:
            frame = LOADERS[kind](path)
            info = _read_meta(kind, path) or _write_meta(kind, path, frame, [])
        except Exception as error:  # noqa: BLE001 - list the file anyway; the pages show the error
            info = FileInfo(path, kind, file_date(path), FILE_DATE, error=str(error))
    _INFO[stem] = info
    return info


# ----------------------------------------------------------- weekly summary ----
SUMMARY_VERSION = "1"
SUMMARY_GROUP = ["Device Name", "Applications", "Platform"]
SUMMARY_COLUMNS = {
    VULN: ["Open findings", "Past SLA"] + SEVERITY_ORDER,
    MBSS: ["MBSS failed", "MBSS critical"],
    CS: ["CS servers", "CS gaps", "Servers with a CS gap"],
}


def key_text(values: pd.Series) -> pd.Series:
    """Key values as comparable text: 443, 443.0 and ' 443' match; a blank key is ''."""
    return values.astype("string").str.strip().str.replace(r"\.0$", "", regex=True).fillna("")


def unique_findings(kind: str, frame: pd.DataFrame) -> pd.DataFrame:
    """One row per finding (FINDING_KEY), keys as text. A finding listed twice keeps its newest row.

    A key column the report lacks (an older report without "Port Number") counts as blank.
    """
    key = FINDING_KEY[kind]
    out = frame.assign(**{column: key_text(frame[column]) if column in frame else "" for column in key})
    column = REPORT_DATE_COLUMN.get(kind)
    if column in out.columns:
        out = out.sort_values(column, ascending=False, kind="stable")
    return out.drop_duplicates(key)


def summarise(kind: str, frame: pd.DataFrame, sla_days: dict[str, int] | None = None) -> pd.DataFrame:
    """Per-server counts for one report: the figures the weekly trend adds up.

    One row per (Device Name, Applications, Platform) with SUMMARY_COLUMNS[kind]. Findings are
    counted once per FINDING_KEY. ``sla_days`` (config.yaml) decides "Past SLA" like add_sla.
    """
    columns = SUMMARY_GROUP + SUMMARY_COLUMNS[kind]
    if frame.empty:
        return pd.DataFrame(columns=columns)
    if kind == VULN:
        unique = unique_findings(kind, frame)
        if "SLA Status" not in unique:
            unique = add_sla(unique, sla_days or {}, 0)
        parts = unique[SUMMARY_GROUP].assign(**{"Open findings": 1, "Past SLA": unique["SLA Status"].eq("Breached")})
        for severity in SEVERITY_ORDER:
            parts[severity] = unique["Severity"].eq(severity).fillna(False)
    elif kind == MBSS:
        unique = unique_findings(kind, frame)
        parts = unique[SUMMARY_GROUP].assign(**{"MBSS failed": 1,
                                                "MBSS critical": unique["Criticality"].eq("Critical").fillna(False)})
    else:
        parts = frame[SUMMARY_GROUP].assign(**{"CS servers": 1, "CS gaps": frame["Gaps"], "Servers with a CS gap": frame["Gaps"].gt(0)})
    summary = parts.groupby(SUMMARY_GROUP, dropna=False, as_index=False).sum()
    summary[SUMMARY_COLUMNS[kind]] = summary[SUMMARY_COLUMNS[kind]].astype("int64")
    return summary[columns]


def load_summary(kind: str, path: Path) -> pd.DataFrame:
    """summarise() for one file, stored next to its Parquet cache so the trend reads it in milliseconds."""
    sla_days = settings.load_config().get("sla_days", {}) if kind == VULN else {}
    tag = hashlib.sha1(f"{SUMMARY_VERSION}|{sorted(sla_days.items())}".encode()).hexdigest()[:8]
    target = settings.cache_dir() / f"{_cache_stem(kind, path)}.summary-{tag}.parquet"
    if target.exists():
        return pd.read_parquet(target)
    summary = summarise(kind, LOADERS[kind](path), sla_days)
    _write_atomic(target, lambda temporary: summary.to_parquet(temporary, index=False))
    return summary


# ------------------------------------------------------------ vulnerabilities ----
def _prepare_vulnerabilities(frame: pd.DataFrame) -> pd.DataFrame:
    frame = frame.drop(columns=["Authentication Summary"], errors="ignore")  # large HTML, never used
    frame = frame[frame["Overall Status"].astype("string").str.strip().str.lower() == "open"].copy()
    frame["Ageing in Days"] = pd.to_numeric(frame["Ageing in Days"], errors="coerce").fillna(0).astype(int)
    frame["Severity"] = frame["Severity"].astype("string").str.strip().str.title()
    for column in ("Date First Found", "Date Last Found", "Last Scan Date Time"):
        if column in frame.columns:
            frame[column] = _dates(frame[column])
    return frame


def load_vulnerabilities(path: Path) -> pd.DataFrame:
    return _load(VULN, path, _prepare_vulnerabilities)


def add_sla(frame: pd.DataFrame, sla_days: dict[str, int], due_soon_days: int) -> pd.DataFrame:
    """Add SLA Days, SLA Remaining Days and SLA Status (Breached / Due soon / Within SLA)."""
    frame["SLA Days"] = frame["Severity"].map(sla_days).astype("Int64")
    frame["SLA Remaining Days"] = frame["SLA Days"] - frame["Ageing in Days"]
    breached = frame["SLA Breached?"].astype("string").str.strip().eq("Non-Compliant") | (frame["SLA Remaining Days"] < 0)
    due_soon = ~breached & (frame["SLA Remaining Days"] <= due_soon_days)
    frame["SLA Status"] = "Within SLA"
    frame.loc[due_soon.fillna(False), "SLA Status"] = "Due soon"
    frame.loc[breached.fillna(False), "SLA Status"] = "Breached"
    return frame


# ------------------------------------------------------------------------ MBSS ----
def _prepare_mbss(frame: pd.DataFrame) -> pd.DataFrame:
    frame = frame[frame["Overall Status"].astype("string").str.strip().str.lower() == "failed"].copy()
    frame["Criticality"] = frame["Criticality"].astype("string").str.strip().str.title()
    frame["Qualys Control ID"] = frame["Qualys Control ID"].astype("string")
    for column in ("Evaluation Date", "Posture Modified Date", "Last Compliance Scan Date Time"):
        if column in frame.columns:
            frame[column] = _dates(frame[column])
    if {"Evaluation Date", "Posture Modified Date"} <= set(frame.columns):
        frame["Days Failing"] = (frame["Evaluation Date"] - frame["Posture Modified Date"]).dt.days.clip(lower=0)
    # The report has no OS column; infer the baseline family from the remediation wording per policy.
    text = (frame["Remediation"].astype("string").fillna("") + " " + frame["Control Description"].astype("string").fillna("")).str.lower()
    windows = text.str.contains(r"via gp|group policy|registry|hklm|windows", regex=True)
    share = windows.groupby(frame["Policy ID"] if "Policy ID" in frame.columns else frame["Platform"]).transform("mean")
    frame["OS Family"] = share.gt(0.5).map({True: "Windows", False: "Linux"})
    return frame


def load_mbss(path: Path) -> pd.DataFrame:
    return _load(MBSS, path, _prepare_mbss)


# ----------------------------------------------------------------- CS controls ----
def _cs_state(status: pd.Series, score: pd.Series | None) -> pd.Series:
    text = status.astype("string").fillna("").str.strip().str.lower()
    state = pd.Series("Gap", index=status.index, dtype="string")
    state[text.isin(_CS_IMPLEMENTED)] = "Implemented"
    state[text.isin(_CS_NOT_IN_SCOPE)] = "Not in scope"
    state[text.str.contains("exception")] = "Exception"
    if score is not None:
        # The status wording decides. The score is only used to spot partial coverage (0 < score < 1),
        # so a row that says "Not Implemented" is never shown as covered.
        numeric = pd.to_numeric(score, errors="coerce")
        state[numeric.gt(0) & numeric.lt(1) & state.eq("Gap")] = "Partial"
    return state


def _prepare_cs(frame: pd.DataFrame) -> pd.DataFrame:
    for control, (status_column, score_column) in CS_CONTROLS.items():
        score = frame[score_column] if score_column and score_column in frame.columns else None
        frame[f"{control} State"] = _cs_state(frame[status_column], score)
    state_columns = [f"{control} State" for control in CS_CONTROLS]
    frame["Gaps"] = frame[state_columns].isin(["Gap", "Partial"]).sum(axis=1)
    if "Host Name" in frame.columns:
        frame["Host Name"] = frame["Host Name"].astype("string").replace({"N/A": pd.NA})
    return frame


def load_cs_controls(path: Path) -> pd.DataFrame:
    return _load(CS, path, _prepare_cs)


def cs_long(frame: pd.DataFrame) -> pd.DataFrame:
    """One row per server per control: Control, Status (report wording), State (normalised)."""
    keep = [c for c in ("Device Name", "Host Name", "Applications", "Platform", "Environment") if c in frame.columns]
    parts = []
    for control, (status_column, _) in CS_CONTROLS.items():
        part = frame[keep].copy()
        part["Control"] = control
        part["Status"] = frame[status_column].astype("string").fillna("(blank)")
        part["State"] = frame[f"{control} State"]
        parts.append(part)
    return pd.concat(parts, ignore_index=True)


LOADERS = {VULN: load_vulnerabilities, MBSS: load_mbss, CS: load_cs_controls}
