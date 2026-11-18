"""Find, validate, normalise and cache the three security reports.

* Vulnerability report  -> one row per open finding per server
* MBSS report           -> one row per failed baseline control per server
* CS Controls report    -> one row per server with the state of each security control

Excel parsing is slow, so every file is parsed once and stored as Parquet under
.cache/, keyed by path, size and modification time. A changed file is re-parsed.
"""
from __future__ import annotations

import hashlib
import re
from pathlib import Path

import pandas as pd

import settings

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


def discover_files(folder: Path) -> dict[str, list[Path]]:
    """Report files in ``folder`` grouped by kind, newest first."""
    found: dict[str, list[Path]] = {VULN: [], MBSS: [], CS: []}
    if not folder.exists():
        return found
    for path in folder.glob("*.xls*"):
        if path.name.startswith("~$"):
            continue
        kind = sniff_kind(path)
        if kind:
            found[kind].append(path)
    for paths in found.values():
        paths.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return found


# ------------------------------------------------------------------ reading ----
def _cache_file(kind: str, path: Path) -> Path:
    stat = path.stat()
    key = f"{path.resolve()}|{stat.st_size}|{stat.st_mtime_ns}|{LOADER_VERSION}"
    return settings.cache_dir() / f"{kind}-{hashlib.sha1(key.encode()).hexdigest()[:16]}.parquet"


def _read_sheets(path: Path) -> dict[str, pd.DataFrame]:
    try:
        return pd.read_excel(path, sheet_name=None, engine="calamine")
    except ImportError:
        return pd.read_excel(path, sheet_name=None)


def _clean_platform(values: pd.Series) -> pd.Series:
    return values.astype("string").str.strip().str.rstrip(":").str.strip()


def _combine(path: Path, kind: str) -> pd.DataFrame:
    """Read every sheet, apply aliases, check required columns, add Platform."""
    frames = []
    for sheet, frame in _read_sheets(path).items():
        if frame.empty:
            continue
        frame = frame.loc[:, [c for c in frame.columns if not str(c).startswith("Unnamed")]]
        frame = frame.rename(columns={old: new for old, new in ALIASES.items()
                                      if old in frame.columns and new not in frame.columns})
        missing = [column for column in REQUIRED[kind] if column not in frame.columns]
        if missing:
            raise SchemaError(
                f"{path.name} (sheet '{sheet}') is missing columns: {', '.join(missing)}. "
                f"Found: {', '.join(map(str, frame.columns[:12]))} ..."
            )
        department = frame["Department Name"] if "Department Name" in frame.columns else pd.Series(sheet, index=frame.index)
        frame["Platform"] = _clean_platform(department).fillna(sheet)
        frames.append(frame)
    if not frames:
        raise SchemaError(f"{path.name} has no data rows.")
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
    frame = _to_parquet_safe(prepare(_combine(path, kind)))
    frame.to_parquet(cache, index=False)
    return frame


def _dates(values: pd.Series) -> pd.Series:
    return pd.to_datetime(values, errors="coerce", format="mixed")


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
