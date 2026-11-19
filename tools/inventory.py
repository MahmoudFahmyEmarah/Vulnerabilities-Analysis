"""Read the AI Platforms Inventory workbook: the reference list of AI platform servers.

The workbook is hand-maintained and every sheet is laid out differently (some hold several
tables). The reader therefore does not expect fixed positions: on every sheet it looks for
header rows that contain an IP column, then takes each following row that has an IP address.

Only these facts are read: IP, hostname, platform, role, cluster, project, environment, status.
Everything else in the workbook (licence keys, iLO addresses, credentials) is ignored and never
stored or shown.
"""
from __future__ import annotations

import re
from pathlib import Path

import pandas as pd

from tools.environment import DEV, PROD

COLUMNS = ["IP", "Hostname", "AI Platform", "Server Role", "Cluster", "Project", "Environment", "Status", "Sheet"]

_IP = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")

# field -> header texts that mean it, best match first (compared lower-case, trimmed)
_HEADERS = {
    "ip": ["app/data ip", "ip address", "ip's", "ip", "gpuip"],
    "hostname": ["hostname/servername", "hostname (os)", "hostname", "dns name", "dns", "vm name"],
    "role": ["server role", "role", "purpose", "app", "product name"],
    "application": ["application"],
    "environment": ["environment"],
    "cluster": ["bd cluster name", "cluster"],
    "project": ["project"],
    "status": ["status"],
    "hint": ["for"],
}
_IP_HEADERS = set(_HEADERS["ip"])


def _clean(cell: object) -> str:
    text = "" if cell is None else str(cell).replace("\xa0", " ").strip()
    return "" if text.upper() in ("N/A", "NA", "-") else text


def _environment(*texts: str) -> str | None:
    """First text that names an environment decides (column value, sheet name, hint, host name)."""
    for text in texts:
        lowered = text.lower()
        if re.search(r"non[\s_\-]?prod|pre[\s_\-]?prod|dev|test|uat|\bsit\b", lowered):
            return DEV
        if "prod" in lowered:
            return PROD
    return None


def _platform(sheet: str) -> str:
    """Sheet name without the environment word: 'SAS Viya - Prod' -> 'SAS Viya', 'Dev-Advance' -> 'Advance'."""
    name = re.sub(r"(?i)(?<![a-z])(dev|prod)(?![a-z])", "", sheet)
    return re.sub(r"\s+", " ", name).strip(" -_") or sheet.strip()


def _header_map(cells: list[str]) -> dict[str, int] | None:
    lowered = [cell.lower() for cell in cells]
    if not any(cell in _IP_HEADERS for cell in lowered):
        return None
    mapping: dict[str, int] = {}
    for field, names in _HEADERS.items():
        for name in names:
            if name in lowered:
                mapping[field] = lowered.index(name)
                break
    return mapping


def load_inventory(path: Path | None, names: dict[str, str] | None = None) -> pd.DataFrame:
    """Return one row per server in the inventory (columns: see COLUMNS). Empty frame if the file is missing.

    ``names`` renames platforms (sheet name without the environment word -> name used in the app).
    """
    names = names or {}
    if not path or not Path(path).exists():
        return pd.DataFrame(columns=COLUMNS)
    import openpyxl

    workbook = openpyxl.load_workbook(path, read_only=True, data_only=True)
    rows: list[dict[str, str | None]] = []
    for sheet in workbook.worksheets:
        header: dict[str, int] = {}
        platform = _platform(sheet.title)
        for raw in sheet.iter_rows(values_only=True):
            cells = [_clean(cell) for cell in raw]
            if not any(cells):
                continue
            found = _header_map(cells)
            if found is not None:
                header = found
                continue

            def field(name: str) -> str:
                index = header.get(name)
                return cells[index] if index is not None and index < len(cells) else ""

            ip = field("ip") if _IP.match(field("ip")) else next((cell for cell in cells if _IP.match(cell)), "")
            if not ip:
                continue
            hostname = re.sub(r"^https?://", "", field("hostname")).strip("/")
            rows.append({
                "IP": ip,
                "Hostname": hostname or None,
                "AI Platform": names.get(field("application") or platform, field("application") or platform),
                "Server Role": field("role") or None,
                "Cluster": field("cluster") or None,
                "Project": field("project") or None,
                "Environment": _environment(field("environment"), sheet.title, field("hint"), hostname),
                "Status": field("status") or None,
                "Sheet": sheet.title,
            })
    workbook.close()
    frame = pd.DataFrame(rows, columns=COLUMNS)
    if frame.empty:
        return frame
    # A server can be listed twice with two roles (JupyterHub and CAS Worker on one host): keep both roles.
    roles = frame.dropna(subset=["Server Role"]).groupby("IP")["Server Role"].agg(lambda s: ", ".join(dict.fromkeys(s)))
    frame = frame.drop_duplicates("IP").reset_index(drop=True)
    frame["Server Role"] = frame["IP"].map(roles)
    return frame
