"""Week-over-week comparison of the security reports. Pure pandas: no Streamlit, no file access.

The reports list only what is open (vulnerabilities) or failing (MBSS) on the day they were
pulled, so "fixed" can only be found by comparing two weeks. A finding is classified as:

* New            in the current week only. "Change detail" says Re-opened (the report's own
                 Qualys Status), Server new this week, or New finding.
* Still open     in both weeks.
* Fixed          in the previous week only, and the server is still in this week's reports.
* Not rescanned  in the previous week only, but the server is missing from this week's reports
                 (not scanned, decommissioned or moved out of scope). Never counted as fixed.

Pass ``current_servers``: every server in this week's reports. The CS report lists every server,
so its Device Name column is the natural source. Without it, a server whose last finding was
fixed would look like a server that dropped out of the reports.

Entry point for other modules (the Trends page, an Excel export):

    application_deltas(current, previous, current_servers)   -> one row per application

Lower-level pieces: vulnerability_changes / mbss_changes / cs_changes (one row per finding with a
"Change" column), count_changes (group those by any columns), weekly_trend (sum the per-server
summaries from tools.data_loader.summarise per week).
"""
from __future__ import annotations

from collections.abc import Iterable, Sequence

import pandas as pd

from tools import data_loader as dl

# ---- vulnerabilities
NEW, STILL_OPEN, FIXED, NOT_RESCANNED = "New", "Still open", "Fixed", "Not rescanned"
VULN_CHANGES = [NEW, STILL_OPEN, FIXED, NOT_RESCANNED]
# ---- MBSS (failed baseline checks)
NEWLY_FAILING, STILL_FAILING, NOW_PASSING = "Newly failing", "Still failing", "Now passing"
MBSS_CHANGES = [NEWLY_FAILING, STILL_FAILING, NOW_PASSING, NOT_RESCANNED]
# ---- CS controls (one row per server and control that is a gap in either week)
NEW_GAP, STILL_GAP, GAP_CLOSED = "New gap", "Still a gap", "Gap closed"
CS_CHANGES = [NEW_GAP, STILL_GAP, GAP_CLOSED, NOT_RESCANNED]
CS_GAP_STATES = ["Gap", "Partial"]

REOPENED, NEW_SERVER, NEW_FINDING, SERVER_MISSING = (
    "Re-opened", "Server new this week", "New finding", "Server not in this week's reports")

DEFAULT_GROUP = ("Applications",)


def _server_set(frame: pd.DataFrame, extra: Iterable[str] | None) -> set[str]:
    servers = set(frame["Device Name"].dropna().astype(str).str.strip()) if "Device Name" in frame else set()
    return servers | {str(server).strip() for server in extra or ()}


def _past_sla(frame: pd.DataFrame) -> pd.Series:
    """True for findings past their SLA. Uses "SLA Status" (dl.add_sla) when present, else the report's flag."""
    if "SLA Status" in frame:
        return frame["SLA Status"].eq("Breached").fillna(False).astype(bool)
    if "SLA Breached?" in frame:
        return frame["SLA Breached?"].astype("string").str.strip().eq("Non-Compliant").fillna(False).astype(bool)
    return pd.Series(False, index=frame.index)


def _compare(kind: str, current: pd.DataFrame, previous: pd.DataFrame, labels: list[str],
             current_servers: Iterable[str] | None, previous_servers: Iterable[str] | None) -> pd.DataFrame:
    """Shared logic for vulnerabilities and MBSS. labels = [new, still, gone, not rescanned]."""
    new, still, gone, not_rescanned = labels
    key = dl.FINDING_KEY[kind]
    now = dl.unique_findings(kind, current) if not current.empty else pd.DataFrame(columns=key)
    before = dl.unique_findings(kind, previous) if not previous.empty else pd.DataFrame(columns=key)
    servers_now = _server_set(current, current_servers)
    servers_before = _server_set(previous, previous_servers)

    now_keys = pd.MultiIndex.from_frame(now[key])
    before_keys = pd.MultiIndex.from_frame(before[key])
    in_before = now_keys.isin(before_keys)
    sla_before = pd.Series(_past_sla(before).to_numpy(), index=before_keys)
    sla_before = sla_before[~sla_before.index.duplicated()]

    current_rows = now.assign(**{
        "Change": pd.Series(in_before, index=now.index).map({True: still, False: new}),
        "Change detail": "",
        "In current": True,
        "In previous": in_before,
        "Past SLA now": _past_sla(now),
        "Past SLA before": sla_before.reindex(now_keys).fillna(False).astype(bool).to_numpy(),
    })
    fresh = ~in_before
    if "Qualys Status" in current_rows:
        reopened = current_rows["Qualys Status"].astype("string").str.strip().str.lower().eq("re-opened").fillna(False)
    else:
        reopened = pd.Series(False, index=current_rows.index)
    new_server = ~current_rows["Device Name"].isin(servers_before)
    current_rows.loc[fresh, "Change detail"] = NEW_FINDING
    current_rows.loc[fresh & new_server, "Change detail"] = NEW_SERVER
    current_rows.loc[fresh & reopened, "Change detail"] = REOPENED

    gone_rows = before[~before_keys.isin(now_keys)]
    server_seen = gone_rows["Device Name"].isin(servers_now)
    gone_rows = gone_rows.assign(**{
        "Change": server_seen.map({True: gone, False: not_rescanned}),
        "Change detail": server_seen.map({True: "", False: SERVER_MISSING}),
        "In current": False,
        "In previous": True,
        "Past SLA now": False,
        "Past SLA before": _past_sla(gone_rows),
    })
    changes = pd.concat([frame for frame in (current_rows, gone_rows) if not frame.empty] or [current_rows],
                        ignore_index=True)
    changes["Change"] = pd.Categorical(changes["Change"], categories=labels)
    first = key + ["Change", "Change detail"]
    return changes[first + [column for column in changes.columns if column not in first]]


def vulnerability_changes(current: pd.DataFrame, previous: pd.DataFrame,
                          current_servers: Iterable[str] | None = None,
                          previous_servers: Iterable[str] | None = None) -> pd.DataFrame:
    """One row per vulnerability in either week, keyed by (Device Name, Qualys ID, Port Number).

    ``current`` / ``previous``: vulnerability frames as loaded by tools.data_loader (ideally with
    "SLA Status" from add_sla). ``current_servers``: every server in this week's reports (decides
    Fixed vs Not rescanned). ``previous_servers``: every server in last week's reports (spots
    servers new this week). Descriptive columns come from the current week, else the previous one.
    Adds: Change, Change detail, In current, In previous, Past SLA now, Past SLA before.
    """
    return _compare(dl.VULN, current, previous, VULN_CHANGES, current_servers, previous_servers)


def mbss_changes(current: pd.DataFrame, previous: pd.DataFrame,
                 current_servers: Iterable[str] | None = None,
                 previous_servers: Iterable[str] | None = None) -> pd.DataFrame:
    """One row per failed MBSS check in either week, keyed by (Device Name, Qualys Control ID).

    Change is Newly failing, Still failing, Now passing or Not rescanned (same rules as
    vulnerability_changes).
    """
    return _compare(dl.MBSS, current, previous, MBSS_CHANGES, current_servers, previous_servers)


def cs_changes(current: pd.DataFrame, previous: pd.DataFrame) -> pd.DataFrame:
    """One row per server and CS control that is a gap (Gap or Partial) in either week.

    Uses the "<Control> State" columns from tools.data_loader. Change is New gap, Still a gap,
    Gap closed, or Not rescanned (the server is missing from this week's CS report). The CS report
    lists every server, so it needs no separate server list.
    """
    key = ["Device Name", "Control"]
    now = dl.cs_long(current) if not current.empty else pd.DataFrame(columns=key + ["State", "Status"])
    before = dl.cs_long(previous) if not previous.empty else pd.DataFrame(columns=key + ["State", "Status"])
    before = before.rename(columns={"State": "State before", "Status": "Status before"})
    merged = now.merge(before, on=key, how="outer", suffixes=("", " (previous)"), indicator=True)
    for column in [c for c in merged.columns if c.endswith(" (previous)")]:
        base = column.removesuffix(" (previous)")
        merged[base] = merged[base].fillna(merged[column]) if base in merged else merged[column]
        merged = merged.drop(columns=column)
    gap_now = merged["State"].isin(CS_GAP_STATES)
    gap_before = merged["State before"].isin(CS_GAP_STATES)
    in_now, in_before = merged["_merge"].ne("right_only"), merged["_merge"].ne("left_only")
    servers_before = set(before["Device Name"])

    change = pd.Series(pd.NA, index=merged.index, dtype="object")
    change[gap_now & gap_before] = STILL_GAP
    change[gap_now & ~gap_before] = NEW_GAP
    change[~gap_now & gap_before & in_now] = GAP_CLOSED
    change[gap_before & ~in_now] = NOT_RESCANNED
    detail = pd.Series("", index=merged.index, dtype="object")
    detail[gap_now & ~merged["Device Name"].isin(servers_before)] = NEW_SERVER
    detail[gap_before & ~in_now] = "Server not in this week's CS report"

    out = merged.assign(**{"Change": change, "Change detail": detail, "In current": gap_now,
                           "In previous": gap_before & in_before}).drop(columns="_merge")
    out = out[out["Change"].notna()].reset_index(drop=True)
    out["Change"] = pd.Categorical(out["Change"], categories=CS_CHANGES)
    first = key + ["Change", "Change detail", "State before", "State"]
    return out[first + [column for column in out.columns if column not in first]]


def count_changes(changes: pd.DataFrame, by: str | Sequence[str] = DEFAULT_GROUP) -> pd.DataFrame:
    """Count a *_changes() frame per group.

    One column per Change label (in the frame's own order), then "Current total" (open / failing /
    gaps this week), "Previous total", "Net change", and for vulnerabilities "Re-opened",
    "Past SLA now", "Past SLA before" and "Past SLA change". ``by`` can be one column or several,
    for example ("Applications", "Severity"); an empty ``by`` gives a single total row.
    """
    by = [by] if isinstance(by, str) else list(by)
    labels = list(changes["Change"].cat.categories) if isinstance(changes["Change"].dtype, pd.CategoricalDtype) \
        else list(pd.unique(changes["Change"].dropna()))
    frame = changes.assign(_all="All") if not by else changes
    group = by or ["_all"]
    frame = frame.assign(**{label: frame["Change"].eq(label) for label in labels})
    sums = {label: (label, "sum") for label in labels}
    sums |= {"Current total": ("In current", "sum"), "Previous total": ("In previous", "sum")}
    if "Change detail" in frame and frame["Change detail"].eq(REOPENED).any():
        frame = frame.assign(_reopened=frame["Change detail"].eq(REOPENED))
        sums["Re-opened"] = ("_reopened", "sum")
    if "Past SLA now" in frame:
        sums |= {"Past SLA now": ("Past SLA now", "sum"), "Past SLA before": ("Past SLA before", "sum")}
    if frame.empty:
        columns = by + list(sums) + ["Net change"] + (["Past SLA change"] if "Past SLA now" in frame else [])
        return pd.DataFrame(columns=columns)
    table = frame.groupby(group, dropna=False, observed=True).agg(**sums).astype("int64")
    table.insert(len(labels) + 2, "Net change", table["Current total"] - table["Previous total"])
    if "Past SLA now" in table:
        table["Past SLA change"] = table["Past SLA now"] - table["Past SLA before"]
    table = table.reset_index()
    return table.drop(columns="_all") if not by else table.sort_values("Current total", ascending=False,
                                                                        ignore_index=True)


def application_deltas(current: pd.DataFrame, previous: pd.DataFrame,
                       current_servers: Iterable[str] | None = None,
                       by: str | Sequence[str] = DEFAULT_GROUP) -> pd.DataFrame:
    """Per-application vulnerability deltas between two weekly reports.

    ``current`` / ``previous``: the two vulnerability frames (tools.data_loader.load_vulnerabilities,
    optionally enriched). ``current_servers``: every server in this week's reports (for example the
    CS report's Device Name column); see the module docstring for why it matters.
    Returns one row per ``by`` group with New, Still open, Fixed, Not rescanned, Current total,
    Previous total, Net change, Re-opened (when any), Past SLA now / before / change.
    """
    return count_changes(vulnerability_changes(current, previous, current_servers), by)


# ---------------------------------------------------------------------- trend ----
GROUP_DAYS = 3   # report files dated within this many days of a set's newest file belong to that set


def group_reports(files: Iterable, days: int = GROUP_DAYS) -> list[tuple[pd.Timestamp, dict]]:
    """Group report files into weekly sets, newest first: [(date of the set's newest file, {kind: file})].

    ``files`` are tools.data_loader.FileInfo (anything with ``kind`` and ``report_date``). A set holds at
    most one file of each kind, all dated within ``days`` of its newest file; a second file of the same
    kind starts the next (older) set. Sets follow the reports' own dates rather than calendar weeks, so
    two weekly reports are never merged just because their dates fall either side of a week boundary
    (for example scans ending Sunday one week and Saturday the next).
    """
    sets: list[tuple[pd.Timestamp, dict]] = []
    for info in sorted(files, key=lambda item: item.report_date, reverse=True):
        date = pd.Timestamp(info.report_date)
        if not sets or info.kind in sets[-1][1] or sets[-1][0] - date > pd.Timedelta(days=days):
            sets.append((date, {}))
        sets[-1][1][info.kind] = info
    return sets


def week_start(value) -> pd.Timestamp:
    """The Sunday that starts the (Saudi, Sunday-Thursday) working week containing ``value``."""
    day = pd.Timestamp(value).normalize()
    return day - pd.Timedelta(days=(day.weekday() + 1) % 7)


def weekly_trend(weeks: Iterable[tuple[str, pd.Timestamp, pd.DataFrame]],
                 by: str | Sequence[str] = ()) -> pd.DataFrame:
    """Add up per-server summaries per week.

    ``weeks``: (kind, week, summary) triples, one per report file and at most one per kind and
    week, where summary is tools.data_loader.summarise output (already filtered to the scope you
    want). Returns one row per week (and per ``by`` group) with the SUMMARY_COLUMNS of every kind.
    A group missing from a week's report counts 0; a week with no file of a kind is blank (<NA>)
    for that kind's columns.
    """
    by = [by] if isinstance(by, str) else list(by)
    keys = ["Week"] + by
    present: dict[str, set[pd.Timestamp]] = {}
    totals: dict[str, list[pd.DataFrame]] = {}
    groups: list[pd.DataFrame] = []
    for kind, week, summary in weeks:
        week, metrics = pd.Timestamp(week), dl.SUMMARY_COLUMNS[kind]
        present.setdefault(kind, set()).add(week)
        if by:
            total = summary.groupby(by, dropna=False)[metrics].sum().reset_index()
            groups.append(summary[by])
        else:
            total = pd.DataFrame([summary[metrics].sum()])
        totals.setdefault(kind, []).append(total.assign(Week=week))
    if not present:
        return pd.DataFrame(columns=keys)
    result = pd.DataFrame({"Week": sorted(set().union(*present.values()))})
    if by:
        result = result.merge(pd.concat(groups, ignore_index=True).drop_duplicates(), how="cross")
    for kind, parts in totals.items():
        metrics = dl.SUMMARY_COLUMNS[kind]
        result = result.merge(pd.concat(parts, ignore_index=True)[keys + metrics], on=keys, how="left")
        has_file = result["Week"].isin(present[kind])
        result.loc[has_file, metrics] = result.loc[has_file, metrics].fillna(0)
        result[metrics] = result[metrics].astype("Int64")
    return result.sort_values(keys, ignore_index=True)
