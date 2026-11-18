"""CS Controls: is each server covered by antivirus, EDR, SIEM, vulnerability scanning, the Qualys agent and PAM?"""
from __future__ import annotations

import pandas as pd
import streamlit as st

from tools import data_loader as dl
from ui import charts, components, state, theme
from workflows import recommend

GAP_STATES = ["Gap", "Partial"]


def _coverage(long: pd.DataFrame, by: list[str]) -> pd.DataFrame:
    """Coverage per group: implemented / servers in scope (exceptions and not-in-scope are left out)."""
    in_scope = long[long["State"].isin(["Implemented", "Partial", "Gap"])]
    grouped = in_scope.groupby(by).agg(in_scope=("State", "size"),
                                       implemented=("State", lambda s: int((s == "Implemented").sum())),
                                       gaps=("State", lambda s: int(s.isin(GAP_STATES).sum()))).reset_index()
    grouped["coverage"] = grouped["implemented"] / grouped["in_scope"]
    return grouped


def _control_detail(cs: pd.DataFrame, long: pd.DataFrame, vulns: pd.DataFrame) -> None:
    gaps = long[long["State"].isin(GAP_STATES)]
    if gaps.empty:
        st.success("No control gaps in this scope.")
        return
    with st.container(border=True):
        theme.title("Close a gap", "Pick a control to see the servers behind it and ask for an onboarding runbook.")
        counts = gaps["Control"].value_counts()
        control = st.selectbox("Control", list(counts.index), key="c_control",
                               format_func=lambda name: f"{name} — {counts[name]:,} servers with a gap")
        rows = gaps[gaps["Control"] == control]
        breakdown = rows["Status"].value_counts()
        theme.badges([(f"{status}: {count:,}", "red") for status, count in breakdown.items()])
        columns = [c for c in ("Device Name", "Host Name", "Applications", "Platform", "Environment", "Status") if c in rows]
        components.capped_table(rows[columns].sort_values(["Applications", "Device Name"]), "c_gap_rows",
                                f"cs_gap_{control.lower().replace(' ', '_')}.csv", height=300)

    os_mix = ""
    if not vulns.empty:
        affected = vulns[vulns["Device Name"].isin(rows["Device Name"])].drop_duplicates("Device Name")
        os_mix = ", ".join(f"{name}: {count}" for name, count in affected["OS Family"].value_counts().items())
    applications = sorted(rows["Applications"].unique())
    finding = {
        "Control": control,
        "Applications": ", ".join(applications[:10]) + (f" and {len(applications) - 10} more" if len(applications) > 10 else ""),
        "Status Breakdown": ", ".join(f"{status}: {count}" for status, count in breakdown.items()),
        "Operating Systems": os_mix or "not known from the vulnerability report",
        "Servers Affected": str(rows["Device Name"].nunique()),
    }
    components.recommendation_panel(recommend.CS_CONTROL, finding, key=control)


def render() -> None:
    data = state.load()
    vulns, _, cs, _ = state.filtered(data)
    theme.hero(
        "CS Controls · cybersecurity control coverage",
        "Security control coverage",
        "Whether each server has the mandatory cybersecurity controls: antivirus, EDR, SIEM log forwarding, "
        "authenticated vulnerability scanning, the Qualys agent and privileged access management. Coverage counts "
        "servers where the control applies; exceptions and out-of-scope servers are shown separately.",
        [("Report:", data.files["cs_controls"].name if data.files["cs_controls"] else "not loaded"),
         ("Scope:", state.scope_label())],
    )
    if "cs_controls" in data.errors:
        st.error(data.errors["cs_controls"])
        return
    if cs.empty:
        st.info("No CS Controls data in this scope. Check the sidebar filters or add the report on the Settings page.")
        return

    long = dl.cs_long(cs)
    per_control = _coverage(long, ["Control"]).set_index("Control").reindex(list(dl.CS_CONTROLS)).dropna(subset=["in_scope"])
    clean = int((cs["Gaps"] == 0).sum())
    cards = [{"label": "Servers with no gap", "value": theme.percent(clean, len(cs)), "tone": "primary",
              "sub": f"{clean:,} of {len(cs):,} servers", "progress": clean / len(cs)}]
    for control, row in per_control.iterrows():
        cards.append({"label": control, "value": f"{row['coverage']:.0%}",
                      "sub": f"{int(row['gaps']):,} gaps · {int(row['in_scope']):,} in scope",
                      "progress": row["coverage"], "tone": "alert" if row["coverage"] < 0.8 else ""})
    theme.kpis(cards)

    # Stacked, not side by side: both charts have long labels and need the full width on a laptop screen.
    with st.container(border=True):
        theme.title("Status of each control", "Share of servers")
        counts = long.groupby(["Control", "State"]).size().reset_index(name="Servers")
        charts.show(charts.stacked_bars(counts, "Control", "Servers", "State", list(dl.CS_CONTROLS), charts.CS_ORDER,
                                        charts.CS_COLORS, "Share of servers", normalize=True))
    with st.container(border=True):
        theme.title("Coverage by application", "The 12 applications with most gaps. Blank = control not in scope.")
        by_app = _coverage(long, ["Applications", "Control"])
        worst = by_app.groupby("Applications")["gaps"].sum().nlargest(12)
        worst = worst[worst > 0]
        if worst.empty:
            st.caption("No gaps in this scope.")
        else:
            charts.show(charts.heatmap(by_app[by_app["Applications"].isin(worst.index)], "Control", "Applications",
                                       "coverage", list(dl.CS_CONTROLS), list(worst.index), "Coverage"))

    with st.container(border=True):
        theme.title("Servers", "One row per server with the state of every control")
        only_gaps = st.toggle("Only servers with a gap", value=True, key="c_only_gaps")
        state_columns = [f"{control} State" for control in dl.CS_CONTROLS]
        columns = [c for c in ("Device Name", "Host Name", "Applications", "Server Role", "Platform", "Environment")
                   if c in cs]
        table = cs[columns + state_columns + ["Gaps"]].rename(columns={c: c.removesuffix(" State") for c in state_columns})
        if only_gaps:
            table = table[table["Gaps"] > 0]
        components.capped_table(table.sort_values("Gaps", ascending=False), "c_servers", "cs_controls_by_server.csv",
                                height=380)

    _control_detail(cs, long, vulns)
