"""Altair charts in the dashboard style.

Colour rules (validated for colour-blind safety on a white surface):
* one measure            -> one purple for every bar
* severity / criticality -> a single-hue purple ramp, darker = more severe
* status                 -> purple = fine, red = breached / gap, amber = due soon / exception, gray = not in scope
* environment            -> purple = production, orange = development
* owner                  -> purple = OS team, teal = application team
Every chart has hover tooltips, and the same numbers are available in a table on the page. Donuts are
kept to whole-at-a-glance splits of at most six parts, and their legend carries each part's count and
share, so no part is identified by colour alone.
"""
from __future__ import annotations

import altair as alt
import pandas as pd
import streamlit as st

PURPLE = "#6A3FC4"
PURPLE_LIGHT = "#B9A5EA"
RED = "#D03B3B"
ORANGE = "#EB6834"
AMBER = "#C98500"   # "due soon" / "exception": validated against the red beside it
GRAY = "#C9C4D4"
INK = "#1D1033"
MUTED = "#6F6781"
GRID = "#EEE9F5"

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Minimal"]
SEVERITY_COLORS = ["#3A1780", "#5F33B8", "#7F59D3", "#9C7FE0", "#B9A5EA"]
SLA_ORDER = ["Breached", "Due soon", "Within SLA"]
SLA_COLORS = [RED, AMBER, PURPLE]
CS_ORDER = ["Implemented", "Partial", "Gap", "Exception", "Not in scope"]
CS_COLORS = [PURPLE, PURPLE_LIGHT, RED, AMBER, GRAY]
ENV_ORDER = ["Production", "Development"]
ENV_COLORS = [PURPLE, ORANGE]
TEAL = "#16996B"   # beside PURPLE: checked for colour-blind separation and 3:1 contrast on white
OWNER_ORDER = ["OS Issue", "Application Issue"]   # tools/classifier.OS / APP
OWNER_LABELS = {"OS Issue": "OS team", "Application Issue": "Application team"}
OWNER_COLORS = [PURPLE, TEAL]

_FONT = 'system-ui, -apple-system, "Segoe UI", sans-serif'


def _style(chart: alt.Chart | alt.LayerChart) -> alt.Chart:
    return (
        chart.configure(font=_FONT, background="transparent")
        .configure_view(stroke=None)
        .configure_axis(labelColor=MUTED, titleColor=MUTED, labelFontSize=12, titleFontSize=12, gridColor=GRID,
                        domainColor="#D8D0E6", tickColor="#D8D0E6", titleFontWeight="normal", labelLimit=190)
        .configure_legend(labelColor=INK, titleColor=MUTED, labelFontSize=12, titleFontSize=12, orient="top",
                          symbolType="square", title=None)
    )


def show(chart: alt.Chart) -> None:
    st.altair_chart(_style(chart), theme=None, width="stretch")


def _height(rows: int, step: int = 28, legend: bool = False) -> int:
    """Total chart height. Streamlit fits axes and legend inside it, so they are added to the rows."""
    return rows * step + 56 + (34 if legend else 0)


def _room(data: pd.DataFrame, value: str, headroom: float = 0.15) -> alt.Scale:
    """X scale with head-room (15% by default) so the value label after the longest bar is not clipped.

    A chart in a narrow column needs more: the label keeps its width in pixels while the plot shrinks.
    """
    top = float(data[value].max()) if len(data) else 1.0
    return alt.Scale(domain=[0, max(top, 1.0) * (1 + headroom)], nice=False)


def ranked_bars(data: pd.DataFrame, category: str, value: str, value_title: str, color: str = PURPLE,
                tooltip: list[str] | None = None, order: list[str] | None = None, headroom: float = 0.15) -> alt.Chart:
    """Horizontal bars, one colour, value written at the end of each bar.

    Sorted by value unless ``order`` gives a fixed category order (age buckets, for example).
    """
    if order is None:
        data = data.sort_values(value, ascending=False)
    base = alt.Chart(data).encode(
        y=alt.Y(f"{category}:N", sort=order or list(data[category]), title=None),
        x=alt.X(f"{value}:Q", title=value_title, axis=alt.Axis(tickMinStep=1, format="~s"), scale=_room(data, value, headroom)),
        tooltip=[alt.Tooltip(f"{category}:N"), alt.Tooltip(f"{value}:Q", title=value_title, format=",")]
        + [alt.Tooltip(f"{name}:Q", format=",") for name in tooltip or []],
    )
    bars = base.mark_bar(color=color, cornerRadiusEnd=4, size=16)
    labels = base.mark_text(align="left", dx=5, color=INK, fontSize=12).encode(text=alt.Text(f"{value}:Q", format=","))
    return (bars + labels).properties(height=_height(len(data)))


def ordinal_bars(data: pd.DataFrame, category: str, value: str, order: list[str], colors: list[str],
                 value_title: str, headroom: float = 0.15) -> alt.Chart:
    """Horizontal bars for an ordered scale (severity): fixed order, darker = more severe."""
    present = [name for name in order if name in set(data[category])]
    base = alt.Chart(data).encode(
        y=alt.Y(f"{category}:N", sort=present, title=None),
        x=alt.X(f"{value}:Q", title=value_title, axis=alt.Axis(format="~s"), scale=_room(data, value, headroom)),
        tooltip=[alt.Tooltip(f"{category}:N"), alt.Tooltip(f"{value}:Q", title=value_title, format=",")],
    )
    bars = base.mark_bar(cornerRadiusEnd=4, size=18).encode(
        color=alt.Color(f"{category}:N", legend=None,
                        scale=alt.Scale(domain=present, range=[colors[order.index(name)] for name in present])))
    labels = base.mark_text(align="left", dx=5, color=INK, fontSize=12).encode(text=alt.Text(f"{value}:Q", format=","))
    return (bars + labels).properties(height=_height(len(present), 34))


def stacked_bars(data: pd.DataFrame, category: str, value: str, series: str, category_order: list[str],
                 series_order: list[str], colors: list[str], value_title: str, normalize: bool = False,
                 headroom: float = 0.15) -> alt.Chart:
    """Horizontal stacked bars with a legend; white gaps separate the segments."""
    present = [name for name in series_order if name in set(data[series])]
    palette = [colors[series_order.index(name)] for name in present]
    order = {name: index for index, name in enumerate(series_order)}
    data = data.assign(_order=data[series].map(order))
    totals = data.groupby(category, as_index=False)[value].sum()
    x = alt.X(f"{value}:Q", title=value_title, stack="normalize" if normalize else "zero",
              axis=alt.Axis(format="%" if normalize else "~s"),
              scale=alt.Scale(domain=[0, 1]) if normalize else _room(totals, value, headroom))
    chart = alt.Chart(data).mark_bar(size=18, stroke="white", strokeWidth=2).encode(
        y=alt.Y(f"{category}:N", sort=category_order, title=None),
        x=x,
        color=alt.Color(f"{series}:N", scale=alt.Scale(domain=present, range=palette),
                        legend=alt.Legend(columns=3 if len(present) > 3 else 0)),
        order=alt.Order("_order:Q"),
        tooltip=[alt.Tooltip(f"{category}:N"), alt.Tooltip(f"{series}:N"),
                 alt.Tooltip(f"{value}:Q", title=value_title, format=",")],
    )
    if not normalize:
        chart = chart + alt.Chart(totals).mark_text(align="left", dx=5, color=INK, fontSize=12).encode(
            y=alt.Y(f"{category}:N", sort=category_order, title=None), x=alt.X(f"{value}:Q"),
            text=alt.Text(f"{value}:Q", format=","))
    return chart.properties(height=_height(data[category].nunique(), 34, legend=True) + (22 if len(present) > 3 else 0))


def donut(data: pd.DataFrame, category: str, value: str, order: list[str], colors: list[str], centre: str,
          value_title: str, labels: dict[str, str] | None = None) -> alt.Chart:
    """Part-to-whole at a glance: a ring with the total in the centre and a legend of count and share.

    ``order`` fixes both the order around the ring (clockwise from the top) and the colour of each
    part, so a filter that removes a part never repaints the others. ``labels`` renames parts for
    display (for example "OS Issue" -> "OS team"). Parts with no value are left out.
    """
    counts = data.groupby(category, as_index=False)[value].sum()
    counts = counts[counts[value] > 0]
    present = [name for name in order if name in set(counts[category])]
    counts = counts.set_index(category).reindex(present).reset_index()
    total = int(counts[value].sum())
    counts["_share"] = counts[value] / total if total else 0.0
    counts["_order"] = range(len(counts))
    names = [(labels or {}).get(name, name) for name in present]
    counts["_part"] = names
    counts["_legend"] = [f"{name}   {count:,} · {'<1%' if share < 0.005 else f'{share:.0%}'}"
                         for name, count, share in zip(names, counts[value], counts["_share"])]
    legend_labels = list(counts["_legend"])
    palette = [colors[order.index(name)] for name in present]

    # The ring is sized from the plot area, so it fits a narrow column as well as a wide one.
    radius = alt.ExprRef("min(width, height) / 2 - 2")
    ring = alt.Chart(counts).mark_arc(outerRadius=radius, innerRadius=alt.ExprRef("(min(width, height) / 2 - 2) * 0.62"),
                                      stroke="white", strokeWidth=2).encode(
        theta=alt.Theta(f"{value}:Q", stack=True),
        order=alt.Order("_order:Q"),
        color=alt.Color("_legend:N", sort=legend_labels, scale=alt.Scale(domain=legend_labels, range=palette),
                        legend=alt.Legend(orient="bottom", direction="vertical", columns=1, labelLimit=260)),
        tooltip=[alt.Tooltip("_part:N", title=category), alt.Tooltip(f"{value}:Q", title=value_title, format=","),
                 alt.Tooltip("_share:Q", title="Share", format=".1%")],
    )
    middle = alt.ExprRef("width / 2")
    figure = alt.Chart(pd.DataFrame({"text": [f"{total:,}"]})).mark_text(
        x=middle, y=alt.ExprRef("height / 2 - 7"), fontSize=20, fontWeight="bold", color=INK).encode(text="text:N")
    caption = alt.Chart(pd.DataFrame({"text": [centre]})).mark_text(
        x=middle, y=alt.ExprRef("height / 2 + 12"), fontSize=11, color=MUTED).encode(text="text:N")
    return (ring + figure + caption).properties(height=200 + 20 * len(present))


def heatmap(data: pd.DataFrame, x: str, y: str, value: str, x_order: list[str], y_order: list[str],
            value_title: str) -> alt.Chart:
    """Coverage heatmap: one hue, darker = higher, the percentage is written in every cell."""
    base = alt.Chart(data).encode(
        x=alt.X(f"{x}:N", sort=x_order, title=None, axis=alt.Axis(orient="top", labelAngle=-25, labelAlign="left")),
        y=alt.Y(f"{y}:N", sort=y_order, title=None),
        tooltip=[alt.Tooltip(f"{y}:N"), alt.Tooltip(f"{x}:N"), alt.Tooltip(f"{value}:Q", title=value_title, format=".0%"),
                 alt.Tooltip("in_scope:Q", title="Servers in scope")],
    )
    cells = base.mark_rect(stroke="white", strokeWidth=2, cornerRadius=4).encode(
        color=alt.Color(f"{value}:Q", scale=alt.Scale(domain=[0, 1], range=["#EFE8FB", "#3A1780"]), legend=None))
    text = base.mark_text(fontSize=12).encode(
        text=alt.Text(f"{value}:Q", format=".0%"),
        color=alt.condition(alt.datum[value] > 0.55, alt.value("white"), alt.value(INK)))
    return (cells + text).properties(height=_height(len(y_order), 30) + 20)


def trend_lines(data: pd.DataFrame, series: list[str], colors: list[str], value_title: str) -> alt.Chart:
    """Weekly trend: one line with points per series, x = the "Week" column (Sunday that starts it)."""
    present = [name for name in series if name in data.columns]
    long = data.melt(id_vars="Week", value_vars=present, var_name="Measure", value_name="Value").dropna(subset=["Value"])
    long["Value"] = long["Value"].astype(float)
    chart = alt.Chart(long).mark_line(point=alt.OverlayMarkDef(size=60, filled=True), strokeWidth=2.5).encode(
        x=alt.X("Week:T", title=None, axis=alt.Axis(format="%d %b", labelAngle=0, tickCount="week")),
        y=alt.Y("Value:Q", title=value_title, axis=alt.Axis(format="~s", tickMinStep=1), scale=alt.Scale(zero=True)),
        color=alt.Color("Measure:N", scale=alt.Scale(domain=present, range=[colors[series.index(n)] for n in present])),
        tooltip=[alt.Tooltip("Week:T", title="Week of", format="%d %b %Y"), alt.Tooltip("Measure:N"),
                 alt.Tooltip("Value:Q", title=value_title, format=",")],
    )
    return chart.properties(height=260)


def gantt(data: pd.DataFrame) -> alt.Chart:
    """Schedule timeline: one row per wave, one bar per change window it uses, coloured by environment."""
    present = [name for name in ENV_ORDER if name in set(data["Environment"])]
    waves = list(dict.fromkeys(data["Wave"]))
    chart = alt.Chart(data).mark_bar(cornerRadius=4, size=18).encode(
        x=alt.X("Start:T", title=None, axis=alt.Axis(format="%a %d %b", labelAngle=0, tickCount="day")),
        x2="End:T",
        y=alt.Y("Wave:N", sort=waves, title=None),
        color=alt.Color("Environment:N", scale=alt.Scale(domain=present, range=[ENV_COLORS[ENV_ORDER.index(n)] for n in present])),
        tooltip=[alt.Tooltip("Wave:N"), alt.Tooltip("Window:N"), alt.Tooltip("Environment:N"),
                 alt.Tooltip("Start:T", format="%a %d %b %Y %H:%M"), alt.Tooltip("End:T", format="%a %d %b %Y %H:%M"),
                 alt.Tooltip("Servers:Q"), alt.Tooltip("Estimated minutes:Q")],
    )
    return chart.properties(height=_height(len(waves), 40, legend=True))
