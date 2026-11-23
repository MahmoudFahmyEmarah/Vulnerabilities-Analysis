"""Look and feel: purple header band, KPI cards, pills and badges.

All dynamic text is HTML-escaped before it is placed in markup, because application
and server names come from uploaded files.
"""
from __future__ import annotations

import html
from typing import Any

import streamlit as st

PURPLE_900 = "#2A0A52"
PURPLE_700 = "#4F008C"
PURPLE_500 = "#6A3FC4"
RED = "#D03B3B"
ORANGE = "#EB6834"
INK = "#1D1033"
MUTED = "#6F6781"

_CSS = f"""
<style>
:root {{
  --p900: {PURPLE_900}; --p700: {PURPLE_700}; --p500: {PURPLE_500}; --p200: #D9CDF3; --p50: #F6F2FC;
  --red: {RED}; --ink: {INK}; --muted: {MUTED}; --line: #E8E1F3; --card: #FFFFFF;
}}
.block-container {{ padding-top: 3.2rem; padding-bottom: 3rem; max-width: 1500px; }}
.sp-hero, .sp-kpis, .sp-note, .sp-title, .sp-caption, .sp-badge, .sp-facts, .sp-text {{
  font-family: system-ui, -apple-system, "Segoe UI", sans-serif; }}

.sp-hero {{
  background: linear-gradient(115deg, var(--p900) 0%, var(--p700) 55%, #7B2FBF 100%);
  color: #fff; border-radius: 16px; padding: 22px 28px; margin-bottom: 14px;
  display: flex; justify-content: space-between; gap: 24px; align-items: flex-start; flex-wrap: wrap;
}}
.sp-hero .eyebrow {{ font-size: 11px; letter-spacing: .14em; text-transform: uppercase; opacity: .8; font-weight: 600; }}
.sp-hero h1 {{ font-size: 26px; line-height: 1.2; margin: 6px 0 8px; padding: 0; color: #fff; font-weight: 700; }}
.sp-hero p {{ margin: 0; max-width: 820px; font-size: 13.5px; line-height: 1.5; opacity: .92; }}
.sp-hero .meta {{ text-align: right; font-size: 12px; line-height: 1.7; opacity: .9; white-space: nowrap; }}
.sp-hero .meta b {{ font-weight: 600; }}

.sp-note {{
  background: #FFF1F3; border: 1px solid #F6CBD2; color: #A3152B; border-radius: 10px;
  padding: 9px 14px; font-size: 13px; margin-bottom: 14px;
}}
.sp-kpis {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(125px, 1fr)); gap: 12px; margin: 4px 0 16px; }}
.sp-kpi {{ background: var(--card); border: 1px solid var(--line); border-radius: 14px; padding: 14px 16px 15px; min-width: 0; }}
.sp-kpi .label {{ font-size: 11px; letter-spacing: .1em; text-transform: uppercase; color: var(--p700); font-weight: 700; }}
.sp-kpi .value {{ font-size: 30px; font-weight: 700; color: var(--ink); line-height: 1.15; margin-top: 6px; }}
.sp-kpi .value small {{ font-size: 14px; font-weight: 500; color: var(--muted); margin-left: 6px; }}
.sp-kpi .sub {{ font-size: 12px; color: var(--muted); margin-top: 4px; overflow-wrap: anywhere; }}
.sp-kpi.primary {{ background: linear-gradient(135deg, var(--p700), #6B1FB0); border-color: var(--p700); }}
.sp-kpi.primary .label, .sp-kpi.primary .value, .sp-kpi.primary .sub, .sp-kpi.primary .value small {{ color: #fff; }}
.sp-kpi.primary .sub {{ opacity: .85; }}
.sp-kpi.alert {{ background: #FFF5F6; border-color: #F6D5DA; }}
.sp-kpi.alert .label, .sp-kpi.alert .value {{ color: var(--red); }}
.sp-kpi .bar {{ height: 6px; border-radius: 3px; background: rgba(120,90,170,.18); margin-top: 10px; overflow: hidden; }}
.sp-kpi .bar i {{ display: block; height: 100%; border-radius: 3px; background: var(--p500); }}
.sp-kpi.primary .bar {{ background: rgba(255,255,255,.25); }} .sp-kpi.primary .bar i {{ background: #fff; }}
.sp-kpi.alert .bar i {{ background: var(--red); }}

.sp-title {{ font-size: 12px; letter-spacing: .12em; text-transform: uppercase; color: var(--p700); font-weight: 700; margin: 2px 0 2px; }}
.sp-caption {{ font-size: 12px; color: var(--muted); margin: 0 0 6px; }}
.sp-badge {{ display: inline-block; padding: 2px 10px; border-radius: 999px; font-size: 12px; font-weight: 600;
  background: var(--p50); color: var(--p700); border: 1px solid var(--p200); margin: 0 6px 6px 0; }}
.sp-badge.solid {{ background: var(--p700); color: #fff; border-color: var(--p700); }}
.sp-badge.red {{ background: #FFF1F3; color: #A3152B; border-color: #F6CBD2; }}
.sp-badge.orange {{ background: #FFF4EC; color: #A2440F; border-color: #F8D6BF; }}
.sp-badge.gray {{ background: #F3F1F6; color: #56506A; border-color: #E2DEE9; }}
.sp-facts {{ display: grid; grid-template-columns: max-content 1fr; gap: 4px 16px; font-size: 13px; margin: 6px 0 10px; }}
.sp-facts dt {{ color: var(--muted); }} .sp-facts dd {{ margin: 0; color: var(--ink); overflow-wrap: anywhere; }}
.sp-text {{ border: 1px solid var(--line); border-radius: 10px; padding: 10px 14px 12px; margin: 4px 0 12px; }}
.sp-text .body {{ white-space: pre-wrap; font-size: 13.5px; line-height: 1.55; color: var(--ink);
  overflow-wrap: anywhere; margin-top: 6px; }}

div[data-testid="stVerticalBlockBorderWrapper"] {{ background: var(--card); border-radius: 14px; }}
section[data-testid="stSidebar"] {{ border-right: 1px solid var(--line); }}
div[data-testid="stDataFrame"] {{ border-radius: 10px; }}
.stTabs [data-baseweb="tab"] {{ font-weight: 600; }}
</style>
"""


def inject() -> None:
    st.html(_CSS)


def esc(value: Any) -> str:
    return html.escape("" if value is None else str(value))


def number(value: Any) -> str:
    try:
        return f"{int(value):,}"
    except (TypeError, ValueError):
        return esc(value)


def percent(part: float, whole: float) -> str:
    return "–" if not whole else f"{100 * part / whole:.0f}%"


def hero(eyebrow: str, title: str, description: str, meta: list[tuple[str, str]] | None = None) -> None:
    meta_html = "".join(f"<div>{esc(label)} <b>{esc(value)}</b></div>" for label, value in meta or [])
    st.html(
        f'<div class="sp-hero"><div><div class="eyebrow">{esc(eyebrow)}</div><h1>{esc(title)}</h1>'
        f'<p>{esc(description)}</p></div><div class="meta">{meta_html}</div></div>'
    )


def note(text: str) -> None:
    st.html(f'<div class="sp-note">{esc(text)}</div>')


def kpis(cards: list[dict[str, Any]]) -> None:
    """Render KPI cards. Each card: label, value, optional unit, sub, tone (primary|alert), progress (0-1)."""
    parts = []
    for card in cards:
        tone = esc(card.get("tone", ""))
        unit = f"<small>{esc(card['unit'])}</small>" if card.get("unit") else ""
        sub = f'<div class="sub">{esc(card["sub"])}</div>' if card.get("sub") else ""
        bar = ""
        if card.get("progress") is not None:
            width = max(0.0, min(1.0, float(card["progress"]))) * 100
            bar = f'<div class="bar"><i style="width:{width:.0f}%"></i></div>'
        parts.append(f'<div class="sp-kpi {tone}"><div class="label">{esc(card["label"])}</div>'
                     f'<div class="value">{esc(card["value"])}{unit}</div>{sub}{bar}</div>')
    st.html(f'<div class="sp-kpis">{"".join(parts)}</div>')


def title(text: str, caption: str = "") -> None:
    extra = f'<div class="sp-caption">{esc(caption)}</div>' if caption else ""
    st.html(f'<div class="sp-title">{esc(text)}</div>{extra}')


def badges(items: list[tuple[str, str]]) -> None:
    """items: (text, tone) where tone is '', solid, red, orange or gray."""
    st.html("".join(f'<span class="sp-badge {esc(tone)}">{esc(text)}</span>' for text, tone in items))


def text_block(heading: str, text: str) -> None:
    """A heading over a full text from a report, shown as it is (escaped, line breaks kept)."""
    st.html(f'<div class="sp-text"><div class="sp-title">{esc(heading)}</div>'
            f'<div class="body">{esc(text) or "Not provided in the report."}</div></div>')


def facts(items: list[tuple[str, Any]]) -> None:
    rows = "".join(f"<dt>{esc(label)}</dt><dd>{esc(value)}</dd>" for label, value in items if value not in (None, ""))
    st.html(f'<dl class="sp-facts">{rows}</dl>')
