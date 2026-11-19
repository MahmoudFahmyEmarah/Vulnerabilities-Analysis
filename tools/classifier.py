"""Rule-based split of findings into OS issues and application issues.

A finding is an OS issue when the operating system team fixes it (distribution
packages, kernel, Windows updates, base network services, hypervisor tools).
Everything fixed by upgrading or reconfiguring a product is an application issue.

Rules run top to bottom on the finding title; the first match wins. Titles that
match nothing default to an application issue and are marked as unmatched so
they can be reviewed or sent to the model (agents/classifier.py).
"""
from __future__ import annotations

import re

import pandas as pd

OS = "OS Issue"
APP = "Application Issue"
UNMATCHED_RULE = "Unmatched (default)"

# (rule name, topic, pattern) — patterns are case-insensitive.
RULES: list[tuple[str, str, str]] = [
    # Vendor builds of Java ("Red Hat OpenJDK ... (RHSA-...)", "Microsoft OpenJDK ...") are application
    # runtimes, not OS packages, so this rule comes before the distribution-advisory rule.
    ("Java runtime (vendor build)", APP, r"^(red hat|microsoft|azul|oracle|eclipse|amazon) (openjdk|java|corretto|temurin)"),
    ("Linux distribution advisory", OS,
     r"^(red hat (security )?update|oracle enterprise linux|centos|suse|ubuntu|debian|amazon linux|rocky linux"
     r"|almalinux)\b|\brhsa-\d"),
    ("Operating system end of life", OS, r"^eol/obsolete operating system"),
    ("Linux kernel", OS, r"\blinux kernel\b"),
    ("Windows update or component", OS,
     r"^microsoft windows\b|^windows\b|microsoft (desktop window manager|winverifytrust|spnego|internet explorer"
     r"|\.net|asp\.net|xml core|malicious software|malware protection|defender|cumulative security update"
     r"|http/2 protocol)|\bsmb(v\d)?\b|null session|\bntlm\b|netbios"),
    ("OS network service", OS,
     r"\bopenssh\b|^ssh\b|\bnfs\b|rpc mountd|\bsnmp\b|\bntp\b|\bicmp\b|tcp timestamp|\bsudo\b|\bglibc\b"
     r"|\bsystemd\b|\bpolkit\b|xdmcp|\bvnc\b"),
    ("OS configuration", OS, r"file permissions|path variable|world writable|passwd|\bumask\b"),
    ("Virtualisation platform", OS, r"^vmware (tools|esxi|vcenter)"),
    ("Security or backup agent", OS, r"qualys cloud agent|forescout|trend micro|deep security|networker"),
    ("TLS or certificate configuration", APP,
     r"ssl certificate|secure sockets layer|ssl/tls|\btls\b|sweet32|birthday attacks|weak ssl|certificate"),
    ("Java runtime", APP, r"\b(oracle java|openjdk|azul|java se|jre|jdk)\b"),
    ("Application or middleware", APP,
     r"apache|log4j|spring|tomcat|elasticsearch|\bbeats\b|kibana|gitlab|jenkins|zookeeper|kafka|nifi|activemq"
     r"|hadoop|\bspark\b|cloudera|mysql|postgres|pgadmin|sql server|oracle database|mongodb|redis|kubernetes"
     r"|docker|grafana|nginx|jetty|jackson|netty|python|node\.js|\bphp\b|\bsas\b|tableau|teradata|openssl"
     r"|\belastic\b|\bjmx\b|jupyter|power bi|libcurl|starlette|nltk|http trace|web server"),
    ("Desktop software", APP,
     r"chrome|microsoft edge|firefox|notepad\+\+|zoom|7-zip|visual studio|visual c\+\+|microsoft office|adobe"
     r"|putty|winscp|wireshark|\bvlc\b|winrar|mobaxterm|pycharm|webex|azure data studio|tortoisesvn"),
    ("Obsolete software", APP, r"^eol/obsolete software"),
]

_COMPILED = [(name, topic, re.compile(pattern, re.IGNORECASE)) for name, topic, pattern in RULES]


def classify_title(title: str) -> tuple[str, str]:
    """Return (topic, rule name) for one finding title."""
    text = title or ""
    for name, topic, pattern in _COMPILED:
        if pattern.search(text):
            return topic, name
    return APP, UNMATCHED_RULE


def classify_titles(titles: pd.Series, overrides: dict[str, str] | None = None) -> pd.DataFrame:
    """Classify a column of titles. Works on unique titles, so 100k rows cost ~3k lookups.

    ``overrides`` maps a title to a topic decided by a person or by the model; it wins over rules.
    """
    overrides = overrides or {}
    unique = pd.unique(titles.dropna())
    topic_of: dict[str, str] = {}
    rule_of: dict[str, str] = {}
    for title in unique:
        if title in overrides:
            topic_of[title], rule_of[title] = overrides[title], "AI / manual label"
        else:
            topic_of[title], rule_of[title] = classify_title(str(title))
    return pd.DataFrame(
        {"Topic": titles.map(topic_of).fillna(APP), "Topic Rule": titles.map(rule_of).fillna(UNMATCHED_RULE)},
        index=titles.index,
    )


def os_family(operating_system: str | None) -> str:
    """Collapse a scanner OS string to a short key, e.g. 'RHEL 8' or 'Windows Server 2019'."""
    text = str(operating_system or "")
    match = re.search(r"red hat enterprise linux(?: server)? (\d+)", text, re.IGNORECASE)
    if match:
        return f"RHEL {match.group(1)}"
    match = re.search(r"windows server (\d{4})", text, re.IGNORECASE)
    if match:
        return f"Windows Server {match.group(1)}"
    lowered = text.lower()
    if "windows" in lowered:
        return "Windows"
    if "vmware" in lowered or "esxi" in lowered:
        return "VMware"
    if any(word in lowered for word in ("linux", "suse", "ubuntu", "centos", "debian")):
        return "Linux (other)"
    return "Other / unknown"
