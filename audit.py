#!/usr/bin/env python3
"""
audit.py — Password Audit CLI Tool
-----------------------------------
A command-line tool to audit passwords for strength, breach exposure,
and dangerous structural patterns.

Usage:
    python audit.py check "mypassword"
    python audit.py bulk passwords.txt
    python audit.py bulk passwords.txt --no-hibp --output report.csv

Requirements:
    pip install zxcvbn rich requests click
"""

import re
import hashlib
import csv
import os
import sys

import click
import requests
import zxcvbn as zx
from rich.console import Console
from rich.table import Table
from rich import box as rich_box

console = Console()

SCORE_LABELS = {
    0: ("Terrible", "bold red"),
    1: ("Bad",      "red"),
    2: ("Weak",     "yellow"),
    3: ("Good",     "green"),
    4: ("Strong",   "bold green"),
}

RISK_COLORS = {"HIGH": "bold red", "MEDIUM": "yellow", "LOW": "bold green"}
HIBP_API    = "https://api.pwnedpasswords.com/range/"

KEYBOARD_WALKS = [
    "qwerty","qwert","werty","asdfg","asdf","sdfgh",
    "zxcvb","zxcv","qazwsx","12345","23456","34567",
    "45678","56789","67890","09876","98765",
]
LEET_MAP = {
    "a":["4","@"],"e":["3"],"i":["1","!"],"o":["0"],
    "s":["5","$"],"t":["7"],"l":["1"],"g":["9"],"b":["8"],
}

def _reverse_leet(password):
    p = password.lower()
    for letter, subs in LEET_MAP.items():
        for sub in subs:
            p = p.replace(sub, letter)
    return p

def score_password(password):
    r = zx.zxcvbn(password)
    score = r["score"]
    label, _ = SCORE_LABELS[score]
    return {
        "score":      score,
        "label":      label,
        "crack_time": r["crack_times_display"]["offline_slow_hashing_1e4_per_second"],
        "warning":    r["feedback"]["warning"] or "",
        "suggestions":r["feedback"]["suggestions"],
        "guesses":    r["guesses"],
    }

def check_breach(password):
    sha1   = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    try:
        response = requests.get(HIBP_API + prefix, timeout=5)
        response.raise_for_status()
    except requests.RequestException:
        return -1
    for line in response.text.splitlines():
        parts = line.split(":")
        if len(parts) == 2 and parts[0] == suffix:
            return int(parts[1])
    return 0

def detect_patterns(password):
    flags, lower = [], password.lower()
    reversed_leet = _reverse_leet(password)
    for walk in KEYBOARD_WALKS:
        if walk in lower or walk in lower[::-1]:
            flags.append(f"keyboard walk ({walk})")
            break
    for walk in KEYBOARD_WALKS:
        if walk in reversed_leet and f"keyboard walk ({walk})" not in flags:
            flags.append(f"l33tspeak keyboard walk ({walk})")
            break
    for pattern, label in [
        (r"\b(0[1-9]|[12]\d|3[01])(0[1-9]|1[0-2])\d{4}\b", "date (DDMMYYYY)"),
        (r"\b(0[1-9]|1[0-2])[\/\-](0[1-9]|[12]\d|3[01])[\/\-]\d{2,4}\b", "date (MM/DD/YY)"),
        (r"\b(19|20)\d{2}\b", "year (19xx/20xx)"),
    ]:
        if re.search(pattern, password):
            flags.append(label)
    if re.search(r"(.)\1{2,}", password):
        flags.append("repeated characters")
    leet_found = any(sub in password for subs in LEET_MAP.values() for sub in subs)
    if leet_found and not any("l33tspeak" in f for f in flags):
        flags.append("l33tspeak substitution")
    return flags

def audit_password(password, check_hibp=True):
    strength = score_password(password)
    breach   = check_breach(password) if check_hibp else -1
    patterns = detect_patterns(password)
    if breach > 0 or strength["score"] <= 1:
        risk = "HIGH"
    elif strength["score"] == 2 or patterns:
        risk = "MEDIUM"
    else:
        risk = "LOW"
    return {
        "password": password, "score": strength["score"], "label": strength["label"],
        "crack_time": strength["crack_time"], "warning": strength["warning"],
        "suggestions": strength["suggestions"], "breach_count": breach,
        "patterns": patterns, "risk_level": risk,
    }

def render_report(results):
    table = Table(title="Password Audit Report", box=rich_box.ROUNDED,
                  show_lines=True, header_style="bold cyan")
    table.add_column("Password",   style="dim",      max_width=24)
    table.add_column("Score",      justify="center", max_width=10)
    table.add_column("Crack Time", justify="left",   max_width=22)
    table.add_column("Breaches",   justify="center", max_width=10)
    table.add_column("Patterns",   justify="left",   max_width=28)
    table.add_column("Risk",       justify="center", max_width=8)
    for r in results:
        score_label, score_color = SCORE_LABELS[r["score"]]
        breach = r["breach_count"]
        table.add_row(
            r["password"],
            f"[{score_color}]{r['score']}/4\n{score_label}[/{score_color}]",
            r["crack_time"],
            f"[bold red]{breach:,}×[/bold red]" if breach > 0
                else ("[yellow]N/A[/yellow]" if breach < 0 else "[bold green]Clean[/bold green]"),
            "[yellow]" + "\n".join(r["patterns"]) + "[/yellow]" if r["patterns"] else "[green]none[/green]",
            f"[{RISK_COLORS[r['risk_level']]}]{r['risk_level']}[/{RISK_COLORS[r['risk_level']]}]",
        )
    console.print(table)
    high   = sum(1 for r in results if r["risk_level"] == "HIGH")
    medium = sum(1 for r in results if r["risk_level"] == "MEDIUM")
    low    = sum(1 for r in results if r["risk_level"] == "LOW")
    console.print(f"\n  Summary: [bold red]{high} HIGH[/bold red] · [yellow]{medium} MEDIUM[/yellow] · [bold green]{low} LOW[/bold green] ({len(results)} total)")


@click.group()
def cli():
    """Password Audit Tool — check strength, breaches, and patterns."""
    pass

@cli.command()
@click.argument("password")
@click.option("--no-hibp", is_flag=True, default=False, help="Skip HaveIBeenPwned check")
def check(password, no_hibp):
    """Audit a single password."""
    result = audit_password(password, check_hibp=not no_hibp)
    render_report([result])
    if result["suggestions"]:
        console.print("\n  [bold]Suggestions:[/bold]")
        for s in result["suggestions"]:
            console.print(f"    • {s}")

@cli.command()
@click.argument("filepath", type=click.Path(exists=True))
@click.option("--no-hibp",  is_flag=True, default=False,             help="Skip HIBP checks (faster)")
@click.option("--output",   default="audit_report.csv", show_default=True, help="CSV output filename")
def bulk(filepath, no_hibp, output):
    """Audit all passwords in a .txt file (one per line)."""
    with open(filepath, "r", encoding="utf-8") as f:
        passwords = [l.strip() for l in f if l.strip()]
    console.print(f"  Loaded [cyan]{len(passwords)}[/cyan] passwords from [dim]{filepath}[/dim]")
    results = []
    for i, pw in enumerate(passwords, 1):
        console.print(f"  Auditing [{i}/{len(passwords)}]...", end="\r")
        results.append(audit_password(pw, check_hibp=not no_hibp))
    console.print(f"  [green]✓ Done[/green]                    ")
    render_report(results)
    with open(output, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=[
            "password","score","label","crack_time","breach_count","patterns","risk_level","warning"
        ])
        writer.writeheader()
        for r in results:
            writer.writerow({**r, "patterns": "; ".join(r["patterns"]), "suggestions": ""})
    console.print(f"  [bold green]✓ Report saved:[/bold green] [cyan]{output}[/cyan]")

if __name__ == "__main__":
    cli()
