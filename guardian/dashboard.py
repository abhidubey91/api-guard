"""Rich-powered colour-coded terminal alerts."""
from datetime import datetime

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from .models import Verdict

console = Console(highlight=False)

_stats = {"total": 0, "blocked": 0, "safe": 0}

_COLS = (("time", 9), ("ip", 16), ("method", 7), ("endpoint", 35), ("verdict", 10),
         ("engine", 10), ("conf", 6), ("ms", 8), ("reason", 40))


def banner(upstream: str, llm_mode: str, port: int = 8000) -> None:
    console.print(Panel.fit(
        f"[bold cyan]API-Guardian[/] listening on [bold]:{port}[/]  ->  upstream [bold]{upstream}[/]\n"
        f"LLM guard: [bold magenta]{llm_mode}[/]",
        title="API-Guardian", border_style="cyan",
    ))
    header = Text()
    for name, width in _COLS:
        header.append(name.ljust(width), style="bold underline")
    console.print(header)


def log_request(ip: str, method: str, path: str, verdict: Verdict, latency_ms: float,
                upstream_status: int | None = None) -> None:
    _stats["total"] += 1
    if verdict.malicious:
        _stats["blocked"] += 1
        vtxt = Text("BLOCKED", style="bold white on red")
    else:
        _stats["safe"] += 1
        vtxt = Text(f"SAFE {upstream_status or ''}".strip(), style="bold green")

    engine_style = {"regex": "yellow", "gemini": "magenta", "heuristic": "blue"}.get(verdict.engine, "white")
    conf_style = "red" if verdict.confidence >= 0.8 else "yellow" if verdict.confidence >= 0.5 else "green"
    lat_style = "green" if latency_ms < 200 else "yellow" if latency_ms < 1500 else "red"

    line = Text()
    line.append(datetime.now().strftime("%H:%M:%S").ljust(9), style="dim")
    line.append(ip.ljust(16))
    line.append(method.ljust(7), style="bold")
    line.append(path[:33].ljust(35), style="cyan")
    line.append_text(vtxt)
    line.append(" " * max(1, 10 - len(vtxt.plain)))
    line.append(verdict.engine.ljust(10), style=engine_style)
    line.append(f"{verdict.confidence:.2f}".ljust(6), style=conf_style)
    line.append(f"{latency_ms:7.1f} ", style=lat_style)
    reason = verdict.reason if verdict.malicious else "-"
    line.append(reason[:40], style="red" if verdict.malicious else "dim")
    console.print(line)

    if verdict.malicious and verdict.evidence:
        for e in verdict.evidence[:3]:
            console.print(Text(f"    -> {e[:110]}", style="dim red"))


def summary() -> None:
    console.print(Panel.fit(
        f"total={_stats['total']}  [green]safe={_stats['safe']}[/]  [red]blocked={_stats['blocked']}[/]",
        title="session summary", border_style="cyan"))
