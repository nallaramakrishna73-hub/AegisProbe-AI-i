"""
Structured logging for AegisProbe AI using Rich.
Never logs real secrets, tokens, or credentials.
"""

import sys
import logging
from rich.console import Console
from rich.theme import Theme
from typing import Optional

custom_theme = Theme({
    "info": "dim cyan",
    "warning": "yellow",
    "error": "bold red",
    "critical": "bold white on red",
    "success": "bold green",
    "banner": "bold cyan",
})

console = Console(theme=custom_theme)
error_console = Console(stderr=True, theme=custom_theme)

DEBUG_MODE = False


def set_debug(enabled: bool):
    global DEBUG_MODE
    DEBUG_MODE = enabled


def log_info(msg: str):
    console.print(f"[info][INFO][/info] {msg}")


def log_success(msg: str):
    console.print(f"[success][SUCCESS][/success] {msg}")


def log_warning(msg: str):
    console.print(f"[warning][WARNING][/warning] {msg}")


def log_error(msg: str, exc: Optional[Exception] = None):
    error_console.print(f"[error][ERROR][/error] {msg}")
    if DEBUG_MODE and exc:
        error_console.print_exception()


def log_debug(msg: str):
    if DEBUG_MODE:
        console.print(f"[dim][DEBUG] {msg}[/dim]")
