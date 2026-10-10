"""Ядро сканера: находки, доказательства, контекст проверки и лог."""
import os
import sys
import time
import traceback
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SEV_RU = {
    "CRITICAL": "КРИТИЧНО",
    "HIGH": "ВЫСОКИЙ",
    "MEDIUM": "СРЕДНИЙ",
    "LOW": "НИЗКИЙ",
    "INFO": "ИНФО",
}
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}

_ANSI = {
    "CRITICAL": "\033[1;97;41m",
    "HIGH": "\033[1;91m",
    "MEDIUM": "\033[1;93m",
    "LOW": "\033[96m",
    "INFO": "\033[37m",
    "OK": "\033[92m",
    "SECTION": "\033[1;95m",
    "DIM": "\033[90m",
    "ERR": "\033[31m",
    "RESET": "\033[0m",
}


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def fmt_dt(dt: Optional[datetime]) -> str:
    """Время в локальном часовом поясе проверяемого ПК."""
    if dt is None:
        return "—"
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone().strftime("%Y-%m-%d %H:%M:%S")


def ago(dt: Optional[datetime], now: Optional[datetime] = None) -> str:
    if dt is None:
        return ""
    now = now or utcnow()
    delta = now - dt
    secs = int(delta.total_seconds())
    if secs < 0:
        return "в будущем (!)"
    if secs < 60:
        return f"{secs} сек. назад"
    if secs < 3600:
        return f"{secs // 60} мин. назад"
    if secs < 86400:
        return f"{secs // 3600} ч. {secs % 3600 // 60} мин. назад"
    return f"{secs // 86400} дн. назад"


@dataclass
class Evidence:
    text: str
    path: Optional[str] = None
    time: Optional[datetime] = None
    url: Optional[str] = None
    source: Optional[str] = None
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self):
        return {
            "text": self.text,
            "path": self.path,
            "time": fmt_dt(self.time) if self.time else None,
            "time_utc": self.time.isoformat() if self.time else None,
            "url": self.url,
            "source": self.source,
            "extra": self.extra,
        }


@dataclass
class Finding:
    severity: str
    category: str
    title: str
    description: str
    evidence: List[Evidence] = field(default_factory=list)
    kb: List[str] = field(default_factory=list)       # ссылки на статьи базы знаний
    tools: List[str] = field(default_factory=list)    # инструменты для ручной перепроверки
    recommendation: str = ""

    def to_dict(self):
        return {
            "severity": self.severity,
            "severity_ru": SEV_RU[self.severity],
            "category": self.category,
            "title": self.title,
            "description": self.description,
            "recommendation": self.recommendation,
            "kb": self.kb,
            "tools": self.tools,
            "evidence": [e.to_dict() for e in self.evidence],
        }


@dataclass
class ExecRecord:
    """След запуска/обращения к файлу из любого источника."""
    path: str
    source: str
    time: Optional[datetime] = None
    note: str = ""
    kind: str = "exec"   # exec — запуск, access — обращение/открытие, storage — факт хранения


class Logger:
    def __init__(self, log_path: Optional[str], color: bool = True, verbose: bool = False):
        self.color = color
        self.verbose = verbose
        self.lines: List[str] = []
        self._fh = open(log_path, "w", encoding="utf-8-sig") if log_path else None

    def _emit(self, text: str, style: Optional[str] = None, console: bool = True):
        stamp = datetime.now().strftime("%H:%M:%S")
        line = f"[{stamp}] {text}"
        self.lines.append(line)
        if self._fh:
            self._fh.write(line + "\n")
            self._fh.flush()
        if console:
            if self.color and style:
                out = f"{_ANSI['DIM']}[{stamp}]{_ANSI['RESET']} {_ANSI[style]}{text}{_ANSI['RESET']}"
            else:
                out = line
            try:
                print(out, flush=True)
            except UnicodeEncodeError:
                print(out.encode("ascii", "replace").decode(), flush=True)

    def section(self, title: str):
        self._emit("", None)
        self._emit(f"══════ {title} ══════", "SECTION")

    def info(self, text: str):
        self._emit(f"  {text}", None)

    def ok(self, text: str):
        self._emit(f"  [OK] {text}", "OK")

    def debug(self, text: str):
        self._emit(f"  · {text}", "DIM", console=self.verbose)

    def warn(self, text: str):
        self._emit(f"  [!] {text}", "MEDIUM")

    def error(self, text: str):
        self._emit(f"  [ОШИБКА] {text}", "ERR")

    def finding(self, f: Finding):
        tag = SEV_RU[f.severity]
        self._emit(f"  [{tag}] {f.title}", f.severity)
        for ev in f.evidence[:5]:
            t = f" ({fmt_dt(ev.time)})" if ev.time else ""
            self._emit(f"        → {ev.text}{t}", "DIM")
        if len(f.evidence) > 5:
            self._emit(f"        → … ещё {len(f.evidence) - 5} шт. (см. отчёт)", "DIM")

    def close(self):
        if self._fh:
            self._fh.close()
            self._fh = None


@dataclass
class Options:
    hours: float = 3.0              # «незадолго до проверки»
    since: Optional[datetime] = None
    quick: bool = False             # не сканировать диски целиком
    no_memory: bool = False
    no_usn: bool = False
    memory_limit_mb: int = 768
    out_dir: Optional[str] = None
    open_report: bool = True
    verbose: bool = False
    extra_paths: List[str] = field(default_factory=list)


class Context:
    def __init__(self, opts: Options, out_dir: str):
        self.opts = opts
        self.out_dir = out_dir
        self.start = utcnow()
        if opts.since:
            self.window_start = opts.since
        else:
            self.window_start = self.start - timedelta(hours=opts.hours)
        self.log = Logger(os.path.join(out_dir, "scan.log"), color=True, verbose=opts.verbose)
        self.findings: List[Finding] = []
        self.executions: List[ExecRecord] = []
        self.tables: Dict[str, Dict[str, Any]] = {}
        self.system: Dict[str, Any] = {}
        self.errors: List[str] = []
        self.timings: Dict[str, float] = {}
        # общие данные между проверками
        self.shared: Dict[str, Any] = {}

    # ---------- помощники ----------
    def is_recent(self, dt: Optional[datetime]) -> bool:
        return dt is not None and dt >= self.window_start

    def recent_mark(self, dt: Optional[datetime]) -> str:
        return " ⚠ незадолго до проверки" if self.is_recent(dt) else ""

    def add(self, severity: str, category: str, title: str, description: str,
            evidence: Optional[List[Evidence]] = None, kb: Optional[List[str]] = None,
            tools: Optional[List[str]] = None, recommendation: str = "") -> Finding:
        f = Finding(severity, category, title, description, evidence or [], kb or [], tools or [],
                    recommendation)
        self.findings.append(f)
        self.log.finding(f)
        return f

    def add_exec(self, path: str, source: str, time: Optional[datetime] = None, note: str = "",
                 kind: str = "exec"):
        if not path:
            return
        self.executions.append(ExecRecord(path.strip(), source, time, note, kind))

    def table(self, key: str, title: str, columns: List[str], rows: List[List[Any]], note: str = ""):
        self.tables[key] = {"title": title, "columns": columns, "rows": rows, "note": note}

    def run_check(self, name: str, func):
        self.log.section(name)
        t0 = time.time()
        try:
            func(self)
        except KeyboardInterrupt:
            raise
        except Exception as e:  # одна упавшая проверка не должна ронять весь скан
            msg = f"{name}: {type(e).__name__}: {e}"
            self.errors.append(msg + "\n" + traceback.format_exc())
            self.log.error(msg)
            self.log.debug(traceback.format_exc())
        finally:
            self.timings[name] = round(time.time() - t0, 1)


def resource_dir() -> str:
    """Каталог рядом с exe (PyInstaller) или со скриптом."""
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
