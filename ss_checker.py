"""SS Checker - автоматическая проверка ПК на читы для Minecraft по базе знаний SS.

Запуск (от администратора):  ss_checker.exe   или   python ss_checker.py [параметры]
"""
import argparse
import os
import platform
import sys
import time
from datetime import datetime

from sschecker import __version__
from sschecker.checks import PIPELINE
from sschecker.core import SEV_RU, SEVERITIES, Context, Options, fmt_dt, resource_dir
from sschecker.report import verdict, write_html, write_json
from sschecker.winutil import IS_WIN, enable_vt_mode, is_admin

BANNER = r"""
  ____ ____     ____ _               _
 / ___/ ___|   / ___| |__   ___  ___| | _____ _ __
 \___ \___ \  | |   | '_ \ / _ \/ __| |/ / _ \ '__|
  ___) |__) | | |___| | | |  __/ (__|   <  __/ |
 |____/____/   \____|_| |_|\___|\___|_|\_\___|_|     v{ver}
"""


def parse_args(argv):
    p = argparse.ArgumentParser(description="Проверка ПК на читы Minecraft по базе знаний SS")
    p.add_argument("--hours", type=float, default=3.0,
                   help="окно «незадолго до проверки» в часах (по умолчанию 3)")
    p.add_argument("--since", help="время вызова на проверку, «ГГГГ-ММ-ДД ЧЧ:ММ» (локальное) - заменяет --hours")
    p.add_argument("--quick", action="store_true", help="искать файлы только в профиле пользователя (быстрее)")
    p.add_argument("--no-memory", action="store_true", help="не сканировать память процессов")
    p.add_argument("--no-usn", action="store_true", help="не читать USN-журнал")
    p.add_argument("--memory-limit", type=int, default=768, help="МБ памяти на процесс (по умолчанию 768)")
    p.add_argument("--path", action="append", default=[], help="доп. папка для поиска (например, своя папка игры)")
    p.add_argument("--out", help="куда сохранить отчёт (по умолчанию рядом с программой)")
    p.add_argument("--no-open", action="store_true", help="не открывать отчёт после проверки")
    p.add_argument("--no-pause", action="store_true", help="не ждать Enter в конце")
    p.add_argument("-v", "--verbose", action="store_true", help="подробный лог")
    return p.parse_args(argv)


def relaunch_as_admin():
    """Если запущено без прав - предлагаем UAC-перезапуск"""
    import ctypes
    params = " ".join(f'"{a}"' for a in sys.argv[1:])
    if getattr(sys, "frozen", False):
        exe, args = sys.executable, params
    else:
        exe, args = sys.executable, f'"{os.path.abspath(sys.argv[0])}" {params}'
    rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, args, None, 1)
    return rc > 32


def main(argv=None):
    args = parse_args(argv if argv is not None else sys.argv[1:])
    enable_vt_mode()
    print(BANNER.format(ver=__version__))
    if IS_WIN and not is_admin() and not os.environ.get("SS_NO_ELEVATE"):
        print("Для полной проверки нужны права администратора. Запрашиваю повышение прав...")
        if relaunch_as_admin():
            return 0
        print("Повышение отклонено - продолжаю с ограниченными правами")

    since = None
    if args.since:
        try:
            since = datetime.strptime(args.since, "%Y-%m-%d %H:%M").astimezone()
        except ValueError:
            print("Неверный формат --since, ожидается «ГГГГ-ММ-ДД ЧЧ:ММ»")
            return 2
    opts = Options(hours=args.hours, since=since, quick=args.quick, no_memory=args.no_memory, no_usn=args.no_usn,
                   memory_limit_mb=args.memory_limit, open_report=not args.no_open, verbose=args.verbose,
                   extra_paths=args.path)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base = args.out or resource_dir()
    out_dir = os.path.join(base, f"SS_Report_{platform.node()}_{stamp}")
    os.makedirs(out_dir, exist_ok=True)

    ctx = Context(opts, out_dir)
    ctx.log.info(f"SS Checker {__version__}. Отчёт: {out_dir}")
    ctx.log.info(f"«Незадолго до проверки» = после {fmt_dt(ctx.window_start)}")
    t0 = time.time()
    try:
        for name, func in PIPELINE:
            if opts.no_memory and func.__module__.endswith("memory"):
                continue
            if opts.no_usn and func.__module__.endswith("usn"):
                continue
            ctx.run_check(name, func)
    except KeyboardInterrupt:
        ctx.log.warn("Проверка прервана пользователем - сохраняю то, что успели собрать")
    duration = time.time() - t0

    html_path = os.path.join(out_dir, "report.html")
    json_path = os.path.join(out_dir, "report.json")
    write_json(ctx, json_path)
    write_html(ctx, html_path, duration)

    counts, v = verdict(ctx)
    ctx.log.section("ИТОГ")
    style = {"crit": "CRITICAL", "high": "HIGH", "med": "MEDIUM", "ok": "OK"}[v[0]]
    ctx.log._emit(f"  {v[1]}", style)
    ctx.log.info("  ".join(f"{SEV_RU[s]}: {counts[s]}" for s in SEVERITIES))
    top = [f for f in sorted(ctx.findings, key=lambda f: SEVERITIES.index(f.severity))
           if f.severity in ("CRITICAL", "HIGH")][:15]
    for f in top:
        ctx.log._emit(f"  • [{SEV_RU[f.severity]}] {f.title}", f.severity)
    ctx.log.info(f"Время проверки: {duration:.0f} с")
    ctx.log.info(f"HTML-отчёт: {html_path}")
    ctx.log.info(f"JSON:       {json_path}")
    ctx.log.info(f"Лог:        {os.path.join(out_dir, 'scan.log')}")
    ctx.log.close()
    if opts.open_report and IS_WIN:
        try:
            os.startfile(html_path)
        except OSError:
            pass
    if IS_WIN and not args.no_pause and sys.stdin and sys.stdin.isatty():
        try:
            input("\nНажмите Enter для выхода...")
        except EOFError:
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
