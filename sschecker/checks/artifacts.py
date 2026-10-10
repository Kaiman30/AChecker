"""Файловые артефакты (База → 1. Артефакты, 4. Win+R, Обходы)."""
import glob
import json
import os
import re
import shutil
import sqlite3
import tempfile
import xml.etree.ElementTree as ET
from collections import defaultdict
from datetime import timedelta

from .. import kb
from ..core import Evidence, fmt_dt
from ..match import deconfuse, hits_text, keyword_hits, suspicious_commands, top_severity
from ..parsers import (decode_text_file, parse_lnk, parse_pca_generaldb, parse_pca_launchdic, parse_prefetch,
                       parse_recycle_i, utf16_strings)
from ..winutil import (FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_READONLY, IS_WIN, ctime_dt, decompress_mam, drives,
                       file_attrs, mtime_dt, normalize_path, path_exists, unix_to_dt)

WINDIR = os.environ.get("SystemRoot", r"C:\Windows")
LOCAL = os.environ.get("LOCALAPPDATA", "")
ROAMING = os.environ.get("APPDATA", "")
TEMP = os.environ.get("TEMP", "")
_ALLOWED_PF_EXT = {".EXE", ".COM", ".SCR", ".CPL", ".MSC"}


def run_check(ctx):
    if not IS_WIN:
        ctx.log.warn("Не Windows — файловые артефакты Windows пропущены")
        return
    for fn in (_prefetch, _pca_files, _java_launcher, _temp, _ps_history, _recent, _jumplists, _recycle,
               _tasks, _usage_logs, _crashdumps, _activities, _hosts):
        try:
            fn(ctx)
        except Exception as e:  # noqa
            ctx.log.error(f"{fn.__name__}: {e}")
            ctx.errors.append(f"artifacts.{fn.__name__}: {e}")


def _sev_up(sev):
    return {"LOW": "MEDIUM", "MEDIUM": "HIGH", "HIGH": "CRITICAL"}.get(sev, sev)


def _kw_ev(text, path=None, t=None, source=None):
    hits = keyword_hits(text, weak=True)
    if not hits:
        return None, None
    return top_severity(hits), Evidence(f"{text}  [совпадение: {hits_text(hits)}]", path=path, time=t, source=source)


# ---------------------------------------------------------------------------
# Prefetch
# ---------------------------------------------------------------------------
def _resolve_volume_path(p: str) -> str:
    m = re.match(r"^\\VOLUME\{[^}]+\}(\\.*)$", p, re.I)
    if not m:
        return normalize_path(p)
    rest = m.group(1)
    for root, _ in drives((2, 3)):
        cand = root[:2] + rest
        if os.path.exists(cand):
            return cand
    return "?:" + rest


def _find_renamed_prefetch():
    """Обход: буква в названии папки Prefetch заменена кириллицей/другим символом."""
    try:
        for name in os.listdir(WINDIR):
            if name.lower() != "prefetch" and deconfuse(name).lower() == "prefetch":
                return os.path.join(WINDIR, name)
            if name.lower() != "prefetch" and re.fullmatch(r"pr.?f.?tch|prefetch.+|.prefetch", name.lower()) \
                    and os.path.isdir(os.path.join(WINDIR, name)):
                return os.path.join(WINDIR, name)
    except OSError:
        pass
    return None


def _prefetch(ctx):
    pf_dir = os.path.join(WINDIR, "Prefetch")
    renamed = _find_renamed_prefetch()
    if renamed:
        ctx.add("CRITICAL", "Обходы", "Папка Prefetch переименована (подмена символов)",
                "Название папки изменено похожими символами (например, кириллической «е»), чтобы Win+R → Prefetch "
                "и WinPrefetchView ничего не показывали.",
                [Evidence(f"Найдена папка: {renamed!r}", path=renamed, time=mtime_dt(renamed))],
                kb=["Обходы/Различные методы/Prefetch"])
        if not os.path.isdir(pf_dir):
            pf_dir = renamed
    if not os.path.isdir(pf_dir):
        ctx.add("CRITICAL", "Обходы", "Папка Prefetch отсутствует",
                "C:\\Windows\\Prefetch не найдена — её удалили или переименовали.", [Evidence(pf_dir)],
                kb=["База/1. Артефакты/Prefetch", "Обходы/Различные методы/Prefetch"])
        return
    files = glob.glob(os.path.join(pf_dir, "*.pf"))
    if not files:
        ctx.add("CRITICAL", "Чистка", "Папка Prefetch пуста",
                "В Prefetch нет ни одного .pf-файла — Prefetch очищали или он отключён.", [Evidence(pf_dir)],
                kb=["База/1. Артефакты/Prefetch"])
        return
    rows, attr_ev, ext_ev, kw_ev, java_ev, dll_ev = [], [], [], [], [], []
    by_name = defaultdict(set)
    cleanup = []
    oldest = None
    parsed = 0
    for f in files:
        base = os.path.basename(f)
        ct, mt = ctime_dt(f), mtime_dt(f)
        if ct and (oldest is None or ct < oldest):
            oldest = ct
        a = file_attrs(f)
        if a & (FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN):
            flags = ("ReadOnly " if a & FILE_ATTRIBUTE_READONLY else "") + ("Hidden" if a & FILE_ATTRIBUTE_HIDDEN else "")
            attr_ev.append(Evidence(f"{base}: {flags}", path=f, time=mt))
        m = re.match(r"^(.+)-([0-9A-F]{8})\.pf$", base, re.I)
        exe_name = m.group(1) if m else base[:-3]
        if m:
            by_name[exe_name.upper()].add(m.group(2).upper())
        ext = os.path.splitext(exe_name)[1].upper()
        info = None
        try:
            with open(f, "rb") as fh:
                raw = fh.read()
            data = decompress_mam(raw)
            if data:
                info = parse_prefetch(data)
        except OSError:
            pass
        last = mt
        count = ""
        exe_path = ""
        if info:
            parsed += 1
            if info["last_runs"]:
                last = info["last_runs"][0]
            count = info["run_count"]
            exe_path = _resolve_volume_path(info["exe_path"]) if info["exe_path"] else ""
            # ссылки на файлы внутри .pf
            up = exe_name.upper()
            for ref in info["files"]:
                sev, e = _kw_ev(ref, path=_resolve_volume_path(ref), t=last, source=base)
                if e:
                    kw_ev.append((sev, e))
                rl = ref.lower()
                if up in ("JAVAW.EXE", "JAVA.EXE") and rl.endswith((".jar", ".dll")):
                    if not re.search(r"\\(libraries|versions|runtime|jre[^\\]*|jdk[^\\]*|java[^\\]*|"
                                     r"assets|natives|bin|lib)\\", rl) or "\\temp\\" in rl or "jnativehook" in rl:
                        java_ev.append(Evidence(f"{base}: {_resolve_volume_path(ref)}", path=_resolve_volume_path(ref),
                                                time=last))
                if up in ("DLLHOST.EXE", "RUNDLL32.EXE", "REGSVR32.EXE") and \
                        re.search(r"\\users\\|\\temp\\|\\downloads\\", rl) and not rl.endswith((".mui", ".dat", ".db")):
                    dll_ev.append(Evidence(f"{base}: {_resolve_volume_path(ref)}", path=_resolve_volume_path(ref),
                                           time=last))
        if ext and ext not in _ALLOWED_PF_EXT:
            sev = "LOW" if ext == ".TMP" else "HIGH"
            ext_ev.append((sev, Evidence(f"{base} → запущен файл «{exe_name}»", path=exe_path or f, time=last)))
        if exe_name.upper() in kb.CLEANUP_BINARIES:
            cleanup.append((exe_name.upper(), last, count, f))
        ctx.add_exec(exe_path or exe_name, "Prefetch", last,
                     note=f"{base}, запусков: {count}" if count != "" else base)
        rows.append([fmt_dt(last), exe_name, count, exe_path, base, fmt_dt(ct)])
    rows.sort(key=lambda r: r[0], reverse=True)
    ctx.table("prefetch", f"Prefetch ({len(files)} файлов, разобрано {parsed})",
              ["Последний запуск", "Файл", "Запусков", "Путь", ".pf", "Создан .pf"], rows)
    ctx.log.info(f"Prefetch: {len(files)} .pf, разобрано {parsed}")
    if parsed == 0 and IS_WIN:
        ctx.log.warn("Не удалось распаковать .pf (нужны права администратора?) — используется дата изменения")

    if attr_ev:
        ctx.add("HIGH", "Обходы", "У .pf-файлов изменены атрибуты (Только чтение / Скрытый)",
                "Атрибут «Только чтение» на .pf «замораживает» историю запусков: Windows не может её обновить.",
                attr_ev, kb=["Обходы/Различные методы/Изменение атрибутов"], tools=["Everything 1.5a", "PrefetchView++"])
    if ext_ev:
        hi = [e for s, e in ext_ev if s == "HIGH"]
        lo = [e for s, e in ext_ev if s == "LOW"]
        if hi:
            ctx.add("CRITICAL", "Обходы", "Prefetch: запускались файлы с изменённым расширением",
                    "В Prefetch не могут появляться картинки и прочие не-.exe файлы. Запись вида BYPASS.PNG-xxxx.pf "
                    "означает, что исполняемый файл переименовали и запустили (wmic/start/cmd).",
                    hi, kb=["Обходы/Различные методы/Измененные расширения", "База/1. Артефакты/Prefetch"])
        if lo:
            ctx.add("LOW", "Файлы", "Prefetch: запускались временные .tmp-файлы",
                    "Обычно это установщики (Inno Setup), но так же может запускаться переименованный файл.", lo)
    if kw_ev:
        sev = "CRITICAL" if any(s == "HIGH" for s, _ in kw_ev) else "HIGH"
        uniq = {e.text: e for _, e in kw_ev}
        ctx.add(sev, "Запуски", "Prefetch: в загруженных файлах есть названия читов",
                "Каждый .pf хранит список файлов, к которым программа обращалась при запуске.",
                list(uniq.values())[:150], kb=["База/1. Артефакты/Prefetch"], tools=["WinPrefetchView"])
    if java_ev:
        uniq = {e.text: e for e in java_ev}
        ctx.add("MEDIUM", "Minecraft", "Prefetch javaw: Java загружала .jar/.dll не из библиотек игры",
                "В .pf процесса javaw остаётся список файлов, загруженных при старте. Там видно следы инжекта .jar "
                "(например, Doomsday) и JNativeHook. Проверьте каждый путь.",
                list(uniq.values())[:150], kb=["База/2. Программы/Nirsoft/WinPrefetchView"], tools=["WinPrefetchView"])
    if dll_ev:
        uniq = {e.text: e for e in dll_ev}
        ctx.add("MEDIUM", "Запуски", "Prefetch dllhost/rundll32/regsvr32: загружались файлы из пользовательских папок",
                "Так запускают DLL-читы (в т.ч. с изменённым расширением) — по dllhost находят Doomsday.",
                list(uniq.values())[:100], kb=["База/2. Программы/Nirsoft/WinPrefetchView"])
    for exe, last, count, f in cleanup:
        sev, desc = kb.CLEANUP_BINARIES[exe]
        if ctx.is_recent(last):
            sev = "CRITICAL" if sev in ("CRITICAL", "HIGH") else "HIGH"
        else:
            sev = {"CRITICAL": "MEDIUM", "HIGH": "MEDIUM", "MEDIUM": "LOW"}.get(sev, "INFO")
            if sev == "INFO":
                continue
        ctx.add(sev, "Чистка", f"Prefetch: запускался {exe}" + (" незадолго до проверки" if ctx.is_recent(last) else ""),
                desc + ". Сопоставьте время с другими событиями (журналы, USN).",
                [Evidence(f"{os.path.basename(f)}: последний запуск {fmt_dt(last)}, запусков {count}", path=f, time=last)],
                kb=["База/1. Артефакты/Prefetch"])
    multi = {n: h for n, h in by_name.items() if len(h) > 1 and n not in _MULTI_OK}
    if multi:
        ctx.add("LOW", "Запуски", "Prefetch: одно имя файла запускалось из разных папок",
                "Разные хэши у одного имени = разные пути запуска. Запишите имена и проверьте в других артефактах.",
                [Evidence(f"{n}: {len(h)} путей ({', '.join(sorted(h))})") for n, h in sorted(multi.items())][:60],
                kb=["База/1. Артефакты/Prefetch"])
    if oldest:
        if ctx.is_recent(oldest) and len(files) < 60:
            ctx.add("CRITICAL", "Чистка", "Prefetch очищали незадолго до проверки",
                    "Самый старый .pf-файл создан недавно, а самих файлов мало — папку Prefetch чистили.",
                    [Evidence(f"Файлов: {len(files)}, самый старый создан {fmt_dt(oldest)}", time=oldest)],
                    kb=["База/1. Артефакты/Prefetch"], tools=["PrefetchView++", "JournalTrace"])
        elif ctx.start - oldest < timedelta(hours=24) and len(files) < 80:
            ctx.add("HIGH", "Чистка", "Prefetch содержит записи только за последние сутки",
                    "Обычно Prefetch хранит историю за недели. Возможна очистка.",
                    [Evidence(f"Файлов: {len(files)}, самый старый создан {fmt_dt(oldest)}", time=oldest)],
                    kb=["База/1. Артефакты/Prefetch"])


_MULTI_OK = {"SVCHOST.EXE", "DLLHOST.EXE", "RUNDLL32.EXE", "BACKGROUNDTASKHOST.EXE", "CONHOST.EXE",
             "MSEDGE.EXE", "MSEDGEWEBVIEW2.EXE", "WERFAULT.EXE", "TASKHOSTW.EXE", "SETUP.EXE", "UPDATE.EXE",
             "INSTALL.EXE", "UNINS000.EXE", "MSIEXEC.EXE", "SEARCHPROTOCOLHOST.EXE", "SEARCHFILTERHOST.EXE",
             "MPCMDRUN.EXE", "MOUSOCOREWORKER.EXE", "JAVA.EXE", "JAVAW.EXE", "CMD.EXE", "POWERSHELL.EXE",
             "DISMHOST.EXE", "DRVINST.EXE", "WMIPRVSE.EXE", "SIHCLIENT.EXE", "NGEN.EXE", "NGENTASK.EXE",
             "MSCORSVW.EXE", "DOTNET.EXE", "ELEVATION_SERVICE.EXE", "CHROME.EXE", "DISCORD.EXE",
             "SQUIRREL.EXE", "STEAMSERVICE.EXE", "STEAMWEBHELPER.EXE", "MPSIGSTUB.EXE", "REGSVR32.EXE",
             "OPERA.EXE", "BROWSER.EXE", "FIREFOX.EXE", "OPERA_AUTOUPDATE.EXE", "AM_DELTA_PATCH.EXE"}


# ---------------------------------------------------------------------------
def _pca_files(ctx):
    d = os.path.join(WINDIR, "appcompat", "pca")
    rows = []
    found = False
    for name, parser, src in (("PcaAppLaunchDic.txt", parse_pca_launchdic, "PCA AppLaunchDic"),
                              ("PcaGeneralDb0.txt", parse_pca_generaldb, "PCA GeneralDb"),
                              ("PcaGeneralDb1.txt", parse_pca_generaldb, "PCA GeneralDb")):
        p = os.path.join(d, name)
        try:
            with open(p, "rb") as f:
                text = decode_text_file(f.read())
        except OSError:
            continue
        found = True
        for r in parser(text):
            path = normalize_path(r["path"])
            note = f"код выхода {r.get('exitcode')}" if r.get("exitcode") else ""
            ctx.add_exec(path, src, r["time"], note=note)
            rows.append([fmt_dt(r["time"]), path, src, r.get("desc", ""), r.get("exitcode", "")])
    rows.sort(key=lambda r: r[0], reverse=True)
    ctx.table("pca", "PCA (C:\\Windows\\appcompat\\pca) — запуски программ", ["Время", "Путь", "Файл", "Описание",
                                                                            "Код выхода"], rows)
    ctx.log.info(f"PCA: {len(rows)} записей" if found else "PCA-файлы не найдены (до Windows 11 их нет)")
    build = 0
    try:
        build = int(re.search(r"сборка (\d+)", ctx.system.get("os", "")).group(1))
    except (AttributeError, ValueError):
        pass
    if IS_WIN and build >= 22000 and not found and os.path.isdir(os.path.join(WINDIR, "appcompat")):
        ctx.add("HIGH", "Чистка", "Файлы PCA отсутствуют на Windows 11",
                "На Windows 11 в C:\\Windows\\appcompat\\pca должны быть PcaAppLaunchDic.txt и PcaGeneralDb*.txt. "
                "Их отсутствие — признак удаления или отключённой службы PcaSvc.",
                [Evidence(d, path=d)], kb=["База/1. Артефакты/PCA"])


def _java_launcher(ctx):
    candidates = [os.path.join(TEMP, "JavaLauncher.log"), os.path.join(LOCAL, "Temp", "JavaLauncher.log")]
    for p in dict.fromkeys(candidates):
        if not os.path.isfile(p):
            continue
        with open(p, "rb") as f:
            text = decode_text_file(f.read())
        mt = mtime_dt(p)
        lines = [l for l in text.splitlines() if l.strip()]
        jars = re.findall(r"([A-Za-z]:\\[^\"\r\n|<>]+?\.jar)", text, re.I)
        for j in jars:
            ctx.add_exec(j, "JavaLauncher.log", mt)
        ev = [Evidence(l[:400]) for l in lines[-60:]]
        hits = keyword_hits(text)
        sev = "CRITICAL" if any(s == "HIGH" for _, s in hits) else ("HIGH" if hits else "MEDIUM")
        if not jars and not hits:
            sev = "LOW"
        ctx.add(sev, "Minecraft", "Найден JavaLauncher.log — фиксация запуска Java-приложений",
                "Файл фиксирует запуск .jar-программ (так находят запуск Doomsday и других .jar-читов)."
                + (f" Совпадения: {hits_text(hits)}." if hits else ""),
                [Evidence(f"Файл изменён {fmt_dt(mt)}", path=p, time=mt)] + [Evidence(f"Запущен jar: {j}", path=j) for j in
                                                                             dict.fromkeys(jars)] + ev,
                kb=["База/4. Win+R/JavaLauncher.log"])


def _temp(ctx):
    if not TEMP or not os.path.isdir(TEMP):
        return
    jnh, arch = [], []
    try:
        entries = list(os.scandir(TEMP))
    except OSError:
        return
    for e in entries:
        n = e.name
        low = n.lower()
        if "jnativehook" in low:
            jnh.append(Evidence(f"{n} (изменён {fmt_dt(mtime_dt(e.path))})", path=e.path, time=mtime_dt(e.path)))
        if e.is_dir() and (low.startswith("rar$ex") or low.startswith("7z") or low.startswith("rar$di")):
            for root, dirs, files in os.walk(e.path):
                for fn in files:
                    if os.path.splitext(fn.lower())[1] in (".exe", ".jar", ".dll", ".bat", ".cmd"):
                        fp = os.path.join(root, fn)
                        hits = keyword_hits(fn, weak=True)
                        arch.append(Evidence(f"{fp}" + (f"  [совпадение: {hits_text(hits)}]" if hits else ""),
                                             path=fp, time=mtime_dt(fp)))
    if jnh:
        newest = max((x.time for x in jnh if x.time), default=None)
        ctx.add("HIGH" if ctx.is_recent(newest) else "MEDIUM", "Minecraft", "В %TEMP% найден JNativeHook",
                "JNativeHook — Java-библиотека перехвата клавиатуры и мыши, её используют .jar-читы и кликеры. "
                "Дата изменения файла соответствует времени запуска программы.", jnh,
                kb=["База/4. Win+R/Temp"], tools=["JournalTrace"])
    if arch:
        ctx.add("HIGH" if any("совпадение" in x.text for x in arch) else "MEDIUM", "Запуски",
                "Из архивов запускались исполняемые файлы (Rar$EX / 7z в %TEMP%)",
                "При запуске файла прямо из архива он распаковывается во временную папку.", arch[:80],
                kb=["База/4. Win+R/Temp", "База/2. Программы/System Informer/Explorer (ms-shellactivity)"])
        for x in arch:
            ctx.add_exec(x.path, "Запуск из архива (Temp)", x.time)


def _ps_history(ctx):
    p = os.path.join(ROAMING, "Microsoft", "Windows", "PowerShell", "PSReadLine", "ConsoleHost_history.txt")
    if not os.path.isfile(p):
        ctx.log.info("История PowerShell (ConsoleHost_history.txt) отсутствует")
        return
    mt = mtime_dt(p)
    with open(p, "rb") as f:
        lines = decode_text_file(f.read()).splitlines()
    ev = []
    worst = "LOW"
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    for i, line in enumerate(lines):
        for sev, desc, m in suspicious_commands(line):
            ev.append(Evidence(f"#{i + 1}: {line.strip()[:300]}  ← {desc}",
                               time=mt if i == len(lines) - 1 else None))
            if order.index(sev) < order.index(worst):
                worst = sev
        hits = keyword_hits(line)
        if hits and any(s == "HIGH" for _, s in hits):
            ev.append(Evidence(f"#{i + 1}: {line.strip()[:300]}  ← названия читов: {hits_text(hits)}"))
            worst = "CRITICAL" if worst != "CRITICAL" else worst
    ctx.table("pshistory", f"История PowerShell (последняя команда {fmt_dt(mt)})", ["#", "Команда"],
              [[i + 1, l] for i, l in enumerate(lines[-200:], start=max(0, len(lines) - 200))])
    if ev:
        ctx.add(worst, "Команды", "История PowerShell содержит команды обхода/чистки",
                "ConsoleHost_history.txt хранит введённые команды (без времени; время последней — дата файла "
                f"{fmt_dt(mt)}).", [Evidence("Файл истории", path=p, time=mt)] + ev,
                kb=["База/4. Win+R/Powershell History"])
    if ctx.is_recent(mt):
        ctx.log.info(f"История PowerShell менялась незадолго до проверки ({fmt_dt(mt)})")


def _recent(ctx):
    d = os.path.join(ROAMING, "Microsoft", "Windows", "Recent")
    files = glob.glob(os.path.join(d, "*.lnk"))
    rows, kw, usb, exe = [], [], [], []
    for f in files:
        try:
            with open(f, "rb") as fh:
                info = parse_lnk(fh.read(65536))
        except OSError:
            continue
        if not info:
            continue
        mt = mtime_dt(f)
        target = normalize_path(info["target"]) or os.path.basename(f)[:-4]
        exists = path_exists(target)
        rows.append([fmt_dt(mt), target, info["drive_type"], info["label"], "да" if exists else ("нет" if exists is False else "?")])
        ctx.add_exec(target, "Recent (.lnk)", mt, kind="access")
        sev, e = _kw_ev(target, path=target, t=mt, source=os.path.basename(f))
        if e:
            kw.append((sev, e))
        ext = os.path.splitext(target.lower())[1]
        if ext in (".exe", ".jar", ".bat", ".cmd", ".dll", ".ahk", ".ps1", ".vbs"):
            exe.append(Evidence(f"{target}" + ("" if exists else "  (файл удалён)"), path=target, time=mt))
        if "СЪЁМ" in info["drive_type"] or info["net"]:
            usb.append(Evidence(f"{target} — {info['drive_type'] or 'сеть'} {info['label']} серийный {info['serial']}",
                                path=target, time=mt))
    rows.sort(key=lambda r: r[0], reverse=True)
    ctx.table("recent", f"Recent — ярлыки недавних файлов ({len(rows)})", ["Ярлык изменён", "Цель", "Тип диска",
                                                                            "Метка тома", "Существует"], rows)
    if kw:
        ctx.add("CRITICAL" if any(s == "HIGH" for s, _ in kw) else "HIGH", "Файлы",
                "Recent: открывались файлы/папки с названиями читов",
                "Ярлыки в папке Recent показывают, что файл попал в поле зрения системы (открыт/сохранён/выбран).",
                [e for _, e in kw], kb=["База/1. Артефакты/Recent", "База/4. Win+R/Recent"])
    if exe:
        newest = max((x.time for x in exe if x.time), default=None)
        ctx.add("MEDIUM" if ctx.is_recent(newest) else "LOW", "Файлы",
                "Recent: открывались исполняемые файлы/скрипты (.exe/.jar/.bat…)",
                "Список для ручной проверки. Удалённые файлы особенно интересны.", exe[:100],
                kb=["База/1. Артефакты/Recent"])
    if usb:
        ctx.add("MEDIUM", "USB", "Recent: открывались файлы со съёмных/сетевых носителей",
                "Читы часто держат на флешке, чтобы их не было на диске при проверке.", usb[:100],
                kb=["База/1. Артефакты/USB", "Обходы/Различные методы/FAT32"])
    if IS_WIN and len(files) < 5:
        ctx.add("MEDIUM", "Чистка", "Папка Recent почти пустая",
                f"В Recent всего {len(files)} ярлыков — её могли очистить (очистка Recent очищает и RecentDocs).",
                [Evidence(d, path=d, time=mtime_dt(d))], kb=["База/1. Артефакты/Recent"])


_PATH_IN_STR = re.compile(r"[A-Za-z]:\\[^\x00\"<>|*?\r\n]{3,260}")


def _jumplists(ctx):
    base = os.path.join(ROAMING, "Microsoft", "Windows", "Recent")
    files = glob.glob(os.path.join(base, "AutomaticDestinations", "*.automaticDestinations-ms")) + \
        glob.glob(os.path.join(base, "CustomDestinations", "*.customDestinations-ms"))
    kw, exe = {}, {}
    total = 0
    for f in files:
        try:
            with open(f, "rb") as fh:
                data = fh.read(8 << 20)
        except OSError:
            continue
        mt = mtime_dt(f)
        for s in utf16_strings(data, 6):
            for m in _PATH_IN_STR.finditer(s):
                p = m.group(0).strip()
                total += 1
                ctx.add_exec(p, "JumpLists", None, kind="access", note=os.path.basename(f))
                sev, e = _kw_ev(p, path=p, t=mt, source=os.path.basename(f))
                if e:
                    kw[p] = (sev, e)
                if os.path.splitext(p.lower())[1] in (".exe", ".jar", ".bat", ".dll"):
                    exe[p] = Evidence(p, path=p, source=os.path.basename(f))
    ctx.log.info(f"JumpLists: {len(files)} файлов, {total} путей")
    if kw:
        ctx.add("CRITICAL" if any(s == "HIGH" for s, _ in kw.values()) else "HIGH", "Файлы",
                "JumpLists: история обращений к файлам с названиями читов",
                "JumpLists хранят историю доступа к файлам и папкам, в том числе переименованным и удалённым.",
                [e for _, e in kw.values()], kb=["База/1. Артефакты/JumpLists"], tools=["JumpList Explorer"])


def _recycle(ctx):
    rows, flagged, kw = [], [], []
    for root, _ in drives((2, 3)):
        rb = os.path.join(root, "$Recycle.Bin")
        try:
            sids = os.listdir(rb)
        except OSError:
            continue
        for sid in sids:
            sd = os.path.join(rb, sid)
            if not os.path.isdir(sd):
                continue
            folder_mtime = mtime_dt(sd)
            items = []
            for f in glob.glob(os.path.join(sd, "$I*")):
                try:
                    with open(f, "rb") as fh:
                        info = parse_recycle_i(fh.read(2048))
                except OSError:
                    continue
                if not info:
                    continue
                r_exists = os.path.exists(os.path.join(sd, "$R" + os.path.basename(f)[2:]))
                items.append(info)
                rows.append([fmt_dt(info["deleted"]), info["path"], info["size"], "да" if r_exists else "нет", sid])
                ctx.add_exec(info["path"], "Корзина ($I)", info["deleted"], kind="access", note="удалён в корзину")
                sev, e = _kw_ev(info["path"], path=info["path"], t=info["deleted"], source="$Recycle.Bin")
                if e:
                    kw.append((sev, e))
                if os.path.splitext(info["path"].lower())[1] in kb.INTERESTING_EXTS and ctx.is_recent(info["deleted"]):
                    flagged.append(Evidence(f"{info['path']} ({info['size']} байт)", path=info["path"], time=info["deleted"]))
            newest = max((i["deleted"] for i in items if i["deleted"]), default=None)
            if folder_mtime and ctx.is_recent(folder_mtime) and (not newest or (folder_mtime - newest).total_seconds() > 60):
                ctx.add("HIGH", "Чистка", f"Корзина на диске {root} очищена незадолго до проверки",
                        "Дата изменения папки корзины пользователя — дата последней очистки. Очистка корзины прямо "
                        "перед проверкой — самый простой способ спрятать читы.",
                        [Evidence(f"{sd}: изменена {fmt_dt(folder_mtime)}; файлов в корзине: {len(items)}",
                                  path=sd, time=folder_mtime)],
                        kb=["Обходы/Обнаружение чистки/Чистка Корзины", "База/1. Артефакты/Корзина"],
                        tools=["JournalTrace"])
            elif folder_mtime:
                ctx.log.info(f"Корзина {sd}: файлов {len(items)}, последнее изменение {fmt_dt(folder_mtime)}")
    rows.sort(key=lambda r: r[0], reverse=True)
    ctx.table("recycle", "Корзина ($Recycle.Bin)", ["Удалён", "Исходный путь", "Размер", "Файл ещё в корзине", "SID"], rows)
    if kw:
        ctx.add("CRITICAL" if any(s == "HIGH" for s, _ in kw) else "HIGH", "Файлы",
                "В корзину удалялись файлы с названиями читов", "Записи $I хранят исходный путь и время удаления.",
                [e for _, e in kw], kb=["База/1. Артефакты/Корзина"])
    if flagged:
        ctx.add("HIGH", "Чистка", "Незадолго до проверки в корзину удалялись исполняемые файлы/архивы",
                "Удаление .exe/.jar/.dll/.zip прямо перед проверкой.", flagged, kb=["База/1. Артефакты/Корзина"])


def _tasks(ctx):
    base = os.path.join(WINDIR, "System32", "Tasks")
    if not os.path.isdir(base):
        return
    rows, sus = [], []
    for root, dirs, files in os.walk(base):
        for fn in files:
            p = os.path.join(root, fn)
            try:
                with open(p, "rb") as f:
                    raw = f.read(256 * 1024)
                tree = ET.fromstring(raw)
            except (OSError, ET.ParseError):
                continue
            ns = ""
            if tree.tag.startswith("{"):
                ns = tree.tag.split("}")[0] + "}"
            cmds = []
            for ex in tree.iter(ns + "Exec"):
                c = (ex.findtext(ns + "Command") or "").strip()
                a = (ex.findtext(ns + "Arguments") or "").strip()
                cmds.append((c, a))
            hidden = (tree.findtext(f"{ns}Settings/{ns}Hidden") or "").lower() == "true"
            author = tree.findtext(f"{ns}RegistrationInfo/{ns}Author") or ""
            created = ctime_dt(p)
            rel = os.path.relpath(p, base)
            for c, a in cmds:
                full = f"{c} {a}".strip()
                rows.append([rel, full, author, fmt_dt(created), "да" if hidden else ""])
                cp = normalize_path(os.path.expandvars(c))
                reasons = []
                hits = keyword_hits(full, weak=True)
                if hits:
                    reasons.append(("HIGH", f"названия читов: {hits_text(hits)}"))
                if re.search(r"\\users\\|\\temp\\|\\downloads\\|\\desktop\\", cp, re.I) and \
                        not re.search(r"onedrive|microsoft|google|mozilla|opera|yandex|discord|nvidia|steam|epic|"
                                      r"spotify|telegram|zoom|teams|dropbox|brave|vivaldi", cp, re.I):
                    reasons.append(("LOW", "исполняемый файл в пользовательской папке"))
                if re.search(r"(cmd|powershell|pwsh|wscript|cscript|mshta|javaw?|rundll32|regsvr32)(\.exe)?$", c, re.I) \
                        and re.search(r"\\users\\|\\temp\\|-enc|-e |\.jar|\.ps1|\.vbs|\.bat|http", a, re.I):
                    reasons.append(("MEDIUM", "задача запускает интерпретатор со скриптом/jar"))
                for sev, desc, m in suspicious_commands(full):
                    if sev in ("CRITICAL", "HIGH"):
                        reasons.append((sev, desc))
                if created and ctx.is_recent(created) and reasons:
                    reasons.append(("HIGH", "задача создана незадолго до проверки"))
                if hidden and reasons:
                    reasons.append(("MEDIUM", "задача скрыта (Hidden)"))
                if reasons:
                    sus.append((reasons, Evidence(f"\\{rel}: {full}  ← " + "; ".join(r for _, r in reasons),
                                                  path=cp, time=created)))
    ctx.table("tasks", "Планировщик задач (C:\\Windows\\System32\\Tasks)", ["Задача", "Действие", "Автор",
                                                                            "Файл создан", "Скрыта"], rows)
    if sus:
        order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        sev = min((s for rs, _ in sus for s, _ in rs), key=order.index)
        ctx.add(sev, "Автозагрузка", "Подозрительные задачи планировщика",
                "Через планировщик запускают читы/чистильщики по триггеру. Важна не сама задача, а её окружение: "
                "где лежит файл, когда задача создана и что она запускает.",
                [e for _, e in sorted(sus, key=lambda x: min(order.index(s) for s, _ in x[0]))][:80],
                kb=["База/1. Артефакты/Планировщик задач", "Обходы/Различные методы/TaskScheduler"],
                tools=["Autoruns", "RedLotus TaskSentinel"])


def _usage_logs(ctx):
    dirs = [os.path.join(LOCAL, "Microsoft", "CLR_v4.0", "UsageLogs"),
            os.path.join(LOCAL, "Microsoft", "CLR_v4.0_32", "UsageLogs"),
            os.path.join(WINDIR, "System32", "config", "systemprofile", "AppData", "Local", "Microsoft", "CLR_v4.0", "UsageLogs"),
            os.path.join(WINDIR, "SysWOW64", "config", "systemprofile", "AppData", "Local", "Microsoft", "CLR_v4.0_32", "UsageLogs")]
    rows = []
    for d in dirs:
        for f in glob.glob(os.path.join(d, "*.log")):
            name = os.path.basename(f)[:-4]
            mt = mtime_dt(f)
            rows.append([fmt_dt(mt), name, d])
            ctx.add_exec(name, "CLR UsageLogs (.NET-приложения)", mt, note="время закрытия приложения")
    rows.sort(key=lambda r: r[0], reverse=True)
    ctx.table("usagelogs", "UsageLogs — запуски .NET-приложений (C#)", ["Закрыто", "Программа", "Папка"], rows)


def _crashdumps(ctx):
    d = os.path.join(LOCAL, "CrashDumps")
    rows = []
    for f in glob.glob(os.path.join(d, "*.dmp")):
        name = os.path.basename(f).split(".")[0]
        mt = mtime_dt(f)
        rows.append([fmt_dt(mt), os.path.basename(f), os.path.getsize(f)])
        ctx.add_exec(name + ".exe", "CrashDumps", mt, note="аварийное завершение")
    ctx.table("crashdumps", "CrashDumps — дампы упавших программ", ["Время", "Файл", "Размер"], rows)


def _activities(ctx):
    base = os.path.join(LOCAL, "ConnectedDevicesPlatform")
    dbs = glob.glob(os.path.join(base, "*", "ActivitiesCache.db"))
    if not dbs:
        ctx.log.info("ActivitiesCache.db не найден (Timeline отключён)")
        return
    n = 0
    for db in dbs:
        tmpd = tempfile.mkdtemp(prefix="ss_ac_")
        try:
            for suffix in ("", "-wal", "-shm"):
                if os.path.exists(db + suffix):
                    try:
                        shutil.copy2(db + suffix, os.path.join(tmpd, "a.db" + suffix))
                    except OSError:
                        pass
            con = sqlite3.connect(os.path.join(tmpd, "a.db"))
            try:
                for table in ("Activity", "ActivityOperation"):
                    try:
                        cur = con.execute(f"SELECT AppId, Payload, StartTime, LastModifiedTime FROM {table}")
                    except sqlite3.Error:
                        continue
                    for app_id, payload, start, lastmod in cur:
                        t = unix_to_dt(start or lastmod)
                        paths = []
                        try:
                            for item in json.loads(app_id or "[]"):
                                app = item.get("application", "")
                                if item.get("platform") in ("x_exe_path", "windows_win32") and ("\\" in app or app.endswith(".exe")):
                                    paths.append(app)
                        except (ValueError, AttributeError, TypeError):
                            pass
                        for p in dict.fromkeys(paths):
                            ctx.add_exec(normalize_path(p), "ActivitiesCache (Timeline)", t)
                            n += 1
            finally:
                con.close()
        except sqlite3.Error as e:
            ctx.log.warn(f"ActivitiesCache: {e}")
        finally:
            shutil.rmtree(tmpd, ignore_errors=True)
    ctx.log.info(f"ActivitiesCache: {n} записей о запусках")


def _hosts(ctx):
    p = os.path.join(WINDIR, "System32", "drivers", "etc", "hosts")
    try:
        with open(p, "rb") as f:
            text = decode_text_file(f.read())
    except OSError:
        return
    entries = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) >= 2:
            for host in parts[1:]:
                entries.append((parts[0], host))
    tool = [(ip, h) for ip, h in entries if any(d in h.lower() for d in kb.SS_TOOL_DOMAINS)]
    if tool:
        ctx.add("CRITICAL", "Обходы", "В hosts заблокированы сайты с программами для проверки",
                "Файл hosts перенаправляет домены (обычно на 127.0.0.1/0.0.0.0) — так блокируют скачивание "
                "System Informer, Everything, утилит Zimmerman/Nirsoft.",
                [Evidence(f"{ip} {h}", url=f"https://{h}") for ip, h in tool], kb=["Обходы/Различные методы/Запрет Хостингов"])
    other = [(ip, h) for ip, h in entries if (ip, h) not in tool and h.lower() not in ("localhost", "localhost.localdomain")]
    if other:
        ctx.add("LOW", "Сеть", "В hosts есть пользовательские записи",
                "Список для ручной проверки.", [Evidence(f"{ip} {h}") for ip, h in other[:100]],
                kb=["Обходы/Различные методы/Запрет Хостингов"])
