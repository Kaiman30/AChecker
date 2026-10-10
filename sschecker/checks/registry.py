"""Артефакты реестра (База → 6. Реестр, 1. Артефакты, Обходы)."""
import os
import re
import struct

from .. import kb
from ..core import Evidence, fmt_dt
from ..match import hits_text, keyword_hits, suspicious_commands, top_severity
from ..parsers import parse_shimcache, parse_userassist, utf16_strings
from ..winutil import (IS_WIN, filetime_to_dt, normalize_path, reg_get, reg_last_write,
                       reg_open, reg_subkeys, reg_values)

if IS_WIN:
    import winreg

EXPLORER = r"Software\Microsoft\Windows\CurrentVersion\Explorer"


def run_check(ctx):
    if not IS_WIN:
        ctx.log.warn("Не Windows — проверка реестра пропущена")
        return
    for fn in (_bam, _userassist, _shimcache, _compat_store, _muicache, _feature_usage, _radar,
               _runmru, _typed_paths, _wordwheel, _recentdocs, _opensave, _autoruns, _policies,
               _prefetcher, _archivers, _openwith, _url_protocols, _zonemap, _usb, _uninstall,
               _browsers):
        try:
            fn(ctx)
        except Exception as e:  # noqa
            ctx.log.error(f"{fn.__name__}: {e}")
            ctx.errors.append(f"registry.{fn.__name__}: {e}")


def _kw_finding(ctx, items, category, title, desc, kbref, tools=None):
    """items: [(текст, путь, время)] — общий отчёт по совпадениям с базой читов."""
    ev, sev = [], "INFO"
    order = ["INFO", "LOW", "MEDIUM", "HIGH"]
    for text, path, t in items:
        hits = keyword_hits(text, weak=True)
        if not hits:
            continue
        s = top_severity(hits)
        if order.index(s) > order.index(sev):
            sev = s
        ev.append(Evidence(f"{text}  [совпадение: {hits_text(hits)}]", path=path, time=t))
    if ev:
        sev = {"HIGH": "CRITICAL", "MEDIUM": "HIGH", "LOW": "MEDIUM"}.get(sev, sev)
        ctx.add(sev, category, title, desc, ev, kb=kbref, tools=tools or [])
    return ev


# ---------------------------------------------------------------------------
def _bam(ctx):
    rows = []
    for base in (r"SYSTEM\CurrentControlSet\Services\bam\State\UserSettings",
                 r"SYSTEM\CurrentControlSet\Services\bam\UserSettings"):
        root = reg_open("HKLM", base)
        if root is None:
            continue
        for sid in reg_subkeys(root):
            k = reg_open("HKLM", base + "\\" + sid)
            last_write = reg_last_write(k)
            newest = None
            for name, data, typ in reg_values(k):
                if typ != winreg.REG_BINARY or not isinstance(data, bytes) or len(data) < 8:
                    continue
                t = filetime_to_dt(struct.unpack_from("<Q", data, 0)[0])
                path = normalize_path(name)
                if "\\" not in path:
                    continue  # UWP-приложения
                ctx.add_exec(path, "BAM", t, note=f"SID {sid}")
                rows.append([fmt_dt(t), path, sid])
                if t and (newest is None or t > newest):
                    newest = t
            # Чистка реестра: раздел менялся позже последней записи → записи удаляли
            if last_write and newest and (last_write - newest).total_seconds() > 120:
                sev = "HIGH" if ctx.is_recent(last_write) else "LOW"
                ctx.add(sev, "Чистка", "BAM: раздел пользователя изменён позже последней записи",
                        "Дата изменения раздела BAM не совпадает с самой свежей записью — из него могли удалять "
                        "значения (reg delete / ручная чистка). Это только косвенный признак: Windows тоже "
                        "периодически чистит BAM.",
                        [Evidence(f"Раздел {sid} изменён: {fmt_dt(last_write)}", time=last_write),
                         Evidence(f"Последняя запись в разделе: {fmt_dt(newest)}", time=newest)],
                        kb=["Обходы/Обнаружение чистки/Чистка Реестра", "База/1. Артефакты/BAM"],
                        tools=["Registry Explorer", "BAM Parser (RedLotus)"])
        break
    rows.sort(key=lambda r: r[0], reverse=True)
    ctx.table("bam", "BAM — последние запуски .exe", ["Время", "Путь", "SID"], rows)
    ctx.log.info(f"BAM: {len(rows)} записей")


def _userassist(ctx):
    root = reg_open("HKCU", EXPLORER + r"\UserAssist")
    rows = []
    for guid in reg_subkeys(root):
        k = reg_open("HKCU", EXPLORER + rf"\UserAssist\{guid}\Count")
        for name, data, typ in reg_values(k):
            if not isinstance(data, bytes):
                continue
            ua = parse_userassist(name, data)
            path = normalize_path(ua["path"])
            if path.upper().startswith("UEME_"):
                continue
            ctx.add_exec(path, "UserAssist", ua["last"], note=f"запусков: {ua['count']}",
                         kind="exec" if path.lower().endswith((".exe", ".lnk", ".bat", ".cmd")) else "access")
            rows.append([fmt_dt(ua["last"]), path, ua["count"]])
    rows.sort(key=lambda r: r[0], reverse=True)
    ctx.table("userassist", "UserAssist — запуски через проводник/меню Пуск", ["Время", "Путь", "Запусков"], rows)
    ctx.log.info(f"UserAssist: {len(rows)} записей")


def _shimcache(ctx):
    data = reg_get("HKLM", r"SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache", "AppCompatCache")
    if not isinstance(data, bytes):
        ctx.log.warn("ShimCache недоступен")
        return
    entries = parse_shimcache(data)
    rows = []
    for e in entries:
        path = normalize_path(e["path"])
        ctx.add_exec(path, "ShimCache", None, note=f"дата изменения файла: {fmt_dt(e['mtime'])}")
        rows.append([path, fmt_dt(e["mtime"])])
    ctx.table("shimcache", "ShimCache (AppCompatCache) — исполняемые файлы, к которым обращалась система",
              ["Путь", "Дата изменения файла"], rows,
              note="Время в ShimCache — дата изменения файла на диске, а не время запуска.")
    ctx.log.info(f"ShimCache: {len(rows)} записей")


def _compat_store(ctx):
    n = 0
    for hive, path, src in (
            ("HKCU", r"Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store",
             "Compatibility Assistant Store"),
            ("HKCU", r"Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers", "AppCompatFlags Layers"),
            ("HKLM", r"Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers", "AppCompatFlags Layers"),
            ("HKCU", r"Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom", "AppCompatFlags Custom"),
            ("HKLM", r"Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Persisted",
             "AppCompatFlags Persisted")):
        k = reg_open(hive, path)
        for name, data, typ in reg_values(k):
            if "\\" in name:
                ctx.add_exec(normalize_path(name), src)
                n += 1
        for sub in reg_subkeys(k):
            if "\\" in sub or sub.lower().endswith(".exe"):
                ctx.add_exec(normalize_path(sub), src)
                n += 1
    ctx.log.info(f"AppCompatFlags/PCA Store: {n} записей")


def _muicache(ctx):
    n = 0
    for path in (r"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache",
                 r"Software\Microsoft\Windows\ShellNoRoam\MUICache"):
        k = reg_open("HKCU", path)
        for name, data, typ in reg_values(k):
            m = re.match(r"^(.+?\.\w{1,5})\.(FriendlyAppName|ApplicationCompany)$", name)
            if m:
                ctx.add_exec(normalize_path(m.group(1)), "MuiCache", note=str(data)[:80])
                n += 1
    ctx.log.info(f"MuiCache: {n} записей")


def _feature_usage(ctx):
    for sub, src in (("AppSwitched", "FeatureUsage AppSwitched"), ("ShowJumpView", "FeatureUsage ShowJumpView"),
                     ("AppLaunch", "FeatureUsage AppLaunch")):
        k = reg_open("HKCU", EXPLORER + rf"\FeatureUsage\{sub}")
        for name, data, typ in reg_values(k):
            if "\\" in name:
                ctx.add_exec(normalize_path(name), src, note=f"счётчик: {data}")


def _radar(ctx):
    base = r"SOFTWARE\Microsoft\RADAR\HeapLeakDetection\DiagnosedApplications"
    k = reg_open("HKLM", base)
    for app in reg_subkeys(k):
        t = reg_get("HKLM", base + "\\" + app, "LastDetectionTime", 0)
        dt = filetime_to_dt(t) if isinstance(t, int) else None
        ctx.add_exec(app, "RADAR HeapLeakDetection", dt)


def _runmru(ctx):
    k = reg_open("HKCU", EXPLORER + r"\RunMRU")
    order = ""
    items = {}
    for name, data, typ in reg_values(k):
        if name == "MRUList":
            order = str(data)
        elif isinstance(data, str):
            items[name] = data.rsplit("\\1", 1)[0]
    cmds = [items[c] for c in order if c in items] or list(items.values())
    lw = reg_last_write(k)
    rows = []
    for i, c in enumerate(cmds):
        rows.append([i + 1, c])
        for sev, desc, m in suspicious_commands(c):
            ctx.add(sev, "Команды", f"Win+R: выполнялась команда «{desc}»",
                    "В истории окна «Выполнить» (RunMRU) найдена команда из списка обходов.",
                    [Evidence(c, time=lw if i == 0 else None, source=r"HKCU\...\Explorer\RunMRU")],
                    kb=["База/6. Реестр/RunMRU"])
        p = normalize_path(c)
        if re.match(r"^[A-Za-z]:\\.+\.\w+$", p):
            ctx.add_exec(p, "RunMRU (Win+R)", lw if i == 0 else None)
    _kw_finding(ctx, [(c, None, None) for c in cmds], "Команды", "Win+R: запуск/открытие объектов с названиями читов",
                "История RunMRU содержит пути/команды с названиями читов.", ["База/6. Реестр/RunMRU"])
    ctx.table("runmru", f"Win+R (RunMRU), последнее изменение {fmt_dt(lw)}", ["#", "Команда"], rows)


def _typed_paths(ctx):
    k = reg_open("HKCU", EXPLORER + r"\TypedPaths")
    vals = [(n, d) for n, d, t in reg_values(k) if isinstance(d, str)]
    vals.sort(key=lambda x: int(re.sub(r"\D", "", x[0]) or 0))
    lw = reg_last_write(k)
    rows = [[n, d] for n, d in vals]
    ctx.table("typedpaths", f"Пути, введённые в адресной строке Проводника (изменено {fmt_dt(lw)})",
              ["#", "Путь"], rows)
    _kw_finding(ctx, [(d, normalize_path(d), None) for n, d in vals], "Навигация",
                "Проводник: вручную вводились пути с названиями читов",
                "TypedPaths хранит адреса, введённые в строку Проводника.", ["База/6. Реестр/Typed Paths"])
    for n, d in vals:
        if re.search(r"prefetch|\$recycle|appcompat|\\tasks|usnjrnl", d, re.I):
            ctx.add("LOW", "Навигация", "Проводник: вручную открывались системные папки с артефактами",
                    "Игрок переходил в папку, где хранятся артефакты проверки (Prefetch, корзина, задачи). "
                    "Сопоставьте время с другими событиями.", [Evidence(d, time=lw)],
                    kb=["База/6. Реестр/Typed Paths"])
            break


def _wordwheel(ctx):
    k = reg_open("HKCU", EXPLORER + r"\WordWheelQuery")
    terms = []
    for name, data, typ in reg_values(k):
        if name.isdigit() and isinstance(data, bytes):
            terms.append(data.decode("utf-16-le", errors="ignore").split("\x00", 1)[0])
    lw = reg_last_write(k)
    ctx.table("wordwheel", f"Поиск в Проводнике (WordWheelQuery), изменено {fmt_dt(lw)}", ["Запрос"],
              [[t] for t in terms])
    _kw_finding(ctx, [(t, None, None) for t in terms], "Навигация", "Поиск в Проводнике по названиям читов",
                "Игрок искал файлы с названиями читов через поиск Проводника.",
                ["База/6. Реестр/ExplorerHistory"])


def _recentdocs(ctx):
    base = EXPLORER + r"\RecentDocs"
    rows = []
    root = reg_open("HKCU", base)
    for sub in [""] + reg_subkeys(root):
        k = reg_open("HKCU", base + ("\\" + sub if sub else ""))
        lw = reg_last_write(k)
        for name, data, typ in reg_values(k):
            if name == "MRUListEx" or not isinstance(data, bytes):
                continue
            fname = data.decode("utf-16-le", errors="ignore").split("\x00", 1)[0]
            if fname:
                rows.append([sub or "(все)", fname, fmt_dt(lw)])
    ctx.table("recentdocs", "RecentDocs — недавно открытые файлы/папки", ["Тип", "Имя", "Раздел изменён"], rows)
    _kw_finding(ctx, [(r[1], None, None) for r in rows], "Файлы",
                "RecentDocs: открывались файлы с названиями читов",
                "Зеркало папки Recent в реестре хранит имена недавно открытых файлов.",
                ["База/6. Реестр/RecentDocs", "База/1. Артефакты/Recent"])
    exe_like = [r for r in rows if re.search(r"\.(jar|exe|dll|bat|cmd|ahk|ps1|vbs)$", r[1], re.I) and r[0] == "(все)"]
    for r in exe_like:
        ctx.add_exec(r[1], "RecentDocs", None, kind="access")


def _opensave(ctx):
    rows = []
    for sub in ("OpenSavePidlMRU", "LastVisitedPidlMRU", "OpenSaveMRU", "LastVisitedMRU"):
        base = EXPLORER + rf"\ComDlg32\{sub}"
        root = reg_open("HKCU", base)
        for ext in [""] + reg_subkeys(root):
            k = reg_open("HKCU", base + ("\\" + ext if ext else ""))
            for name, data, typ in reg_values(k):
                if name.startswith("MRUList") or not isinstance(data, bytes):
                    continue
                strs = [s for s in utf16_strings(data, 3) if "." in s or "\\" in s]
                if strs:
                    rows.append([sub, ext or "*", " | ".join(dict.fromkeys(strs))[:300]])
    ctx.table("opensave", "Диалоги «Открыть/Сохранить» (ComDlg32)", ["Раздел", "Расширение", "Имена/пути"], rows)
    _kw_finding(ctx, [(r[2], None, None) for r in rows], "Файлы",
                "Через окна «Открыть/Сохранить» выбирались файлы с названиями читов",
                "OpenSavePidlMRU хранит файлы, выбранные в стандартных диалогах (в т.ч. в лаунчерах/инжекторах).",
                ["База/6. Реестр/OpenSavePIDMRU"])


def _autoruns(ctx):
    rows = []
    for hive, path in (("HKLM", r"Software\Microsoft\Windows\CurrentVersion\Run"),
                       ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run"),
                       ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
                       ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
                       ("HKLM", r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run")):
        for name, data, typ in reg_values(reg_open(hive, path)):
            rows.append([f"{hive}\\{path}", name, str(data)])
    ctx.table("autoruns", "Автозагрузка (Run/RunOnce)", ["Ключ", "Имя", "Команда"], rows)
    _kw_finding(ctx, [(f"{r[1]} → {r[2]}", None, None) for r in rows], "Автозагрузка",
                "В автозагрузке программы с названиями читов", "Ключи Run/RunOnce.",
                ["База/6. Реестр/System Autorun"], tools=["Autoruns"])
    for r in rows:
        for sev, desc, m in suspicious_commands(r[2]):
            if sev in ("CRITICAL", "HIGH"):
                ctx.add(sev, "Автозагрузка", f"Автозагрузка выполняет подозрительную команду: {desc}",
                        "При входе в систему автоматически выполняется команда из списка обходов.",
                        [Evidence(f"{r[0]} → {r[1]} = {r[2]}")], kb=["База/6. Реестр/System Autorun"])
    for hive in ("HKLM", "HKCU"):
        v = reg_get(hive, r"Software\Microsoft\Command Processor", "AutoRun", "")
        if v:
            ctx.add("HIGH", "Обходы", f"CMD AutoRun ({hive}): команда выполняется при каждом запуске cmd.exe",
                    "Через AutoRun можно скрыто выполнять команды при открытии консоли проверяющим "
                    "(например, менять цвета, очищать вывод, запускать скрипты).",
                    [Evidence(f"{hive}\\Software\\Microsoft\\Command Processor\\AutoRun = {v}")],
                    kb=["База/6. Реестр/CMD Autorun", "Обходы/Различные методы/Empty CMD"])


def _policies(ctx):
    # Запрет открытия приложений (gpedit → «Не запускать указанные приложения»)
    for hive in ("HKCU", "HKLM"):
        base = r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
        enabled = reg_get(hive, base, "DisallowRun", 0)
        lst = [str(d) for n, d, t in reg_values(reg_open(hive, base + r"\DisallowRun"))]
        if enabled or lst:
            blocked_tools = [x for x in lst if any(t in x.lower() for t in kb.SS_TOOL_NAMES)]
            ctx.add("CRITICAL" if blocked_tools else "HIGH", "Обходы",
                    f"Политика DisallowRun запрещает запуск программ ({hive})",
                    "Через gpedit/реестр запрещён запуск приложений. Так блокируют программы для проверки "
                    "(System Informer, Everything и т.п.).",
                    [Evidence(f"{x}" + ("  ← инструмент проверки" if x in blocked_tools else "")) for x in lst]
                    or [Evidence(f"DisallowRun = {enabled}")],
                    kb=["База/6. Реестр/DisallowRun Policy", "Обходы/Различные методы/Запрет открытия приложений"])
    checks = [
        ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Policies\System", "DisableTaskMgr", "Диспетчер задач запрещён"),
        ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Policies\System", "DisableRegistryTools", "Редактор реестра запрещён"),
        ("HKCU", r"Software\Policies\Microsoft\Windows\System", "DisableCMD", "Командная строка запрещена"),
        ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\Policies\System", "DisableTaskMgr", "Диспетчер задач запрещён"),
        ("HKLM", r"Software\Policies\Microsoft\Windows\System", "DisableCMD", "Командная строка запрещена"),
    ]
    for hive, path, name, desc in checks:
        v = reg_get(hive, path, name, 0)
        if v:
            ctx.add("HIGH", "Обходы", f"{desc} политикой ({hive})",
                    "Пользователь может запрещать доступ к системным утилитам, чтобы помешать проверке.",
                    [Evidence(f"{hive}\\{path}\\{name} = {v}")], kb=["База/4. Win+R/gpedit"])
    # IFEO Debugger: подмена запуска инструментов проверки
    base = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
    ev = []
    for exe in reg_subkeys(reg_open("HKLM", base)):
        dbg = reg_get("HKLM", base + "\\" + exe, "Debugger", "")
        if dbg:
            tool = any(t in exe.lower() for t in kb.SS_TOOL_NAMES)
            ev.append((tool, Evidence(f"{exe} → Debugger = {dbg}" + ("  ← инструмент проверки" if tool else ""))))
    if ev:
        any_tool = any(t for t, _ in ev)
        ctx.add("CRITICAL" if any_tool else "MEDIUM", "Обходы", "Image File Execution Options: подмена запуска программ",
                "Параметр Debugger в IFEO заставляет Windows вместо программы запускать другую. Так можно "
                "«сломать» запуск System Informer, Everything и других инструментов проверки.",
                [e for _, e in ev], kb=["Обходы/Различные методы/Запрет открытия приложений"])
    # Журналирование PowerShell принудительно выключено
    v = reg_get("HKLM", r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging",
                "EnableScriptBlockLogging", None)
    if v == 0:
        ctx.add("MEDIUM", "Обходы", "Журналирование PowerShell (ScriptBlockLogging) принудительно выключено",
                "Политикой отключена запись выполняемых скриптов PowerShell в журнал событий.",
                [Evidence("HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging = 0")],
                kb=["База/5. Eventvwr/Powershell"])


def _prefetcher(ctx):
    v = reg_get("HKLM", r"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters",
                "EnablePrefetcher", None)
    ctx.shared["enable_prefetcher"] = v
    if v == 0:
        ctx.add("CRITICAL", "Обходы", "Prefetch отключён в реестре (EnablePrefetcher = 0)",
                "Регистрация .pf-файлов выключена — запуски программ не попадают в Prefetch.",
                [Evidence(r"HKLM\SYSTEM\...\PrefetchParameters\EnablePrefetcher = 0")],
                kb=["База/6. Реестр/EnablePrefetcher", "База/7. Службы/SysMain"])
    elif v is not None:
        ctx.log.ok(f"EnablePrefetcher = {v}")


def _archivers(ctx):
    """SteganoChecker: картинки/видео/текст, открытые архиватором."""
    items = []
    k = reg_open("HKCU", r"Software\WinRAR\ArcHistory")
    for name, data, typ in reg_values(k):
        if isinstance(data, str):
            items.append(("WinRAR ArcHistory", data))
    for sub in ("ArcName", "ExtrPath", "FindNames"):
        for name, data, typ in reg_values(reg_open("HKCU", rf"Software\WinRAR\DialogEditHistory\{sub}")):
            if isinstance(data, str):
                items.append((f"WinRAR {sub}", data))
    for path in (r"Software\7-Zip\Compression", r"Software\7-Zip\FM", r"Software\7-Zip\Extraction"):
        for vname in ("ArcHistory", "FolderHistory", "PathHistory"):
            data = reg_get("HKCU", path, vname, None)
            if isinstance(data, bytes):
                for s in data.decode("utf-16-le", errors="ignore").split("\x00"):
                    if s.strip():
                        items.append((f"7-Zip {vname}", s))
    rows = [[src, p] for src, p in items]
    ctx.table("archivers", "История архиваторов (WinRAR / 7-Zip)", ["Источник", "Путь"], rows)
    stego = [(src, p) for src, p in items if os.path.splitext(p.lower())[1] in kb.STEGO_EXTS]
    if stego:
        ctx.add("CRITICAL", "Обходы", "Архиватором открывались картинки/видео/текст — стеганография",
                "Картинки, видео и текстовые файлы не должны открываться через WinRAR/7-Zip. Это признак "
                "архива с читом, приклеенного к медиафайлу (copy /b).",
                [Evidence(f"{src}: {p}", path=normalize_path(p)) for src, p in stego],
                kb=["Обходы/Различные методы/Стеганография", "База/3. Скрипты/SteganoChecker"],
                tools=["JournalTrace"])
    _kw_finding(ctx, [(p, normalize_path(p), None) for _, p in items], "Файлы",
                "Архиваторы: открывались архивы с названиями читов", "История WinRAR/7-Zip.",
                ["База/6. Реестр/WinRAR ArcName History"])
    for _, p in items:
        ctx.add_exec(normalize_path(p), "История архиваторов", kind="access")


def _openwith(ctx):
    base = EXPLORER + r"\FileExts"
    ev = []
    for ext in reg_subkeys(reg_open("HKCU", base)):
        if ext.lower() not in kb.STEGO_EXTS:
            continue
        for name, data, typ in reg_values(reg_open("HKCU", base + "\\" + ext + r"\OpenWithList")):
            if isinstance(data, str) and re.search(r"winrar|7z|bandizip|peazip|javaw?\.exe|rundll32|regsvr32|cmd\.exe",
                                                   data, re.I):
                ev.append(Evidence(f"Файлы {ext} открывались через {data}"))
    if ev:
        ctx.add("HIGH", "Обходы", "Медиафайлы открывались архиватором/Java («Открыть с помощью»)",
                "OpenWithList показывает, что картинки/видео/текст открывали программой, которой они не "
                "предназначены — признак стеганографии или смены расширения.", ev,
                kb=["База/6. Реестр/File Extensions OpenWithList", "Обходы/Различные методы/Стеганография"])


def _url_protocols(ctx):
    """Execute Web: запуск чита через свой URL-протокол в браузере."""
    root = winreg.HKEY_CLASSES_ROOT
    ev = []
    i = 0
    while True:
        try:
            name = winreg.EnumKey(root, i)
        except OSError:
            break
        i += 1
        if name.startswith(".") or name.startswith("{"):
            continue
        try:
            with winreg.OpenKey(root, name) as k:
                try:
                    winreg.QueryValueEx(k, "URL Protocol")
                except OSError:
                    continue
                try:
                    with winreg.OpenKey(k, r"shell\open\command") as c:
                        cmd = winreg.QueryValueEx(c, "")[0]
                except OSError:
                    continue
        except OSError:
            continue
        if not isinstance(cmd, str):
            continue
        hits = keyword_hits(cmd)
        if hits or re.search(r"\\(downloads|appdata\\local\\temp|temp|desktop)\\|cmd\.exe|powershell|javaw?\.exe|"
                             r"wscript|mshta|rundll32", cmd, re.I):
            ev.append(Evidence(f"{name}:// → {cmd}" + (f"  [совпадение: {hits_text(hits)}]" if hits else "")))
    if ev:
        ctx.add("HIGH" if any("совпадение" in e.text for e in ev) else "MEDIUM", "Обходы",
                "Пользовательские URL-протоколы запускают файлы из подозрительных мест",
                "Можно создать протокол в HKCR и запускать чит, вводя «имя://» в браузере — тогда запуск "
                "идёт от браузера, а не проводника. Проверьте каждую команду.", ev,
                kb=["Обходы/Различные методы/Execute Web"])


def _zonemap(ctx):
    """Запрет сайтов: «Опасные сайты» в свойствах браузера (зона 4)."""
    ev = []
    for hive in ("HKCU", "HKLM"):
        for sub in ("Domains", "EscDomains"):
            base = rf"Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\{sub}"
            for dom in reg_subkeys(reg_open(hive, base)):
                k = reg_open(hive, base + "\\" + dom)
                zones = [d for n, d, t in reg_values(k) if isinstance(d, int)]
                subs = reg_subkeys(k)
                for s in subs:
                    zones += [d for n, d, t in reg_values(reg_open(hive, base + "\\" + dom + "\\" + s))
                              if isinstance(d, int)]
                if 4 in zones:
                    tool = any(t in dom.lower() for t in kb.SS_TOOL_DOMAINS)
                    ev.append(Evidence(f"{dom}" + ("  ← сайт инструментов проверки" if tool else ""),
                                       url=f"https://{dom}"))
    if ev:
        ctx.add("HIGH" if any("←" in e.text for e in ev) else "MEDIUM", "Обходы",
                "В «Опасные сайты» добавлены домены", "Через свойства браузера можно запретить сайты с "
                "программами для проверки.", ev, kb=["Обходы/Различные методы/Запрет сайтов"])


def _usb(ctx):
    rows = []
    serials = set()
    base = r"SYSTEM\CurrentControlSet\Enum\USBSTOR"
    root = reg_open("HKLM", base)
    for dev in reg_subkeys(root):
        for inst in reg_subkeys(reg_open("HKLM", base + "\\" + dev)):
            k = reg_open("HKLM", base + "\\" + dev + "\\" + inst)
            name = reg_get("HKLM", base + "\\" + dev + "\\" + inst, "FriendlyName", dev)
            rows.append([name, inst, fmt_dt(reg_last_write(k))])
            serials.add(inst.split("&")[0].lower())
    ctx.table("usb", "USB-накопители (USBSTOR)", ["Устройство", "Серийный номер", "Раздел изменён"], rows)
    ctx.shared["usbstor_serials"] = serials
    # Сравниваем с журналом установки драйверов: USBOblivion чистит реестр, но не setupapi.dev.log
    log = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "INF", "setupapi.dev.log")
    try:
        with open(log, "r", encoding="utf-8", errors="replace") as f:
            txt = f.read()
    except OSError:
        return
    found = {}
    for m in re.finditer(r">>>\s+\[Device Install[^\]]*-\s*(USBSTOR\\[^\]]+)\]\s*\n>>>\s+Section start (\S+ \S+)", txt):
        dev, ts = m.group(1), m.group(2)
        serial = dev.rsplit("\\", 1)[-1].split("&")[0].lower()
        found[serial] = (dev, ts)
    missing = {s: v for s, v in found.items() if s not in serials}
    if missing:
        ctx.add("HIGH", "Чистка", "USB-накопители есть в setupapi.dev.log, но удалены из реестра",
                "Устройство устанавливалось (журнал драйверов), но его раздел в USBSTOR отсутствует — "
                "признак очистки следов USB (например, USBOblivion).",
                [Evidence(f"{dev} — первое подключение {ts}", source=log) for dev, ts in missing.values()],
                kb=["Обходы/Обнаружение чистки/Чистка USB-Устройств", "База/1. Артефакты/USB"],
                tools=["System Informer"])
    if found and not serials:
        ctx.add("HIGH", "Чистка", "Раздел USBSTOR пуст при наличии истории USB", "", [Evidence(log)],
                kb=["Обходы/Обнаружение чистки/Чистка USB-Устройств"])


def _uninstall(ctx):
    items = []
    for hive, path in (("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
                       ("HKLM", r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
                       ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Uninstall")):
        for sub in reg_subkeys(reg_open(hive, path)):
            name = reg_get(hive, path + "\\" + sub, "DisplayName", "")
            loc = reg_get(hive, path + "\\" + sub, "InstallLocation", "")
            if name:
                items.append((str(name), str(loc or "")))
    ctx.table("installed", "Установленные программы", ["Название", "Папка"], [[a, b] for a, b in items])
    _kw_finding(ctx, [(f"{n} {l}", l or None, None) for n, l in items], "Программы",
                "Установлены программы с названиями читов", "Раздел Uninstall (appwiz.cpl).",
                ["База/4. Win+R/Appwiz"])
    cleaners = [(n, l) for n, l in items if any(c in n.lower() for c in kb.CLEANER_TOOLS)]
    if cleaners:
        ctx.add("MEDIUM", "Чистка", "Установлены программы для очистки следов",
                "Такие программы используют для удаления артефактов перед проверкой. Сопоставьте с датами "
                "очистки журналов/корзины.", [Evidence(f"{n}  {l}", path=l or None) for n, l in cleaners],
                kb=["Обходы/Обнаружение чистки/Чистка Реестра"])


def _browsers(ctx):
    names = reg_subkeys(reg_open("HKLM", r"SOFTWARE\Clients\StartMenuInternet"))
    ctx.system["browsers"] = names
    ctx.log.info("Браузеры: " + (", ".join(names) or "—"))
