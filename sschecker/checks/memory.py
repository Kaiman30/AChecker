"""Строки в памяти процессов — автоматизация методик System Informer (База → 2. Программы → System Informer)."""
import os
import re
import time
from collections import defaultdict

from .. import kb
from ..core import Evidence
from ..match import hits_text, keyword_hits, maybe_keyword, suspicious_commands
from ..winutil import (IS_WIN, enable_privilege, normalize_path, path_exists, read_process_memory,
                       service_pids)

ASCII_RX = re.compile(rb"[\x20-\x7e]{5,}")
U16_RX = re.compile(rb"(?:[\x20-\x7e]\x00|[\x00-\xff]\x04){5,}")
MAX_STRINGS = 4_000_000
SI = "База/2. Программы/System Informer/"

# Строки, которые ищем в javaw напрямую по байтам (ASCII и обе «половинки» UTF-16)
_JAVA_RX = re.compile(("|".join(["(?:%s)" % p for p in kb.CHEAT_MEMORY_STRINGS] +
                                 [re.escape(k) for k in kb.CHEAT_STRONG if len(k) >= 5])).encode(), re.I)
_JAR_A = re.compile(rb"[A-Za-z]:\\[\x20-\x7e]{1,260}?\.jar", re.I)
_JAR_U = re.compile(rb"[A-Za-z]\x00:\x00\\\x00(?:[\x20-\x7e]\x00|[\x00-\xff]\x04){1,260}?\.\x00[jJ]\x00[aA]\x00[rR]\x00")


def collect_strings(pid, limit):
    out = set()
    for chunk in read_process_memory(pid, limit):
        for m in ASCII_RX.finditer(chunk):
            s = m.group(0)
            out.add(s[:1024].decode("latin-1"))
        for m in U16_RX.finditer(chunk):
            s = m.group(0)
            if m.start() & 1:
                s = s[1:]
            out.add(s[:2048].decode("utf-16-le", "ignore"))
        if len(out) > MAX_STRINGS:
            break
    return out


def run_check(ctx):
    if not IS_WIN:
        ctx.log.warn("Не Windows — память процессов пропущена")
        return
    if not ctx.system.get("admin"):
        ctx.log.warn("Без прав администратора память системных служб недоступна")
    enable_privilege("SeDebugPrivilege")
    svc = service_pids()
    procs = ctx.shared.get("processes") or []
    by_name = defaultdict(list)
    for p in procs:
        by_name[(p.get("name") or "").lower()].append(p.get("pid"))
    cdp = next((k for k in svc if k.startswith("cdpusersvc_")), None)
    limit = ctx.opts.memory_limit_mb << 20
    targets = [
        ("DPS", svc.get("dps"), _dps),
        ("PcaSvc", svc.get("pcasvc"), _pcasvc),
        ("Explorer", (by_name.get("explorer.exe") or [None])[0], _explorer),
        ("DiagTrack", svc.get("diagtrack"), _diagtrack),
        ("DcomLaunch/Power/PlugPlay", svc.get("dcomlaunch") or svc.get("plugplay") or svc.get("power"), _dcomlaunch),
        ("SysMain", svc.get("sysmain"), _sysmain),
        ("Dnscache", svc.get("dnscache"), _dnscache),
        ("AppInfo", svc.get("appinfo"), _appinfo),
        ("SearchIndexer", (by_name.get("searchindexer.exe") or [svc.get("wsearch")])[0], _searchindexer),
        ("BFE", svc.get("bfe"), _bfe),
        ("Scheduler", svc.get("schedule"), _scheduler),
        ("CDPUserSvc", svc.get(cdp) if cdp else None, _cdp),
        ("csrss", (by_name.get("csrss.exe") or [None])[-1], _csrss),
        ("MsMpEng", (by_name.get("msmpeng.exe") or [None])[0], _msmpeng),
    ]
    for pid in by_name.get("powershell.exe", []) + by_name.get("pwsh.exe", []):
        targets.append((f"PowerShell PID {pid}", pid, _powershell))
    summary = []
    for name, pid, analyzer in targets:
        if not pid:
            summary.append([name, "—", "процесс/служба не найдены"])
            ctx.log.warn(f"{name}: процесс не найден")
            continue
        t0 = time.time()
        try:
            strings = collect_strings(pid, limit)
        except PermissionError:
            summary.append([name, pid, "нет доступа (защищённый процесс)"])
            ctx.log.warn(f"{name} (PID {pid}): нет доступа к памяти — проверьте вручную в System Informer")
            continue
        ctx.log.info(f"{name} (PID {pid}): {len(strings)} строк за {time.time() - t0:.1f} с")
        summary.append([name, pid, f"{len(strings)} строк"])
        try:
            analyzer(ctx, name, strings)
            _generic_keywords(ctx, name, strings)
        except Exception as e:  # noqa
            ctx.log.error(f"{name}: {e}")
        del strings
    for pid in by_name.get("javaw.exe", []) + by_name.get("java.exe", []):
        _javaw(ctx, pid, max(limit, 2048 << 20))
        summary.append([f"javaw PID {pid}", pid, "поиск строк читов и путей .jar"])
    ctx.table("memory", "Сканирование памяти процессов", ["Процесс", "PID", "Результат"], summary)


# ---------------------------------------------------------------------------
def _paths(strings, exts=None):
    out = set()
    for s in strings:
        if ":\\" not in s and "\\device\\" not in s.lower():
            continue
        for m in kb.RE_DOS_PATH.finditer(s):
            p = m.group(0).rstrip(" .")
            if exts is None or os.path.splitext(p.lower())[1] in exts:
                out.add(p)
        for m in kb.RE_DEVICE_PATH.finditer(s):
            p = normalize_path(m.group(0).rstrip(" ."))
            if exts is None or os.path.splitext(p.lower())[1] in exts:
                out.add(p)
    return out


def _generic_keywords(ctx, name, strings):
    hits = {}
    for s in strings:
        if len(s) > 600 or not maybe_keyword(s):
            continue
        h = [x for x in keyword_hits(s) if x[1] == "HIGH"]
        if h:
            hits[s] = h
    if hits:
        items = sorted(hits.items(), key=lambda x: len(x[0]))[:80]
        ctx.add("HIGH", "Память", f"{name}: в памяти найдены названия читов",
                "Строки в памяти процесса существуют, пока процесс работает — это следы текущего сеанса. "
                "Проверьте контекст каждой строки (это может быть, например, просто открытая страница сайта).",
                [Evidence(f"{s[:300]}  [совпадение: {hits_text(h)}]") for s, h in items],
                kb=[SI + "1. О SystemInformer"], tools=["System Informer"])


def _exec_paths(ctx, strings, source, exts=(".exe",)):
    ps = _paths(strings, set(exts))
    for p in ps:
        ctx.add_exec(p, source)
    return ps


def _ext_modified(ctx, name, paths, kbref):
    """Пути без .exe/.dll в процессах, которые хранят только запуски исполняемых файлов."""
    bad = []
    for p in paths:
        ext = os.path.splitext(p.lower())[1]
        if ext and ext not in (".exe", ".dll", ".sys", ".mui", ".manifest", ".config", ".cpl", ".pyd", ".ocx",
                               ".com", ".scr", ".node", ".drv", ".winmd", ".tlb", ".ax", ".efi", ".msc", ".msi",
                               ".tmp", ".ini", ".dat", ".log", ".db", ".etl", ".pf", ".ttf", ".ttc", ".otf",
                               ".fon", ".nls", ".xml", ".json", ".png", ".ico", ".lnk", ".url", ".txt", ".cat",
                               ".msp", ".appx", ".msix", ".jar") and len(ext) <= 6:
            bad.append(p)
    return bad


# ---------------------------------------------------------------------------
def _dps(ctx, name, strings):
    entries = defaultdict(set)
    usb_obl = []
    for s in strings:
        for m in kb.RE_DPS_ENTRY.finditer(s):
            fname, ts = m.group("name").strip(), m.group("ts")
            entries[fname].add(ts)
            if ts.startswith("2021/11/29:17:36:2"):
                usb_obl.append(Evidence(f"{s[:200]}"))
    rows = [[n, ", ".join(sorted(t))] for n, t in sorted(entries.items())]
    ctx.table("dps", "DPS (память): исполняемые файлы, запускавшиеся в текущем сеансе",
              ["Файл", "Метка времени PE (компиляция)"], rows,
              note="Формат !!имя!ГГГГ/ММ/ДД:ЧЧ:ММ:СС! — время здесь из заголовка PE-файла, а не время запуска.")
    for n, ts in entries.items():
        ctx.add_exec(n, "DPS (память)", None, note="метки PE: " + ", ".join(sorted(ts)))
    noexe = [n for n in entries if not re.search(r"\.(exe|com|scr)$", n, re.I)]
    if noexe:
        ctx.add("CRITICAL", "Обходы", "DPS: запускались файлы без расширения .exe",
                "DPS хранит записи !!имя!дата! только для исполняемых файлов. Запись без .exe означает, что "
                "исполняемый файл переименовали (например, в .png) и запустили.",
                [Evidence(f"!!{n}!{', '.join(sorted(entries[n]))}") for n in noexe],
                kb=[SI + "DPS", "Обходы/Различные методы/Измененные расширения"], tools=["System Informer"])
    multi = [(n, ts) for n, ts in entries.items() if len(ts) > 1]
    if multi:
        ctx.add("MEDIUM", "Обходы", "DPS: файлы с одинаковым именем, но разными метками (возможна подмена)",
                "Два разных .exe с одним именем были открыты в этом сеансе. Перед выводами убедитесь, что на ПК нет "
                "других легитимных файлов с тем же именем (Everything), затем сравните метки с VirusTotal.",
                [Evidence(f"{n}: {', '.join(sorted(ts))}") for n, ts in multi],
                kb=["Обходы/Различные методы/FAT32", SI + "DPS"], tools=["Everything 1.5a", "VirusTotal"])
    if usb_obl:
        ctx.add("CRITICAL", "Чистка", "DPS: найдена метка USBOblivion",
                "Строки 2021/11/29:17:36:29 / 2021/11/29:17:36:22 соответствуют USBOblivion — утилите очистки следов USB.",
                usb_obl, kb=["Обходы/Обнаружение чистки/Чистка USB-Устройств"])
    dev = _paths([s for s in strings if "harddiskvolume" in s.lower()])
    for p in dev:
        if p.lower().endswith((".exe",)):
            ctx.add_exec(p, "DPS (память)")


def _pcasvc(ctx, name, strings):
    jars = set()
    for s in strings:
        if ".jar" in s.lower():
            for m in re.finditer(r"[A-Za-z]:\\[^\x00\"<>|*?\r\n]{1,300}?\.jar", s, re.I):
                jars.add(m.group(0))
    _exec_paths(ctx, strings, "PcaSvc (память)")
    for j in jars:
        ctx.add_exec(j, "PcaSvc (память)", note=".jar")
    sus = [j for j in jars if not re.search(r"\\(libraries|versions|launcher|runtime)\\|tlauncher|minecraft\.jar|"
                                            r"\\java\\|\\jdk|\\jre", j, re.I)]
    if sus:
        ev = []
        for j in sorted(sus):
            ex = path_exists(j)
            hits = keyword_hits(j)
            ev.append(Evidence(j + ("" if ex else "  (файла уже нет)") + (f" [совпадение: {hits_text(hits)}]" if hits else ""),
                               path=j))
        ctx.add("HIGH" if any("совпадение" in e.text or "нет)" in e.text for e in ev) else "MEDIUM", "Minecraft",
                "PcaSvc (память): запускались .jar-файлы",
                "PcaSvc помогает обнаружить .jar, внедрённые в игру (например, Doomsday). Проверьте каждый файл; "
                "удалённые .jar особенно подозрительны.", ev, kb=[SI + "PcaSvc"], tools=["System Informer"])
    bad = _ext_modified(ctx, name, _paths(strings), None)
    bad = [b for b in bad if re.match(r"^[A-Za-z]:\\", b) and not re.search(r"\\(windows|program files|programdata)\\", b, re.I)]
    if bad:
        ctx.add("MEDIUM", "Обходы", "PcaSvc (память): обращения к файлам с нестандартным расширением",
                "Regex из базы: ^C:\\\\((?!Exe|dll|…).)*$ — пути, которые PcaSvc видел, но которые не являются .exe. "
                "Может указывать на запуск файла с изменённым расширением.",
                [Evidence(b, path=b) for b in sorted(bad)[:100]], kb=[SI + "📌 System informer regexes"])


def _explorer(ctx, name, strings):
    urls, ads, jnh, wmic, shellact, pcac = set(), set(), set(), set(), set(), set()
    for s in strings:
        low = s.lower()
        if "file:///" in low:
            for m in kb.RE_FILE_URL.finditer(s):
                urls.add(m.group(0))
        if ":" in s and "\\" in s:
            for m in kb.RE_ADS.finditer(s):
                stream = m.group(2).lower()
                if stream.split(":")[0] not in kb.BENIGN_ADS and not stream.startswith("$") and len(stream) < 80 \
                        and not re.match(r"^\d+$", stream):
                    ads.add(m.group(0))
        if "jnativehook" in low:
            for m in kb.RE_JNATIVE.finditer(s):
                jnh.add(m.group(0))
        if "wmic" in low and "process" in low and "create" in low:
            wmic.add(s[:300])
        if "ms-shellactivity" in low:
            shellact.add(s[:400])
        if "pcaclient" in low:
            pcac.add(s[:400])
    files = set()
    for u in urls:
        p = normalize_path(u.replace("%20", " "))
        files.add(p)
    exe_like = {f for f in files if os.path.splitext(f.lower())[1] in (".exe", ".jar", ".bat", ".cmd", ".dll", ".ps1",
                                                                       ".vbs", ".ahk", ".py")}
    for f in exe_like:
        ctx.add_exec(f, "Explorer (память, file:///)", kind="storage")
    gone = [f for f in exe_like if path_exists(f) is False and not re.search(r"\\(temp|windows)\\", f, re.I)]
    if gone:
        ctx.add("MEDIUM", "Файлы", "Explorer (память): исполняемые файлы, которых уже нет на диске",
                "Процесс Explorer помнит файлы, с которыми работал в этом сеансе (file:///…). Файл отсутствует — его "
                "удалили, переместили или он был на флешке.", [Evidence(f, path=f) for f in sorted(gone)[:150]],
                kb=[SI + "Explorer"], tools=["System Informer", "JournalTrace"])
    if ads:
        ctx.add("HIGH", "Обходы", "Explorer (память): обращения к альтернативным потокам NTFS (ADS)",
                "Строка вида C:\\file.ext:stream — в поток можно спрятать чит (notepad.exe:secret.dll).",
                [Evidence(a) for a in sorted(ads)[:60]], kb=["Обходы/Различные методы/ADS", SI + "Explorer"])
    if jnh:
        ctx.add("MEDIUM", "Minecraft", "Explorer (память): упоминание JNativeHook",
                "JNativeHook используют .jar-кликеры.", [Evidence(j) for j in sorted(jnh)], kb=[SI + "📌 System informer regexes"])
    if wmic:
        ctx.add("HIGH", "Обходы", "Explorer (память): запуск через wmic process call create",
                "Так запускают файлы без расширения/с изменённым расширением.", [Evidence(w) for w in sorted(wmic)[:30]],
                kb=[SI + "wmic"])
    exe_in_act = [s for s in shellact if re.search(r"\.(exe|jar|bat|dll)\b", s, re.I)]
    if exe_in_act:
        ctx.add("MEDIUM", "Запуски", "Explorer (память): файлы, запускавшиеся из архивов (ms-shellactivity)",
                "", [Evidence(s) for s in sorted(exe_in_act)[:60]], kb=[SI + "Explorer"])
    for s in pcac:
        for p in _paths([s], {".exe", ".jar", ".bat"}):
            ctx.add_exec(p, "Explorer pcaclient (память)")


def _diagtrack(ctx, name, strings):
    dev = _paths([s for s in strings if "harddiskvolume" in s.lower() or ":\\" in s])
    for p in dev:
        if p.lower().endswith(".exe"):
            ctx.add_exec(p, "DiagTrack (память)")
    rund = [s[:300] for s in strings if "rundll32" in s.lower() and (":\\" in s or "harddisk" in s.lower())]
    rund = [r for r in rund if not re.search(r"\\windows\\", r.split("rundll32", 1)[-1], re.I)]
    if rund:
        ctx.add("MEDIUM", "Запуски", "DiagTrack (память): rundll32 с файлами вне системных папок",
                "Так запускают DLL-читы.", [Evidence(r) for r in sorted(set(rund))[:40]], kb=[SI + "DiagTrack"])


def _dcomlaunch(ctx, name, strings):
    cmds = sorted({s[:500] for s in strings if "-jar" in s.lower() and ("java" in s.lower() or ".jar" in s.lower())})
    if cmds:
        ev = []
        for c in cmds:
            hits = keyword_hits(c)
            ev.append(Evidence(c + (f"  [совпадение: {hits_text(hits)}]" if hits else "")))
            for m in re.finditer(r"-jar\s+\"?([^\"]+?\.jar)", c, re.I):
                ctx.add_exec(normalize_path(m.group(1)), "DcomLaunch (память, -jar)")
        ctx.add("HIGH" if any("совпадение" in e.text for e in ev) else "MEDIUM", "Minecraft",
                "DcomLaunch/Power/PlugPlay (память): запуск .jar через «-jar»",
                "Этот процесс помогает обнаружить читы, которые внедряются в игру как .jar. Легитимные лаунчеры "
                "(TLauncher и т.п.) тоже запускаются через -jar — проверьте пути. При анхуке Doomsday данные здесь "
                "могут очищаться.", ev[:60], kb=[SI + "DcomLaunch, Power, PlugPlay"])


def _sysmain(ctx, name, strings):
    pfs = set()
    for s in strings:
        for m in re.finditer(r"\\PREFETCH\\([^\\\x00]+?-[0-9A-F]{8}\.pf)", s, re.I):
            pfs.add(m.group(1).upper())
    pf_dir = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "Prefetch")
    try:
        present = {f.upper() for f in os.listdir(pf_dir)}
    except OSError:
        present = set()
    noexe = [p for p in pfs if not re.search(r"\.(EXE|COM|SCR|CPL|MSC|TMP)-[0-9A-F]{8}\.PF$", p)]
    missing = [p for p in pfs if p not in present]
    if noexe:
        ctx.add("CRITICAL", "Обходы", "SysMain (память): Prefetch-записи для файлов не .exe",
                "SysMain формирует .pf только для исполняемых файлов. Запись для файла с другим расширением — "
                "исполняемый файл был переименован и запущен.", [Evidence(p) for p in sorted(noexe)],
                kb=[SI + "SysMain", "Обходы/Различные методы/Измененные расширения"])
    if missing and present:
        ctx.add("HIGH", "Чистка", "SysMain (память): .pf-файлы, которых нет в папке Prefetch",
                "Служба помнит .pf-файлы этого сеанса, но в папке их нет — их удалили.",
                [Evidence(p) for p in sorted(missing)[:100]], kb=[SI + "SysMain", "База/1. Артефакты/Prefetch"],
                tools=["PrefetchView++", "JournalTrace"])


def _dnscache(ctx, name, strings):
    domains = set()
    for s in strings:
        if len(s) > 200 or "." not in s:
            continue
        for m in kb.RE_DOMAIN.finditer(s):
            d = m.group(0).lower()
            if len(d) > 4:
                domains.add(d)
    ctx.table("dns", "DNS-кэш (память Dnscache): домены", ["Домен"], [[d] for d in sorted(domains)][:3000])
    sus = []
    for d in domains:
        hits = keyword_hits(d.replace(".", " "))
        if hits and any(s in ("HIGH", "MEDIUM") for _, s in hits):
            sus.append(Evidence(f"{d}  [совпадение: {hits_text(hits)}]", url=f"https://{d}"))
    if sus:
        ctx.add("HIGH", "Сеть", "DNS: обращения к доменам с названиями читов",
                "Служба Dnscache хранит домены, к которым обращались программы (сайты читов, лоадеры, API).",
                sus, kb=[SI + "Dnscache"])


def _appinfo(ctx, name, strings):
    for p in _exec_paths(ctx, strings, "AppInfo (запуск от администратора)"):
        pass


def _searchindexer(ctx, name, strings):
    for p in _paths(strings, {".exe", ".jar", ".dll"}):
        ctx.add_exec(p, "SearchIndexer (память)", kind="storage")


def _bfe(ctx, name, strings):
    q = sorted({s[:300] for s in strings if re.search(r"(TCP|UDP) Query User", s, re.I)})
    if q:
        ctx.table("bfe", "BFE: запросы брандмауэра (TCP/UDP Query User)", ["Строка"], [[x] for x in q[:300]])
        for s in q:
            for p in _paths([s], {".exe"}):
                ctx.add_exec(p, "BFE (брандмауэр)")


def _scheduler(ctx, name, strings):
    cmds = sorted({s[:400] for s in strings if "<command>" in s.lower()})
    ev = []
    for c in cmds:
        hits = keyword_hits(c, weak=True)
        sc = suspicious_commands(c)
        if hits or any(x[0] in ("CRITICAL", "HIGH") for x in sc):
            ev.append(Evidence(c + (f"  [совпадение: {hits_text(hits)}]" if hits else "")
                               + (f"  ← {sc[0][1]}" if sc else "")))
    if ev:
        ctx.add("HIGH", "Автозагрузка", "Scheduler (память): задачи с подозрительными командами", "", ev,
                kb=[SI + "Scheduler", "Обходы/Различные методы/TaskScheduler"])


def _cdp(ctx, name, strings):
    apps = set()
    for s in strings:
        for m in kb.RE_CDP_APP.finditer(s):
            apps.add(m.group("app").replace("\\\\", "\\"))
    bad = []
    for a in apps:
        p = normalize_path(a)
        if "\\" in p:
            ctx.add_exec(p, "CDPUserSvc (память)")
            if not p.lower().endswith(".exe"):
                bad.append(p)
    if bad:
        ctx.add("HIGH", "Обходы", "CDPUserSvc (память): запуски файлов без .exe",
                "Regex из базы: [{\"application\":\"…\" без .exe — запуск файла с изменённым расширением.",
                [Evidence(b, path=b) for b in sorted(bad)[:60]], kb=[SI + "📌 System informer regexes"])


def _csrss(ctx, name, strings):
    paths = _paths(strings)
    for p in paths:
        if p.lower().endswith(".exe"):
            ctx.add_exec(p, "csrss (память)")
    dlls = [p for p in paths if p.lower().endswith(".dll") and not re.search(r"\\(windows|program files)", p, re.I)]
    if dlls:
        ctx.add("MEDIUM", "Запуски", "csrss (память): DLL вне системных папок",
                "Метод из базы: csrss → ^[A-Z]:\\\\.+\\.dll$ — затем проверка подписей. Неподписанная DLL из "
                "пользовательской папки может быть инжектом.", [Evidence(d, path=d) for d in sorted(dlls)[:100]],
                kb=[SI + "CSRSS", "База/3. Скрипты/Проверка подписей"], tools=["Signatures.ps1"])
    ctx.shared.setdefault("sign_candidates", []).extend(dlls)
    bad = [b for b in _ext_modified(ctx, name, paths, None)
           if not re.search(r"\\(windows|program files|programdata)\\", b, re.I)]
    if bad:
        ctx.add("MEDIUM", "Обходы", "csrss (память): файлы с нестандартными расширениями",
                "Regex «Extension Modifications» из базы.", [Evidence(b, path=b) for b in sorted(bad)[:100]],
                kb=[SI + "CSRSS"])


def _msmpeng(ctx, name, strings):
    ev = {}
    for s in strings:
        if len(s) > 1000:
            continue
        for sev, desc, m in suspicious_commands(s):
            if sev in ("CRITICAL", "HIGH"):
                ev[s[:300]] = (sev, desc)
    if ev:
        order = ["CRITICAL", "HIGH"]
        sev = min((v[0] for v in ev.values()), key=order.index)
        ctx.add(sev, "Команды", "MsMpEng (память): Защитник видел команды обхода/чистки",
                "Защитник сканирует командные строки — в его памяти остаются fsutil/wevtutil/reg delete и т.п.",
                [Evidence(f"{k}  ← {v[1]}") for k, v in list(ev.items())[:60]], kb=[SI + "MsMpEng", SI + "wmic"])


def _powershell(ctx, name, strings):
    ev = {}
    for s in strings:
        if len(s) > 2000:
            continue
        for sev, desc, m in suspicious_commands(s):
            if sev in ("CRITICAL", "HIGH") and "get-authenticodesignature" not in s.lower():
                ev[s[:300]] = (sev, desc)
    if ev:
        ctx.add("HIGH", "Команды", f"{name}: в памяти PowerShell команды обхода",
                "Открытое окно PowerShell хранит введённые команды, даже если история отключена.",
                [Evidence(f"{k}  ← {v[1]}") for k, v in list(ev.items())[:60]], kb=[SI + "PowerShell Method"])


def _javaw(ctx, pid, limit):
    t0 = time.time()
    found = {}
    jars = set()
    try:
        for chunk in read_process_memory(pid, limit, include_image=False):
            for view in (chunk, chunk[0::2], chunk[1::2]):
                for m in _JAVA_RX.finditer(view):
                    key = m.group(0).decode("latin-1").lower()
                    if key not in found or len(found[key]) < 5:
                        ctxs = view[max(0, m.start() - 60):m.end() + 60]
                        txt = re.sub(rb"[^\x20-\x7e]+", b" ", ctxs).decode("latin-1").strip()
                        found.setdefault(key, []).append(txt)
            for m in _JAR_A.finditer(chunk):
                jars.add(m.group(0).decode("latin-1"))
            for m in _JAR_U.finditer(chunk):
                b = m.group(0)
                if m.start() & 1:
                    b = b[1:]
                jars.add(b.decode("utf-16-le", "ignore"))
    except PermissionError:
        ctx.log.warn(f"javaw PID {pid}: нет доступа к памяти")
        return
    ctx.log.info(f"javaw PID {pid}: {len(found)} совпадений, {len(jars)} путей .jar за {time.time() - t0:.1f} с")
    if found:
        ctx.add("CRITICAL", "Minecraft", "Память Minecraft (javaw): строки модулей читов",
                "В памяти работающей игры найдены строки, характерные для читов (KillAura, AimAssist, Reach: 4.8 и т.п.). "
                "Это доказательство использования ЗПО в текущем сеансе. Посмотрите контекст: такие слова могут "
                "встречаться и в сообщениях чата.",
                [Evidence(f"«{k}»: …{c}…") for k, cs in sorted(found.items()) for c in cs[:2]][:120],
                kb=["База/1. Артефакты/📌Введение"], tools=["System Informer"])
    mod_jars = sorted({j for j in jars if re.search(r"\\mods\\[^\\]+\.jar$", j, re.I)})
    missing = [j for j in mod_jars if path_exists(j) is False]
    if missing:
        ctx.add("CRITICAL", "Minecraft", "Выгруженные моды: игра загружала моды, которых нет в папке",
                "Моды есть в памяти javaw, но отсутствуют в папке mods — их удалили, переместили или переименовали "
                "после загрузки (выгрузка мода).", [Evidence(j, path=j) for j in missing],
                kb=["Моды/3. Выгруженные моды"], tools=["System Informer"])
    other = sorted({j for j in jars if not re.search(r"\\(libraries|versions|runtime|jre|jdk|java|assets|mods)\\",
                                                     j, re.I)})
    if other:
        ev = []
        for j in other[:80]:
            hits = keyword_hits(j)
            ex = path_exists(j)
            ev.append(Evidence(j + ("" if ex else "  (файла нет)") + (f"  [совпадение: {hits_text(hits)}]" if hits else ""),
                               path=j))
        ctx.add("HIGH" if any("совпадение" in e.text for e in ev) else "MEDIUM", "Minecraft",
                "Память Minecraft: .jar вне папок игры (возможный инжект)",
                "Игра обращалась к .jar-файлам не из libraries/versions/mods — так подгружаются инжект-клиенты "
                "(Doomsday и т.п.).", ev, kb=["Моды/3. Выгруженные моды", SI + "PcaSvc"])
    ctx.shared.setdefault("javaw_jars", set()).update(jars)
