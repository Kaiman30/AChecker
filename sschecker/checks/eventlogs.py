"""Журналы событий (База → 5. Eventvwr, Обходы → Обнаружение чистки)."""
import re
import xml.etree.ElementTree as ET
from datetime import timedelta

from ..core import Evidence, fmt_dt
from ..match import hits_text, keyword_hits, suspicious_commands
from ..winutil import IS_WIN, normalize_path, parse_iso, run_bytes, _decode

NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
CRIT_SERVICES = {"sysmain", "pcasvc", "dps", "eventlog", "diagtrack", "dusmsvc", "bam", "appinfo"}


def _decode_out(b: bytes) -> str:
    if b[:2] == b"\xff\xfe" or (len(b) > 3 and b[1:2] == b"\x00"):
        return b.decode("utf-16-le", errors="replace").lstrip("﻿")
    return _decode(b)


def query(log: str, ids=None, count: int = 100, newest: bool = True, xpath: str = None):
    if not IS_WIN:
        return []
    if xpath is None:
        xpath = "*"
        if ids:
            xpath = "*[System[(" + " or ".join(f"EventID={i}" for i in ids) + ")]]"
    cmd = ["wevtutil", "qe", log, f"/q:{xpath}", "/f:xml", f"/c:{count}", "/uni:true"]
    if newest:
        cmd.append("/rd:true")
    out = _decode_out(run_bytes(cmd, timeout=180))
    events = []
    for chunk in re.findall(r"<Event[ >].*?</Event>", out, re.S):
        try:
            root = ET.fromstring(chunk)
        except ET.ParseError:
            continue
        sysel = root.find(NS + "System")
        if sysel is None:
            continue
        ev = {"log": log, "id": int((sysel.findtext(NS + "EventID") or "0").strip() or 0),
              "provider": (sysel.find(NS + "Provider").get("Name") if sysel.find(NS + "Provider") is not None else ""),
              "time": None, "data": {}, "values": [], "binary": ""}
        tc = sysel.find(NS + "TimeCreated")
        if tc is not None:
            ev["time"] = parse_iso(tc.get("SystemTime", ""))
        ed = root.find(NS + "EventData")
        if ed is not None:
            for d in ed.findall(NS + "Data"):
                v = (d.text or "").strip()
                if d.get("Name"):
                    ev["data"][d.get("Name")] = v
                ev["values"].append(v)
            b = ed.findtext(NS + "Binary")
            if b:
                ev["binary"] = b.strip()
        ud = root.find(NS + "UserData")
        if ud is not None:
            for el in ud.iter():
                if el.text and el.text.strip():
                    tag = el.tag.split("}", 1)[-1]
                    ev["data"][tag] = el.text.strip()
                    ev["values"].append(el.text.strip())
        events.append(ev)
    return events


def _bin_name(hexstr: str) -> str:
    try:
        return bytes.fromhex(hexstr).decode("utf-16-le", errors="ignore").strip("\x00")
    except ValueError:
        return ""


def run_check(ctx):
    if not IS_WIN:
        ctx.log.warn("Не Windows — журналы событий пропущены")
        return
    _cleared(ctx)
    _usn_deleted(ctx)
    _time_changes(ctx)
    _services(ctx)
    _powershell(ctx)
    _process_creation(ctx)
    _defender(ctx)
    _bits(ctx)
    _pca(ctx)
    _pnp(ctx)
    _shutdowns(ctx)
    _oldest(ctx)


def _sev_by_time(ctx, t, recent="CRITICAL", old="HIGH"):
    return recent if ctx.is_recent(t) else old


def _cleared(ctx):
    evs = query("Security", [1102], 20) + query("System", [104], 20)
    if not evs:
        ctx.log.ok("Записей об очистке журналов (1102/104) нет")
        return
    items = []
    for e in evs:
        what = e["data"].get("Channel") or e["data"].get("SubjectUserName") or ""
        if e["id"] == 1102:
            what = "Security" + (f" (пользователь {e['data'].get('SubjectUserName')})" if e["data"].get("SubjectUserName") else "")
        items.append(Evidence(f"[{e['log']} {e['id']}] очищен журнал: {what or '?'}", time=e["time"],
                              source=f"Журнал {e['log']}, событие {e['id']}"))
    newest = max((e["time"] for e in evs if e["time"]), default=None)
    ctx.add(_sev_by_time(ctx, newest), "Чистка", "Журналы событий очищались",
            "Event ID 1102 (Security) и 104 (System) фиксируют очистку журналов. Очистка журналов "
            "незадолго до проверки — прямой признак сокрытия следов.",
            items, kb=["Обходы/Обнаружение чистки/Чистка EventLog", "База/5. Eventvwr/Event Deletion"],
            tools=["Event Viewer"])


def _usn_deleted(ctx):
    evs = [e for e in query("Application", [3079], 20)]
    if not evs:
        ctx.log.ok("Записей об удалении USN-журнала (3079) нет")
        return
    newest = max((e["time"] for e in evs if e["time"]), default=None)
    ctx.add(_sev_by_time(ctx, newest, "CRITICAL", "HIGH"), "Чистка", "USN-журнал удалялся (Event ID 3079)",
            "Событие 3079 в журнале Application фиксирует удаление журнала изменений NTFS ($UsnJrnl) — "
            "им пользуется JournalTrace. Чистка USN является безоговорочным основанием для наказания.",
            [Evidence(f"Удаление USN-журнала: {' '.join(e['values'])[:200]}", time=e["time"],
                      source="Application 3079") for e in evs],
            kb=["Обходы/Обнаружение чистки/Чистка JournalTrace", "База/5. Eventvwr/Clear JournalTrace"])


def _time_changes(ctx):
    ev = []
    for e in query("System", [1], 200):
        if "Kernel-General" not in e["provider"]:
            continue
        old, new = parse_iso(e["data"].get("OldTime", "")), parse_iso(e["data"].get("NewTime", ""))
        if old and new and abs((new - old).total_seconds()) > 120:
            ev.append(Evidence(f"Время изменено: {fmt_dt(old)} → {fmt_dt(new)} (на {int((new - old).total_seconds())} с)",
                               time=e["time"], source="System 1 (Kernel-General)"))
    for e in query("Security", [4616], 50):
        proc = e["data"].get("ProcessName", "")
        if proc.lower().endswith(("svchost.exe",)):
            continue
        prev, new = parse_iso(e["data"].get("PreviousTime", "")), parse_iso(e["data"].get("NewTime", ""))
        if prev and new and abs((new - prev).total_seconds()) > 120:
            ev.append(Evidence(f"Время изменено процессом {proc}: {fmt_dt(prev)} → {fmt_dt(new)}",
                               time=e["time"], source="Security 4616"))
    if ev:
        newest = max((x.time for x in ev if x.time), default=None)
        ctx.add("HIGH" if ctx.is_recent(newest) else "MEDIUM", "Обходы", "Системное время изменялось вручную",
                "Изменив время, можно «спрятать» запуск файлов и очистку в прошлом: Prefetch, BAM и другие "
                "артефакты получат ложные метки времени.", ev, kb=["База/5. Eventvwr/Date Time"])


def _services(ctx):
    stops, changes, installs = [], [], []
    for e in query("System", [7036, 7040, 7034, 7045], 600):
        name = _bin_name(e["binary"]).lower() if e["binary"] else ""
        disp = e["data"].get("param1", "")
        if e["id"] == 7045:
            img = e["data"].get("ImagePath", "")
            p = normalize_path(img)
            hits = keyword_hits(img)
            if hits or re.search(r"\\(users|temp|downloads|appdata)\\", p, re.I):
                installs.append(Evidence(f"Установлена служба/драйвер «{e['data'].get('ServiceName', '')}»: {img}"
                                         + (f" [совпадение: {hits_text(hits)}]" if hits else ""),
                                         path=p, time=e["time"], source="System 7045"))
            continue
        key = name or disp.lower()
        matched = next((s for s in CRIT_SERVICES if s == key or s in key.replace(" ", "")), None)
        if not matched:
            continue
        if e["id"] == 7040:
            changes.append(Evidence(f"{disp}: тип запуска «{e['data'].get('param2', '')}» → «{e['data'].get('param3', '')}»",
                                    time=e["time"], source="System 7040"))
        elif e["id"] == 7036:
            state = e["data"].get("param2", "")
            if re.search(r"stop|останов", state, re.I):
                stops.append(Evidence(f"{disp}: {state}", time=e["time"], source="System 7036"))
        elif e["id"] == 7034:
            stops.append(Evidence(f"{disp}: служба неожиданно завершилась", time=e["time"], source="System 7034"))
    for ev, title in ((stops, "Ключевые службы останавливались"), (changes, "Менялся тип запуска ключевых служб")):
        if ev:
            newest = max((x.time for x in ev if x.time), default=None)
            ctx.add("CRITICAL" if ctx.is_recent(newest) else "MEDIUM", "Службы", title,
                    "Остановка SysMain/PcaSvc/DPS/EventLog/BAM отключает запись артефактов. Сопоставьте время "
                    "с запусками подозрительных файлов.", ev,
                    kb=["База/7. Службы/1. Что такое службы и зачем они нужны", "База/5. Eventvwr/PCA Check"])
    if installs:
        ctx.add("HIGH", "Службы", "Устанавливались службы/драйверы из пользовательских папок",
                "Драйвер или служба из Temp/Downloads/AppData — частый способ загрузки инжекторов (kdmapper и т.п.).",
                installs, kb=["База/7. Службы/1. Что такое службы и зачем они нужны"])


def _powershell(ctx):
    ev = {}
    events = query("Microsoft-Windows-PowerShell/Operational", [4104], 400) + \
        query("Windows PowerShell", [400, 403, 600, 800], 300)
    for e in events:
        text = e["data"].get("ScriptBlockText") or " ".join(e["values"])
        if "HostApplication=" in text:
            m = re.search(r"HostApplication=([^\r\n]+)", text)
            if m:
                text = m.group(1)
        for sev, desc, m in suspicious_commands(text):
            if "ss_checker" in text.lower() or "get-authenticodesignature" in text.lower():
                continue
            key = (desc, m)
            if key not in ev:
                ev[key] = (sev, Evidence(f"{desc}: …{text[max(0, text.lower().find(m) - 80):text.lower().find(m) + 160]}…",
                                         time=e["time"], source=f"{e['log']} {e['id']}"))
        hits = keyword_hits(text)
        if hits and any(s == "HIGH" for _, s in hits):
            ev[("kw", hits_text(hits))] = ("HIGH", Evidence(f"Названия читов в команде PowerShell [{hits_text(hits)}]: "
                                                            f"{text[:300]}", time=e["time"], source=f"{e['log']} {e['id']}"))
    if ev:
        order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        sev = min((s for s, _ in ev.values()), key=order.index)
        ctx.add(sev, "Команды", "Журнал PowerShell: выполнялись команды обхода/чистки",
                "PowerShell пишет выполненные скрипты в журнал (4104, 400, 600, 800).",
                [x for _, x in sorted(ev.values(), key=lambda v: order.index(v[0]))],
                kb=["База/5. Eventvwr/Powershell", "База/4. Win+R/Powershell History"])


def _process_creation(ctx):
    evs = query("Security", [4688], 3000)
    if not evs:
        return
    ctx.log.info(f"Аудит создания процессов включён: {len(evs)} событий 4688")
    sus = []
    for e in evs:
        path = e["data"].get("NewProcessName", "")
        cmd = e["data"].get("CommandLine", "")
        if path:
            ctx.add_exec(normalize_path(path), "Security 4688", e["time"], note=cmd[:200])
        for sev, desc, m in suspicious_commands(cmd):
            if sev in ("CRITICAL", "HIGH"):
                sus.append(Evidence(f"{desc}: {cmd[:300]}", time=e["time"], source="Security 4688"))
    if sus:
        ctx.add("HIGH", "Команды", "Аудит процессов: запускались команды обхода/чистки",
                "Событие 4688 содержит командную строку созданного процесса.", sus[:100],
                kb=["База/7. Службы/EventLog"])


def _defender(ctx):
    log = "Microsoft-Windows-Windows Defender/Operational"
    det, excl, off = [], [], []
    for e in query(log, [1116, 1117, 5001, 5007, 5013], 300):
        d = e["data"]
        if e["id"] in (1116, 1117):
            path = d.get("Path", "")
            det.append(Evidence(f"{d.get('Threat Name', '')} → {path}", path=normalize_path(path.split(";")[0].replace("file:_", "")),
                                time=e["time"], source=f"Defender {e['id']}"))
        elif e["id"] == 5007:
            nv = d.get("New Value", "")
            if "Exclusions" in nv:
                hits = keyword_hits(nv)
                excl.append(Evidence(nv + (f" [совпадение: {hits_text(hits)}]" if hits else ""), time=e["time"],
                                     source="Defender 5007"))
        elif e["id"] in (5001, 5013):
            off.append(Evidence("Защита в реальном времени отключена" if e["id"] == 5001 else
                                "Защита от подделки заблокировала изменение", time=e["time"], source=f"Defender {e['id']}"))
    if det:
        newest = max((x.time for x in det if x.time), default=None)
        ctx.add("HIGH" if ctx.is_recent(newest) else "MEDIUM", "Файлы", "Защитник Windows обнаруживал угрозы",
                "Читы и инжекторы часто детектятся как HackTool/Trojan. Пути в событиях показывают, где лежали файлы.",
                det[:80], kb=["База/2. Программы/System Informer/MsMpEng"], tools=["VirusTotal"])
    if excl:
        ctx.add("MEDIUM", "Обходы", "В исключения Защитника добавлялись папки/файлы",
                "Исключения позволяют держать читы на диске без детекта. Проверьте добавленные пути.", excl,
                kb=["База/2. Программы/System Informer/MsMpEng"])
    if off:
        newest = max((x.time for x in off if x.time), default=None)
        ctx.add("MEDIUM" if ctx.is_recent(newest) else "LOW", "Обходы", "Защита Защитника Windows отключалась",
                "", off[:30])


def _bits(ctx):
    ev = []
    for e in query("Microsoft-Windows-Bits-Client/Operational", [3, 4, 59, 60], 200):
        url = e["data"].get("url") or e["data"].get("Url") or ""
        name = e["data"].get("jobTitle") or e["data"].get("name") or ""
        if url and not re.search(r"(microsoft|windowsupdate|msedge|office|bing|live)\.(com|net)", url, re.I):
            ev.append(Evidence(f"{name}: {url}", url=url, time=e["time"], source=f"Bits-Client {e['id']}"))
    if ev:
        ctx.add("LOW", "Сеть", "Скачивание файлов через BITS (без браузера)",
                "BITS позволяет скачать файл без браузера (bitsadmin). Проверьте ссылки.", ev[:50],
                kb=["База/5. Eventvwr/BitsAdmin"])


def _pca(ctx):
    n = 0
    for e in query("Microsoft-Windows-Application-Experience/Program-Compatibility-Assistant", None, 300):
        for v in e["values"]:
            if re.match(r"^[A-Za-z]:\\.+\.\w{2,4}$", v):
                ctx.add_exec(normalize_path(v), "Журнал PCA", e["time"])
                n += 1
    ctx.log.info(f"Журнал PCA: {n} путей")


def _pnp(ctx):
    rows = []
    for e in query("Microsoft-Windows-Kernel-PnP/Configuration", [400, 410, 420], 60):
        dev = e["data"].get("DeviceInstanceId", "")
        if "USBSTOR" in dev.upper() or "STORAGE\\VOLUME" in dev.upper() or e["id"] == 420:
            rows.append([fmt_dt(e["time"]), {400: "настроено", 410: "запущено", 420: "удалено"}.get(e["id"], e["id"]), dev])
    ctx.table("pnp", "Kernel-PnP: подключение/удаление накопителей (400/410/420)", ["Время", "Событие", "Устройство"], rows)
    recent = [r for r in rows if r[1] == "удалено"]
    if recent:
        ctx.log.info(f"Kernel-PnP: {len(recent)} событий удаления устройств — см. таблицу")


def _shutdowns(ctx):
    rows = []
    for e in query("System", [1074, 6006, 6008, 41], 20):
        desc = {1074: "выключение/перезагрузка (инициатор)", 6006: "журнал остановлен (выключение)",
                6008: "неожиданное выключение", 41: "перезагрузка без корректного завершения"}.get(e["id"])
        extra = e["data"].get("param1", "") if e["id"] == 1074 else ""
        rows.append([fmt_dt(e["time"]), e["id"], desc, extra])
    ctx.table("shutdowns", "Выключения и перезагрузки", ["Время", "ID", "Событие", "Процесс"], rows)


def _oldest(ctx):
    install = ctx.system.get("install_date")
    rows = []
    for log in ("System", "Security", "Application", "Microsoft-Windows-PowerShell/Operational",
                "Windows PowerShell"):
        evs = query(log, None, 1, newest=False)
        t = evs[0]["time"] if evs else None
        rows.append([log, fmt_dt(t)])
        if t and (not install or t - install > timedelta(days=1)):
            if ctx.is_recent(t):
                ctx.add("CRITICAL", "Чистка", f"Журнал «{log}» начинается незадолго до проверки",
                        "Самая старая запись журнала сделана недавно — журнал очищали или пересоздавали.",
                        [Evidence(f"Первая запись: {fmt_dt(t)}", time=t, source=log)],
                        kb=["Обходы/Обнаружение чистки/Чистка EventLog"])
            elif ctx.start - t < timedelta(hours=24) and log in ("System", "Application"):
                ctx.add("MEDIUM", "Чистка", f"Журнал «{log}» содержит события только за последние сутки",
                        "Для System/Application это нетипично — журнал мог быть очищен.",
                        [Evidence(f"Первая запись: {fmt_dt(t)}", time=t, source=log)],
                        kb=["Обходы/Обнаружение чистки/Чистка EventLog"])
    ctx.table("eventlog_span", "Глубина журналов событий", ["Журнал", "Первая запись"], rows)
