"""Сведения о системе, виртуальные машины, WinRM, запущенные процессы (javaw)."""
import os
import platform
import re

from ..core import Evidence, fmt_dt
from ..match import hits_text, keyword_hits, suspicious_commands, top_severity
from ..winutil import (IS_WIN, boot_time, current_user_sid, drives, is_admin, normalize_path,
                       parse_iso, process_list, reg_get, reg_open, reg_values, run,
                       volume_info)

VM_MARKERS = ["vmware", "virtualbox", "vbox", "innotek", "qemu", "xen", "parallels", "kvm", "bochs",
              "virtual machine", "hyper-v", "bhyve", "proxmox"]
VM_SERVICES = ["VBoxGuest", "VBoxMouse", "VBoxSF", "VBoxService", "vmhgfs", "vmmouse", "vm3dmp",
               "VMTools", "vmci", "vioscsi", "viostor", "netkvm", "xenevtchn", "xenbus", "prl_fs",
               "QEMU-GA"]


def run_check(ctx):
    log = ctx.log
    s = ctx.system
    s["hostname"] = platform.node()
    s["user"] = os.environ.get("USERNAME", "")
    s["sid"] = current_user_sid() if IS_WIN else ""
    s["os"] = f"{platform.system()} {platform.release()} ({platform.version()})"
    s["admin"] = is_admin()
    s["boot"] = boot_time()
    s["scan_start"] = ctx.start
    s["window_start"] = ctx.window_start
    if IS_WIN:
        build = reg_get("HKLM", r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "DisplayVersion", "")
        prod = reg_get("HKLM", r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "ProductName", "")
        cur = reg_get("HKLM", r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "CurrentBuild", "")
        s["os"] = f"{prod} {build} (сборка {cur})"
        inst = reg_get("HKLM", r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "InstallDate", 0)
        if inst:
            from ..winutil import unix_to_dt
            s["install_date"] = unix_to_dt(inst)
    log.info(f"Компьютер: {s['hostname']}, пользователь: {s['user']} {s['sid']}")
    log.info(f"ОС: {s['os']}")
    log.info(f"Последняя загрузка: {fmt_dt(s['boot'])}")
    if not s["admin"]:
        ctx.add("HIGH", "Система", "Сканер запущен без прав администратора",
                "Без прав администратора недоступны USN-журнал, журнал Security, память системных служб, "
                "часть реестра. Результаты будут неполными.",
                recommendation="Перезапустите сканер от имени администратора.")
    if s.get("boot") and ctx.is_recent(s["boot"]):
        ctx.add("MEDIUM", "Система", "Компьютер перезагружался незадолго до проверки",
                "Перезагрузка очищает память процессов (DPS, PcaSvc, Explorer, javaw) — строки, которые "
                "ищут через System Informer, теряются. Это частый способ «почистить» следы перед проверкой.",
                [Evidence(f"Время загрузки: {fmt_dt(s['boot'])}", time=s["boot"])],
                kb=["База/1. Артефакты/📌Введение (дамп памяти процесса)"])

    # Диски
    rows = []
    for root, t in drives((2, 3, 4)):
        label, fs = volume_info(root)
        rows.append([root, {2: "съёмный", 3: "локальный", 4: "сетевой"}.get(t, t), label, fs])
        if fs and fs.upper().startswith("FAT") or fs.upper() == "EXFAT":
            ctx.add("MEDIUM", "Обходы", f"Диск {root} в файловой системе {fs}",
                    "FAT32/exFAT не ведут USN-журнал — удаление и замену файлов на таком носителе не видно "
                    "в JournalTrace. Нужно проверять через FTK Imager.",
                    [Evidence(f"{root} «{label}» — {fs}", path=root)],
                    kb=["Обходы/Различные методы/FAT32"], tools=["FTK Imager"])
    ctx.table("drives", "Подключённые диски", ["Диск", "Тип", "Метка", "ФС"], rows)
    ctx.shared["drives"] = rows

    _check_vm(ctx)
    _check_winrm(ctx)
    _check_processes(ctx)


def _check_vm(ctx):
    if not IS_WIN:
        return
    ev = []
    bios = {}
    for name in ("SystemManufacturer", "SystemProductName", "BIOSVendor", "BaseBoardManufacturer",
                 "BaseBoardProduct", "BIOSVersion"):
        v = reg_get("HKLM", r"HARDWARE\DESCRIPTION\System\BIOS", name, "")
        bios[name] = v
        if isinstance(v, str) and any(m in v.lower() for m in VM_MARKERS):
            ev.append(Evidence(f"BIOS {name} = «{v}»", source="HKLM\\HARDWARE\\DESCRIPTION\\System\\BIOS"))
    ctx.system["model"] = f"{bios.get('SystemManufacturer', '')} {bios.get('SystemProductName', '')}".strip()
    disk_enum = reg_open("HKLM", r"SYSTEM\CurrentControlSet\Services\disk\Enum")
    for n, v, _ in reg_values(disk_enum):
        if isinstance(v, str) and any(m in v.lower() for m in ("vbox", "vmware", "qemu", "virtual_disk", "xen")):
            ev.append(Evidence(f"Диск: {v}", source="HKLM\\SYSTEM\\CurrentControlSet\\Services\\disk\\Enum"))
    for svc in VM_SERVICES:
        if reg_open("HKLM", rf"SYSTEM\CurrentControlSet\Services\{svc}") is not None:
            ev.append(Evidence(f"Драйвер/служба гостевой ОС: {svc}"))
    if ev:
        ctx.add("CRITICAL", "Обходы", "Проверка проходит внутри виртуальной машины",
                "Игрок может запускать проверку в ВМ, а играть — на основной системе. Все найденные "
                "артефакты относятся к виртуалке, а не к реальному ПК.",
                ev, kb=["Обходы/Виртуальные машины/Обнаружение вручную", "База/4. Win+R/Virtual machine"],
                tools=["VMAware"], recommendation="Попросите показать msinfo32 → «Модель системы» и запустить VMAware.")
    else:
        ctx.log.ok(f"Признаков виртуальной машины нет ({ctx.system['model']})")


def _check_winrm(ctx):
    if not IS_WIN:
        return
    rc, out = run(["sc", "query", "WinRM"], 20)
    running = bool(re.search(r":\s*4\s+RUNNING", out))
    rc, net = run(["netstat", "-ano"], 60)
    conns = [l.strip() for l in net.splitlines() if re.search(r":598[56]\s", l) and "ESTABLISHED" in l.upper()]
    if conns:
        ctx.add("CRITICAL", "Обходы", "Активное удалённое подключение PowerShell (WinRM)",
                "Во время проверки к ПК подключён кто-то через WinRM (порты 5985/5986) — он может удалять "
                "файлы, чистить реестр и закрывать процессы, пока вы отвлечены.",
                [Evidence(c) for c in conns], kb=["Обходы/Различные методы/WinRm"])
    elif running:
        ctx.add("MEDIUM", "Обходы", "Служба удалённого управления WinRM запущена",
                "Служба позволяет удалённо выполнять команды на ПК. Активных подключений сейчас нет.",
                [Evidence("sc query WinRM → RUNNING")], kb=["Обходы/Различные методы/WinRm"])


def _check_processes(ctx):
    if not IS_WIN:
        return
    procs = process_list()
    ctx.shared["processes"] = procs
    rows = []
    java = []
    for p in procs:
        name = p.get("name") or ""
        path = p.get("path") or ""
        cmd = p.get("cmd") or ""
        created = parse_iso(p.get("created") or "")
        hits = keyword_hits(path or name, weak=True)
        if hits:
            ctx.add("CRITICAL" if top_severity(hits) == "HIGH" else "HIGH", "Процессы",
                    f"Запущен подозрительный процесс: {name}",
                    f"Имя/путь процесса совпадает с базой читов ({hits_text(hits)}).",
                    [Evidence(f"PID {p.get('pid')}: {path or name}", path=path, time=created),
                     Evidence(f"Командная строка: {cmd}")])
        if path and not path.lower().startswith(("c:\\windows", "c:\\program files")):
            ctx.add_exec(path, "Запущенные процессы", created, note=f"PID {p.get('pid')}")
        if name.lower() in ("javaw.exe", "java.exe"):
            java.append(p)
        if name.lower() in ("powershell.exe", "pwsh.exe", "cmd.exe", "conhost.exe"):
            for sev, desc, m in suspicious_commands(cmd):
                ctx.add(sev, "Процессы", f"Консоль запущена с подозрительной командой: {desc}",
                        "Командная строка процесса содержит команду из списка обходов.",
                        [Evidence(f"PID {p.get('pid')}: {cmd}", time=created)])
        rows.append([p.get("pid"), name, path, fmt_dt(created)])
    ctx.table("processes", "Запущенные процессы", ["PID", "Имя", "Путь", "Запущен"], rows)
    ctx.shared["java_procs"] = java
    for p in java:
        cmd = p.get("cmd") or ""
        created = parse_iso(p.get("created") or "")
        ev = [Evidence(f"PID {p.get('pid')} {p.get('path')}", path=p.get("path"), time=created),
              Evidence(f"Командная строка: {cmd[:2000]}")]
        agents = re.findall(r"-javaagent:(\"[^\"]+\"|\S+)", cmd)
        if agents:
            ctx.add("HIGH", "Minecraft", "Minecraft запущен с java-агентом (-javaagent)",
                    "Java-агент внедряет код в игру при запуске — так подключаются инжект-читы. "
                    "Некоторые лаунчеры (например, authlib-injector в TLauncher) используют агент легально — "
                    "проверьте путь.", ev + [Evidence(f"Агент: {a}", path=normalize_path(a.strip('"')))
                                             for a in agents], kb=["Моды/3. Выгруженные моды"])
        hits = keyword_hits(cmd)
        if hits:
            ctx.add("CRITICAL", "Minecraft", "Командная строка Minecraft содержит названия читов",
                    f"Совпадения: {hits_text(hits)}", ev)
        jars = re.findall(r"-jar\s+(\"[^\"]+\"|\S+)", cmd)
        for j in jars:
            jp = normalize_path(j.strip('"'))
            ctx.add_exec(jp, "javaw -jar (процесс)", created)
    if java:
        ctx.log.info(f"Найдено процессов Java: {len(java)} — будут проверены модули и память")
        _java_modules(ctx, java)
    else:
        ctx.log.warn("Minecraft (javaw.exe) сейчас не запущен — проверка памяти игры и выгруженных модов недоступна")


def _java_modules(ctx, java):
    from ..winutil import ps_json
    for p in java:
        pid = p.get("pid")
        data = ps_json(f"$m=(Get-Process -Id {pid}).Modules | ForEach-Object {{ $_.FileName }};"
                       "ConvertTo-Json -Compress -InputObject @($m)", 120) or []
        sus = []
        for path in data:
            if not isinstance(path, str):
                continue
            low = path.lower()
            if low.startswith(("c:\\windows\\", "c:\\program files")):
                continue
            if re.search(r"\\(jre|jdk|java|runtime|bin)[^\\]*\\", low) and "\\temp\\" not in low:
                continue
            sus.append(path)
        jnh = [x for x in sus if "jnativehook" in x.lower()]
        if jnh:
            ctx.add("HIGH", "Minecraft", "В Minecraft загружена библиотека JNativeHook",
                    "JNativeHook перехватывает клавиатуру и мышь — её используют .jar-кликеры и инжект-читы.",
                    [Evidence(x, path=x) for x in jnh], kb=["База/4. Win+R/Temp"])
        other = [x for x in sus if x not in jnh]
        if other:
            ev = []
            for x in other:
                hits = keyword_hits(x)
                ev.append(Evidence(x + (f"  [совпадение: {hits_text(hits)}]" if hits else ""), path=x))
            ctx.add("MEDIUM", "Minecraft", "В процесс javaw загружены DLL из нестандартных папок",
                    "Сторонние DLL в процессе игры могут быть инжектом (вспомните Vape/vec.dll). Часть может "
                    "быть оверлеями (Discord, OBS, Nvidia) — проверьте подписи и пути.",
                    ev, kb=["База/2. Программы/System Informer/CSRSS (заинжекченные dll)"],
                    tools=["System Informer"])
