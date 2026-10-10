"""Состояние служб, на которых держится проверка (База → 7. Службы, Обходы → Threads)."""
import re

from .. import kb
from ..core import Evidence, fmt_dt
from ..winutil import (IS_WIN, process_create_time, ps_json, reg_get, reg_open, reg_subkeys, run,
                       service_pids)

START_TYPES = {0: "Boot", 1: "System", 2: "Автоматически", 3: "Вручную", 4: "ОТКЛЮЧЕНА"}
STATE_RE = re.compile(r":\s*(\d)\s+(RUNNING|STOPPED|START_PENDING|STOP_PENDING|PAUSED|CONTINUE_PENDING|PAUSE_PENDING)")


def _resolve_name(name: str) -> str:
    """CDPUserSvc_xxxxx — имя динамическое."""
    if name != "CDPUserSvc":
        return name
    k = reg_open("HKLM", r"SYSTEM\CurrentControlSet\Services")
    for sub in reg_subkeys(k):
        if sub.lower().startswith("cdpusersvc_"):
            return sub
    return name


def run_check(ctx):
    if not IS_WIN:
        ctx.log.warn("Не Windows — проверка служб пропущена")
        return
    pids = service_pids()
    boot = ctx.system.get("boot")
    rows = []
    service_info = {}
    for base_name, desc, thread_dll, sev in kb.SERVICES:
        name = _resolve_name(base_name)
        rc, out = run(["sc", "queryex", name], 20)
        m = STATE_RE.search(out)
        state = m.group(2) if m else ("НЕ НАЙДЕНА" if rc != 0 else "?")
        start = reg_get("HKLM", rf"SYSTEM\CurrentControlSet\Services\{name}", "Start", None)
        pid = pids.get(name.lower())
        started = process_create_time(pid) if pid else None
        service_info[base_name] = {"name": name, "state": state, "start": start, "pid": pid, "started": started}
        rows.append([name, desc, state, START_TYPES.get(start, start), pid or "", fmt_dt(started)])
        problems = []
        if start == 4:
            problems.append("тип запуска «Отключена»")
        if state != "RUNNING" and base_name != "WSearch":
            problems.append(f"состояние {state}")
        if problems:
            ctx.add(sev, "Службы", f"Служба {name} не работает ({', '.join(problems)})",
                    f"{desc}. Если ключевые службы отключены, следы запусков не пишутся — проверку нельзя "
                    f"считать полноценной.",
                    [Evidence(f"sc queryex {name}: {state}; Start={START_TYPES.get(start, start)}",
                              source=rf"HKLM\SYSTEM\CurrentControlSet\Services\{name}")],
                    kb=["База/7. Службы/1. Что такое службы и зачем они нужны", f"База/7. Службы/{base_name}"],
                    recommendation="Попросите игрока объяснить, зачем служба отключена; проверьте журнал "
                                   "System (7036/7040) — когда это произошло.")
        elif started and boot and (started - boot).total_seconds() > 600:
            sev2 = "HIGH" if ctx.is_recent(started) else "MEDIUM"
            if base_name in ("SysMain", "PcaSvc", "DPS", "EventLog", "DiagTrack", "DusmSvc"):
                ctx.add(sev2, "Службы", f"Служба {name} перезапускалась после загрузки системы",
                        "Служба стартовала значительно позже загрузки ПК: её останавливали и запускали снова. "
                        "При перезапуске память службы (строки DPS/PcaSvc и т.п.) очищается.",
                        [Evidence(f"Загрузка ПК: {fmt_dt(boot)}", time=boot),
                         Evidence(f"Процесс службы (PID {pid}) запущен: {fmt_dt(started)}", time=started)],
                        kb=["База/5. Eventvwr/PCA Check", "Обходы/Различные методы/Threads"])
    ctx.table("services", "Службы", ["Служба", "Назначение", "Состояние", "Тип запуска", "PID", "Процесс запущен"],
              rows)
    ctx.shared["services"] = service_info
    _check_threads(ctx, service_info)


def _check_threads(ctx, info):
    """Обходы → Threads: службу оставляют запущенной, но приостанавливают её потоки."""
    pids = sorted({v["pid"] for v in info.values() if v.get("pid")})
    if not pids:
        return
    script = (
        "$r = foreach($id in @(%s)){ $p = Get-Process -Id $id -ErrorAction SilentlyContinue; if($p){"
        "$t = $p.Threads; $s = @($t | Where-Object { $_.ThreadState -eq 'Wait' -and $_.WaitReason -eq 'Suspended' });"
        "[pscustomobject]@{pid=$id; total=$t.Count; suspended=$s.Count; ids=($s | ForEach-Object { $_.Id }) -join ','} } };"
        "ConvertTo-Json -Compress -InputObject @($r)" % ",".join(str(p) for p in pids)
    )
    data = ps_json(script, 120) or []
    by_pid = {d.get("pid"): d for d in data if isinstance(d, dict)}
    for base, v in info.items():
        d = by_pid.get(v.get("pid"))
        if not d:
            continue
        total, susp = d.get("total") or 0, d.get("suspended") or 0
        if susp and (susp == total or susp >= 1):
            thread_dll = next((t for n, _, t, _ in kb.SERVICES if n == base), None)
            sev = "CRITICAL" if total and susp >= max(1, total // 2) else "HIGH"
            ctx.add(sev, "Обходы", f"У службы {v['name']} приостановлены потоки ({susp} из {total})",
                    "Служба выглядит запущенной, но её потоки заморожены — она не записывает артефакты. "
                    "Это известный способ обхода проверки."
                    + (f" Обычно останавливают поток модуля {thread_dll}." if thread_dll else ""),
                    [Evidence(f"PID {v['pid']}: приостановленные потоки {d.get('ids')}")],
                    kb=["Обходы/Различные методы/Threads"], tools=["System Informer"],
                    recommendation="В System Informer откройте процесс службы → Threads и проверьте поток "
                                   f"{thread_dll or ''}.")
