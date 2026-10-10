"""Сетевые твики для фейк-лагов (База → 8. Сеть)."""
import re

from .. import kb
from ..core import Evidence
from ..winutil import IS_WIN, reg_get, reg_open, reg_subkeys, reg_values, run

NET_KB = "База/8. Сеть/"


def _match(mode, val, expected):
    if val is None:
        return False
    if mode == "exists":
        return True
    try:
        v = int(val)
    except (TypeError, ValueError):
        return False
    if mode == "eq":
        return v == expected
    if mode == "lt":
        return v < expected
    return False


def run_check(ctx):
    if not IS_WIN:
        ctx.log.warn("Не Windows — сеть пропущена")
        return
    found = []
    for path, name, mode, expected, sev, desc, art in kb.NETWORK_TWEAKS:
        v = reg_get("HKLM", path, name, None)
        if _match(mode, v, expected):
            found.append((sev, Evidence(f"HKLM\\{path}\\{name} = {v}  — {desc}", source=art)))
    base = kb.TCPIP + r"\Interfaces"
    for iface in reg_subkeys(reg_open("HKLM", base)):
        vals = {n: d for n, d, t in reg_values(reg_open("HKLM", base + "\\" + iface))}
        ip = vals.get("DhcpIPAddress") or ""
        if not ip and isinstance(vals.get("IPAddress"), list) and vals["IPAddress"]:
            ip = vals["IPAddress"][0]
        for name, desc in kb.INTERFACE_TWEAKS:
            if name in vals:
                found.append(("HIGH", Evidence(f"Интерфейс {iface} ({ip}): {name} = {vals[name]}  — {desc}",
                                               source="Nagle’s Algorithm и задержка ACK")))
    for sub in reg_subkeys(reg_open("HKLM", kb.NIC_CLASS)):
        if not sub.isdigit():
            continue
        vals = {n: d for n, d, t in reg_values(reg_open("HKLM", kb.NIC_CLASS + "\\" + sub))}
        desc_name = vals.get("DriverDesc", sub)
        if not vals.get("NetCfgInstanceId") or re.search(r"wan miniport|virtual|vpn|tap|bluetooth|loopback|"
                                                         r"kernel debug|hyper-v", str(desc_name), re.I):
            continue
        for name, mode, expected, sev, desc in kb.NIC_TWEAKS:
            if _match(mode, vals.get(name), expected) and sev != "INFO":
                found.append((sev, Evidence(f"{desc_name}: {name} = {vals.get(name)}  — {desc}",
                                            source="Манипуляции с разгрузкой (Offload Abuse) / Driver Keys")))
    # netsh int tcp show global
    rc, out = run(["netsh", "int", "tcp", "show", "global"], 30)
    checks = [
        (r"(Receive-Side Scaling State|масштабирования на стороне приема)\s*:\s*(\S+)", "enabled", "RSS должен быть enabled"),
        (r"(Receive Segment Coalescing State|объединения сегментов приема)\s*:\s*(\S+)", "enabled", "RSC должен быть enabled"),
        (r"(ECN Capability|Мощность ECN)\s*:\s*(\S+)", "disabled", "ECN должен быть disabled"),
    ]
    for rx, want, desc in checks:
        m = re.search(rx, out, re.I)
        if m and m.group(2).lower() not in (want, "включено" if want == "enabled" else "отключено",
                                            "включен" if want == "enabled" else "отключен"):
            found.append(("LOW", Evidence(f"netsh: {m.group(1)} = {m.group(2)}  — {desc}", source="Проверка RSS, RSC, ECN")))
    m = re.search(r"(Add-On Congestion Control Provider|контроля перегрузки)\s*:\s*(\S+)", out, re.I)
    if m and m.group(2).lower() not in ("default", "cubic", "по", "нет"):
        found.append(("MEDIUM", Evidence(f"netsh: провайдер контроля перегрузки = {m.group(2)}",
                                         source="Проверка RSS, RSC, ECN")))
    if not found:
        ctx.log.ok("Сетевых твиков из базы не найдено")
        return
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    sev = min((s for s, _ in found), key=order.index)
    ctx.add(sev, "Сеть", "Изменены сетевые параметры (возможны фейк-лаги)",
            "Кастомные настройки TCP/IP используют для искусственного ухудшения соединения: пакеты копятся, "
            "ACK задерживаются, и для других игроков персонаж «дёргается». Параметры с пометкой «бан за "
            "имеющееся значение» в базе считаются нарушением при самом факте их наличия. Часть параметров "
            "(LSO, InterruptModeration) драйверы выставляют сами — сверяйте с дефолтами.",
            [e for _, e in sorted(found, key=lambda x: order.index(x[0]))],
            kb=[NET_KB + "1. Общие сведения", NET_KB + "Nagle’s Algorithm и задержка ACK", NET_KB + "Packet Loss Abuse"],
            tools=["Network Scanner"])
