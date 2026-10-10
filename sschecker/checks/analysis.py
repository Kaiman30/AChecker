"""Сводный анализ всех следов запусков из разных источников + проверка подписей."""
import os
import re
from collections import defaultdict

from .. import kb
from ..core import Evidence, fmt_dt
from ..match import hits_text, keyword_hits, top_severity
from ..winutil import IS_WIN, authenticode, normalize_path, path_exists, zone_identifier

# Источники, которые фиксируют ТОЛЬКО запуск исполняемых файлов
EXEC_ONLY = {"BAM", "Prefetch", "PCA AppLaunchDic", "DPS (память)", "DiagTrack (память)",
             "AppInfo (запуск от администратора)", "CDPUserSvc (память)", "Security 4688",
             "Compatibility Assistant Store", "AppCompatFlags Layers", "PcaSvc (память)"}
_OK_EXT = kb.EXEC_EXTS | {".dll", ".jar", ".tmp"}  # .tmp — установщики Inno Setup


def _key(p):
    return p.lower().rstrip("\\")


def run_check(ctx):
    groups = defaultdict(list)
    for r in ctx.executions:
        p = normalize_path(r.path)
        if not p:
            continue
        groups[_key(p)].append((p, r))
    ctx.log.info(f"Всего следов: {len(ctx.executions)}, уникальных путей/имён: {len(groups)}")
    drive_types = {row[0][:2].upper(): row[1] for row in ctx.shared.get("drives", [])}
    sysdrive = os.environ.get("SystemDrive", "C:").upper()

    kw_exec, kw_access, ext_mod, deleted_recent, deleted_old, removable = [], [], [], [], [], []
    sign_candidates = list(ctx.shared.get("sign_candidates", []))
    timeline = []
    per_path = {}
    for key, items in groups.items():
        path = items[0][0]
        recs = [r for _, r in items]
        sources = sorted({r.source for r in recs})
        times = sorted([r.time for r in recs if r.time], reverse=True)
        last = times[0] if times else None
        is_exec = any(r.kind == "exec" for r in recs)
        full = bool(re.match(r"^[A-Za-z?]:\\", path))
        exists = path_exists(path) if full else None
        ext = os.path.splitext(path.lower())[1]
        flags = []
        hits = keyword_hits(path, weak=ext in _OK_EXT or ext == "")
        if hits:
            flags.append("совпадение: " + hits_text(hits))
            (kw_exec if is_exec else kw_access).append((top_severity(hits), path, sources, last, exists, hits))
        exec_only_src = [s for s in sources if s in EXEC_ONLY]
        if exec_only_src and ext and ext not in _OK_EXT and len(ext) <= 8 and not re.match(r"^\.\d+$", ext):
            flags.append("изменённое расширение")
            ext_mod.append((path, exec_only_src, last))
        if is_exec and exists is False and full and re.search(r"\\(users|temp|downloads|desktop)\\|^[d-z]:\\", path, re.I) \
                and not re.search(r"\\appdata\\local\\temp\\[^\\]+\.tmp\\|\\appdata\\local\\temp\\(is|nsx|nsu|nsa)-", path, re.I):
            flags.append("файл удалён")
            (deleted_recent if ctx.is_recent(last) else deleted_old).append((path, sources, last))
        if is_exec and full:
            letter = path[:2].upper()
            if letter != sysdrive and letter[0] != "?":
                dtype = drive_types.get(letter)
                if dtype == "съёмный" or dtype is None:
                    flags.append("съёмный/отключённый носитель")
                    removable.append((path, sources, last, dtype))
            if exists and ext in (".exe", ".dll") and not re.search(r"\\(windows|program files[^\\]*)\\", path, re.I):
                sign_candidates.append(path)
        per_path[key] = flags
        for p, r in items:
            if r.time or flags:
                timeline.append([r.time, r.source, p, r.note, "да" if exists else ("нет" if exists is False else "?"),
                                 "; ".join(flags)])

    # --- подписи ---
    sigs = {}
    if IS_WIN and sign_candidates:
        cands = list(dict.fromkeys(sign_candidates))[:500]
        ctx.log.info(f"Проверка цифровых подписей: {len(cands)} файлов…")
        sigs = authenticode(cands)
    bad_sig, unsigned = [], []
    for p, (status, signer) in sigs.items():
        if status in ("HashMismatch", "NotTrusted", "UnknownError", "Incompatible"):
            bad_sig.append((p, status, signer))
        elif status == "NotSigned":
            unsigned.append(p)

    # --- находки ---
    def ev_for(path, sources, last, extra=""):
        z = zone_identifier(path) if path_exists(path) else {}
        url = z.get("HostUrl") or z.get("ReferrerUrl") or ""
        txt = f"{path}{extra}  ← {', '.join(sources)}" + (f"  (скачан: {url})" if url else "")
        return Evidence(txt, path=path, time=last, url=url if url.startswith("http") else None)

    if kw_exec:
        kw_exec.sort(key=lambda x: (["HIGH", "MEDIUM", "LOW"].index(x[0]), -(x[3].timestamp() if x[3] else 0)))
        sev = {"HIGH": "CRITICAL", "MEDIUM": "HIGH", "LOW": "MEDIUM"}[kw_exec[0][0]]
        ctx.add(sev, "Запуски", "Запускались файлы с названиями читов",
                "Сводка по всем источникам следов запуска (BAM, Prefetch, PCA, UserAssist, ShimCache, DPS, память "
                "служб и др.). Чем больше независимых источников подтверждают запуск — тем надёжнее доказательство.",
                [ev_for(p, s, t, f"  [{hits_text(h)}]" + ("" if ex is not False else "  (файл удалён)"))
                 for _, p, s, t, ex, h in kw_exec[:200]],
                kb=["База/1. Артефакты/📌Введение", "База/1. Артефакты/BAM", "База/1. Артефакты/Prefetch"],
                tools=["BAM Parser (RedLotus)", "WinPrefetchView", "CachedProgramList"])
    if kw_access:
        kw_access.sort(key=lambda x: ["HIGH", "MEDIUM", "LOW"].index(x[0]))
        sev = {"HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW"}[kw_access[0][0]]
        ctx.add(sev, "Файлы", "Обращения к файлам с названиями читов (открытие/хранение)",
                "Источники вида Recent, JumpLists, корзина, память Explorer показывают, что файл был на ПК или "
                "открывался, но не обязательно запускался.",
                [ev_for(p, s, t, f"  [{hits_text(h)}]") for _, p, s, t, ex, h in kw_access[:200]],
                kb=["База/1. Артефакты/Recent", "База/1. Артефакты/JumpLists"])
    if ext_mod:
        ctx.add("CRITICAL", "Обходы", "Запускались файлы с изменённым расширением",
                "Эти источники фиксируют только запуск исполняемых файлов, но у файла другое расширение. "
                "Значит .exe переименовали (например, в .png) и запустили через wmic/start/cmd.",
                [ev_for(p, s, t) for p, s, t in ext_mod[:150]],
                kb=["Обходы/Различные методы/Измененные расширения", "База/6. Реестр/BAM"])
    if deleted_recent:
        ctx.add("HIGH", "Чистка", "Незадолго до проверки запускались файлы, которых уже нет на диске",
                "Программа запускалась в окне перед проверкой, а затем файл удалили/переместили.",
                [ev_for(p, s, t) for p, s, t in sorted(deleted_recent, key=lambda x: x[2].timestamp() if x[2] else 0, reverse=True)[:150]],
                kb=["База/1. Артефакты/BAM", "База/2. Программы/Spokwn/JournalTrace"], tools=["JournalTrace"])
    if deleted_old:
        ctx.add("LOW", "Запуски", "Запускались файлы, которых уже нет на диске (давно)",
                "Список для ручной проверки: удалённые программы из пользовательских папок и с других дисков.",
                [ev_for(p, s, t) for p, s, t in sorted(deleted_old, key=lambda x: x[2].timestamp() if x[2] else 0,
                                                        reverse=True)[:150]],
                kb=["База/1. Артефакты/BAM"])
    if removable:
        ctx.add("MEDIUM", "USB", "Запуски с других дисков/съёмных носителей",
                "Читы держат на флешке или на диске, который отключают перед проверкой.",
                [ev_for(p, s, t, f"  (диск {'сейчас не подключён' if d is None else d})") for p, s, t, d in removable[:150]],
                kb=["База/1. Артефакты/USB", "Обходы/Различные методы/FAT32"], tools=["System Informer"])
    if bad_sig:
        ctx.add("HIGH", "Обходы", "Файлы с недействительной/поддельной цифровой подписью",
                "HashMismatch — файл изменён после подписи (hex replace), NotTrusted/UnknownError — самоподписанный "
                "или поддельный сертификат. Так маскируют читы под легитимные программы.",
                [Evidence(f"{p}: {st} {sg}", path=p) for p, st, sg in bad_sig],
                kb=["Обходы/Различные методы/Легитимные программы", "Обходы/Различные методы/Hex replace"],
                tools=["Signatures.ps1", "DiE"])
    if unsigned:
        ctx.add("LOW", "Запуски", "Запускались неподписанные исполняемые файлы из пользовательских папок",
                "Само по себе не нарушение (многие программы без подписи), но это первый список для ручной проверки "
                "в DiE (упаковщики Themida/VMProtect, строки aimbot/esp/hwid).",
                [Evidence(p, path=p) for p in unsigned[:200]], kb=["База/2. Программы/DiE"], tools=["DiE", "VirusTotal"])

    timeline.sort(key=lambda r: r[0].timestamp() if r[0] else 0, reverse=True)
    rows = [[fmt_dt(t), src, p, note, ex, fl] for t, src, p, note, ex, fl in timeline[:5000]]
    ctx.table("timeline", "Хронология запусков и обращений (все источники)",
              ["Время", "Источник", "Путь", "Примечание", "Существует", "Признаки"], rows,
              note="Время — в часовом поясе проверяемого ПК. В ShimCache/DPS время не является временем запуска.")
    ctx.shared["signatures"] = sigs
