"""Моды Minecraft (Моды → 1–5, Вес модификаций, Everything → Jar Sizes / Doomsday)."""
import json
import os
import re

from .. import kb
from ..core import Evidence, fmt_dt
from ..match import hits_text, keyword_hits, top_severity
from ..parsers import analyze_jar
from ..winutil import mtime_dt, zone_identifier

APPDATA = os.environ.get("APPDATA", "")
PROFILE = os.environ.get("USERPROFILE", "")
SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
_LIB_DIRS = re.compile(r"\\(libraries|\.m2|\.gradle|gradle|jetbrains|intellij|eclipse|netbeans|android|"
                       r"node_modules|program files|programdata\\microsoft|windows|jdk[^\\]*|jre[^\\]*|java\\|"
                       r"runtime|maven|sdk|\.vscode|anaconda|python)\\", re.I)


def _find_mods_dirs(ctx):
    roots = [os.path.join(APPDATA, d) for d in kb.MC_DIRS_APPDATA] + [os.path.join(PROFILE, d) for d in kb.MC_DIRS_PROFILE]
    roots += ctx.opts.extra_paths
    found = set(ctx.shared.get("mods_dirs", set()))
    game_dirs = set()
    for r in roots:
        if not os.path.isdir(r):
            continue
        base_depth = r.rstrip("\\/").count(os.sep)
        for root, dirs, files in os.walk(r):
            depth = root.count(os.sep) - base_depth
            low = os.path.basename(root).lower()
            if low in ("mods", "mod"):
                found.add(root)
            if "options.txt" in files or "launcher_profiles.json" in files:
                game_dirs.add(root)
            dirs[:] = [d for d in dirs if d.lower() not in ("assets", "libraries", "saves", "screenshots",
                                                            "resourcepacks", "shaderpacks", "runtime", "cache",
                                                            "jre", "natives", "crash-reports")]
            if depth >= 5:
                dirs[:] = []
    return sorted(found), sorted(game_dirs)


def run_check(ctx):
    mods_dirs, game_dirs = _find_mods_dirs(ctx)
    for g in game_dirs:
        _game_dir(ctx, g)
    mods_dirs = sorted(set(mods_dirs) | set(ctx.shared.get("mods_dirs", set())))
    ctx.log.info(f"Папок модов: {len(mods_dirs)}, игровых папок: {len(game_dirs)}")
    if not mods_dirs and not game_dirs:
        ctx.log.warn("Папки Minecraft не найдены. Укажите путь параметром --path, если игра в нестандартном месте")
    rows = []
    for d in mods_dirs:
        _scan_mods_dir(ctx, d, rows)
    rows.sort(key=lambda r: SEV_ORDER.index(r[0]))
    ctx.table("mods", "Моды Minecraft", ["Оценка", "Файл", "Размер", "Изменён", "Загрузчик / ID", "Признаки", "Источник"],
              rows)
    _standalone_jars(ctx)


def _weight_check(fname: str, size: int):
    norm = kb.normalize_mod_name(fname)
    if norm not in kb.MOD_WEIGHTS_KB:
        return None
    kbs = kb.MOD_WEIGHTS_KB[norm]
    actual = size / 1024
    if any(abs(actual - w) <= max(3, w * 0.15) for w in kbs):
        return None
    return f"Вес {actual:.0f} КБ не совпадает с известными весами мода ({', '.join(str(x) for x in sorted(kbs))} КБ)"


def _scan_mods_dir(ctx, d, rows):
    mt = mtime_dt(d)
    try:
        entries = [e for e in os.scandir(d) if e.is_file()]
    except OSError:
        return
    jars = [e for e in entries if e.name.lower().endswith((".jar", ".jar.disabled", ".zip", ".litemod"))]
    others = [e for e in entries if e not in jars]
    newest_file = max((mtime_dt(e.path) for e in jars), default=None)
    ctx.log.info(f"{d}: {len(jars)} модов, папка изменена {fmt_dt(mt)}")
    recent_mods = [e for e in jars if ctx.is_recent(mtime_dt(e.path))]
    if (mt and ctx.is_recent(mt)) or recent_mods:
        ctx.add("CRITICAL" if mt and ctx.is_recent(mt) else "HIGH", "Minecraft",
                "Папка модов/моды изменены незадолго до проверки",
                "База: перед проверкой модов нужно смотреть дату изменения папки. Если она совпадает с моментом вызова "
                "на проверку — это указывает на подмену/удаление модов прямо перед проверкой (папка меняется при "
                "добавлении, удалении и переименовании файлов).",
                [Evidence(f"{d}: изменена {fmt_dt(mt)}", path=d, time=mt),
                 Evidence(f"Самый свежий мод изменён: {fmt_dt(newest_file)}", time=newest_file)]
                + [Evidence(f"Изменён мод: {e.name}", path=e.path, time=mtime_dt(e.path)) for e in recent_mods],
                kb=["Моды/1. Внешние признаки подозрительных модов"], tools=["JournalTrace"],
                recommendation="Через JournalTrace посмотрите, какие .jar удалялись/переименовывались в этой папке.")
    for e in others:
        low = e.name.lower()
        if low.endswith((".dll", ".exe", ".bat", ".cmd", ".vbs", ".ps1")) or low == "keywords.txt":
            ctx.add("HIGH", "Minecraft", f"В папке модов лежит посторонний файл: {e.name}",
                    "В папке mods не должно быть исполняемых файлов/библиотек — это может быть инжектор или конфиг чита.",
                    [Evidence(e.path, path=e.path, time=mtime_dt(e.path))], kb=["Моды/1. Внешние признаки подозрительных модов"])
    for e in jars:
        size = e.stat().st_size
        r = analyze_jar(e.path, size)
        flags = list(r["flags"])
        hits = keyword_hits(e.name, weak=True)
        if hits:
            sev = top_severity(hits)
            flags.insert(0, ("HIGH" if sev == "HIGH" else sev, f"Название совпадает с базой: {hits_text(hits)}"))
        mod_only = [k for k in kb.CHEAT_MOD_ONLY if k in e.name.lower()]
        if mod_only:
            flags.insert(0, ("HIGH", f"Название мода указывает на X-Ray/поиск руд: {', '.join(mod_only)}"))
        w = _weight_check(e.name, size)
        if w:
            flags.append(("MEDIUM", w + " — возможна подмена содержимого мода"))
        jmt = mtime_dt(e.path)
        zone = zone_identifier(e.path)
        src = zone.get("HostUrl") or zone.get("ReferrerUrl") or ""
        sev = "INFO"
        for s, _ in flags:
            if SEV_ORDER.index(s) < SEV_ORDER.index(sev):
                sev = s
        if r["severity"] == "CRITICAL":
            sev = "CRITICAL"
        meta = r["meta"]
        loader = f"{meta.get('loader', '')} {meta.get('id', '')} {meta.get('version', '')}".strip()
        rows.append([sev, e.path, f"{size / 1024:.0f} КБ", fmt_dt(jmt) + ctx.recent_mark(jmt), loader,
                     "; ".join(f for _, f in flags) or "—", src])
        if sev in ("CRITICAL", "HIGH", "MEDIUM"):
            ev = [Evidence(f"Файл: {e.path} ({size} байт, изменён {fmt_dt(jmt)})", path=e.path, time=jmt)]
            if src:
                ev.append(Evidence(f"Скачан с: {src}", url=src if src.startswith("http") else None))
            if loader:
                ev.append(Evidence(f"Метаданные: {loader} «{meta.get('name', '')}»"))
            ev += [Evidence(f"[{s}] {f}") for s, f in flags]
            ctx.add(sev, "Minecraft", f"Подозрительный мод: {e.name}",
                    "Автоматический разбор .jar (структура, обфускация, вложенные библиотеки, строки модулей читов, "
                    "методы, которые меняют читы). Для окончательного вывода декомпилируйте мод.",
                    ev, kb=["Моды/1. Внешние признаки подозрительных модов", "Моды/4. Методы относительно версии модификации",
                            "Моды/5. Теория использования читов внутри мода", "Моды/Вес модификаций"],
                    tools=["Recaf", "Luyten", "BytecodeViewer", "ModAnalyzer", "JarParser"])
        ctx.add_exec(e.path, "Папка mods", jmt, kind="storage")


def _game_dir(ctx, g):
    # latest.log и другие логи
    logs_dir = os.path.join(g, "logs")
    ev = []
    for name in ("latest.log", "debug.log"):
        p = os.path.join(logs_dir, name)
        try:
            with open(p, "r", encoding="utf-8", errors="replace") as f:
                for i, line in enumerate(f):
                    hits = [h for h in keyword_hits(line) if h[1] == "HIGH"]
                    if hits:
                        ev.append(Evidence(f"{name}:{i + 1}: {line.strip()[:300]}  [{hits_text(hits)}]", path=p,
                                           time=mtime_dt(p)))
                    if len(ev) > 100:
                        break
        except OSError:
            continue
    if ev:
        ctx.add("CRITICAL", "Minecraft", "Логи игры содержат названия читов",
                "В логах Minecraft (загрузка модов, команды, ошибки) встречаются названия чит-клиентов/модулей.", ev,
                kb=["Моды/1. Внешние признаки подозрительных модов"])
    # профили лаунчера: аргументы JVM
    p = os.path.join(g, "launcher_profiles.json")
    try:
        with open(p, "r", encoding="utf-8", errors="replace") as f:
            data = json.load(f)
        for pid, prof in (data.get("profiles") or {}).items():
            args = prof.get("javaArgs") or ""
            if "-javaagent" in args or keyword_hits(args):
                ctx.add("HIGH", "Minecraft", f"Профиль лаунчера «{prof.get('name', pid)}» подключает java-агент",
                        "Через -javaagent в аргументах JVM подгружают инжект-читы при каждом запуске игры.",
                        [Evidence(f"{p}: javaArgs = {args}", path=p)])
            gd = prof.get("gameDir")
            if gd and os.path.isdir(os.path.join(gd, "mods")):
                ctx.shared.setdefault("mods_dirs", set()).add(os.path.join(gd, "mods"))
    except (OSError, ValueError, AttributeError):
        pass
    # версии с названиями читов
    vdir = os.path.join(g, "versions")
    try:
        for v in os.listdir(vdir):
            hits = keyword_hits(v, weak=True)
            if hits:
                ctx.add("CRITICAL" if top_severity(hits) == "HIGH" else "HIGH", "Minecraft",
                        f"Установлена версия игры с названием чита: {v}",
                        "Чит-клиенты часто ставятся как отдельная «версия» в папку versions.",
                        [Evidence(os.path.join(vdir, v), path=os.path.join(vdir, v), time=mtime_dt(os.path.join(vdir, v)))],
                        kb=["База/2. Программы/Everything 1.5a"])
    except OSError:
        pass


def _standalone_jars(ctx):
    """.jar вне игровых библиотек, найденные при обходе дисков (лоадеры/инжект-клиенты)."""
    cands = [p for p in ctx.shared.get("all_jars", []) if not _LIB_DIRS.search(p)
             and not re.search(r"\\mods\\", p, re.I)]
    cands = cands[:400]
    if not cands:
        return
    ctx.log.info(f"Отдельных .jar вне библиотек: {len(cands)} — анализ")
    for p in cands:
        try:
            size = os.path.getsize(p)
        except OSError:
            continue
        if size > 60 << 20:
            continue
        r = analyze_jar(p, size, max_scan_bytes=24 << 20)
        hits = keyword_hits(p, weak=True)
        sev = r["severity"]
        if hits and SEV_ORDER.index(top_severity(hits)) < SEV_ORDER.index(sev):
            sev = top_severity(hits)
        if sev in ("CRITICAL", "HIGH") or (sev == "MEDIUM" and (r["cheat_strings"] or r["natives"] or hits)):
            mt = mtime_dt(p)
            zone = zone_identifier(p)
            src = zone.get("HostUrl") or zone.get("ReferrerUrl") or ""
            ev = [Evidence(f"{p} ({size} байт, изменён {fmt_dt(mt)})", path=p, time=mt)]
            if src:
                ev.append(Evidence(f"Скачан с: {src}", url=src if src.startswith("http") else None))
            if hits:
                ev.append(Evidence(f"Название совпадает с базой: {hits_text(hits)}"))
            ev += [Evidence(f"[{s}] {f}") for s, f in r["flags"]]
            ctx.add(sev, "Файлы", f"Подозрительный .jar вне папки игры: {os.path.basename(p)}",
                    "Отдельные .jar вне модов часто являются инжект-клиентами/лоадерами, которые запускаются через "
                    "java -jar или внедряются в игру (Doomsday).", ev,
                    kb=["Моды/1. Внешние признаки подозрительных модов", "База/2. Программы/Jarable"],
                    tools=["Recaf", "Jarabel", "DoomsDayFinder"])
