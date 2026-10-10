"""Поиск файлов на дисках — аналог запросов Everything из базы (имена, точные размеры, vec.dll, Doomsday),
плюс обходы: смена расширения, стеганография, ADS, Unicode-символы."""
import os
import re
import stat
import time
import zipfile

from .. import kb
from ..core import Evidence, fmt_dt
from ..match import hits_text, keyword_hits, maybe_keyword, top_severity, unusual_unicode
from ..winutil import IS_WIN, alt_streams, drives, zone_identifier
from datetime import datetime, timezone

SYSTEM_DRIVE = os.environ.get("SystemDrive", "C:").upper()
_SKIP_DIRS = {"windows", "$windows.~bt", "$windows.~ws", "windows.old", "system volume information",
              "$winreagent", "windowsapps", "node_modules", ".git", "$sysreset", "recovery", "msocache",
              "winsxs", "__pycache__", "site-packages", ".gradle", ".m2", ".cache", "cache2", "code cache",
              "gpucache", "service worker", "indexeddb", "shadercache"}
_EXEC_LIKE = {".exe", ".dll", ".jar", ".zip", ".rar", ".7z", ".bat", ".cmd", ".ahk", ".ps1", ".vbs", ".sys",
              ".scr", ".msi", ".py", ".lnk", ""}
_ZIPLIKE = {".docx", ".xlsx", ".pptx", ".odt", ".ods", ".jar", ".zip", ".apk", ".xpi", ".epub", ".mcpack",
            ".mcworld", ".nupkg", ".whl", ".vsix", ".crx", ".aar", ".kmz", ".3mf"}
_ARCHIVE_SIGS = [(b"Rar!\x1a\x07", "RAR"), (b"PK\x03\x04", "ZIP/JAR"), (b"7z\xbc\xaf\x27\x1c", "7-Zip"),
                 (b"MZ", "EXE")]


def _dt(ts):
    try:
        return datetime.fromtimestamp(ts, timezone.utc)
    except (OSError, OverflowError, ValueError):
        return None


def _user_area(path_low: str) -> bool:
    if "\\program files" in path_low or path_low.startswith(SYSTEM_DRIVE.lower() + "\\windows"):
        return False
    return "\\users\\" in path_low or not path_low.startswith(SYSTEM_DRIVE.lower())


def _read(path, n, offset=0):
    try:
        with open(path, "rb") as f:
            if offset:
                f.seek(offset)
            return f.read(n)
    except OSError:
        return b""


_END_SIGS = [(b"PK\x05\x06", "ZIP/JAR"), (b"\x1dwVQ\x03\x05\x04\x00", "RAR5"),
             (b"\xc4\x3d\x7b\x00\x40\x07\x00", "RAR")]


def _stego_check(path, ext, size):
    """Ищет данные/архив, приклеенные в конец медиафайла (copy /b картинка + архив)."""
    if ext not in (".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".txt"):
        # видео/аудио: архив в конце файла оставляет запись конца архива в последних килобайтах
        tail = _read(path, 65536, max(0, size - 65536))
        found = [n for sig, n in _END_SIGS if sig in tail]
        return found or None
    tail = _read(path, 16, max(0, size - 16))
    suspicious = True
    if ext == ".png":
        suspicious = not tail.rstrip(b"\x00").endswith(b"IEND\xaeB`\x82")
    elif ext in (".jpg", ".jpeg"):
        suspicious = not tail.rstrip(b"\x00").endswith(b"\xff\xd9")
    elif ext == ".gif":
        suspicious = not tail.rstrip(b"\x00").endswith(b";")
    elif ext == ".bmp":
        head = _read(path, 6)
        if len(head) == 6 and head[:2] == b"BM":
            suspicious = int.from_bytes(head[2:6], "little") + 16 < size
    if not suspicious:
        return None
    window = min(size, 8 << 20)
    blob = _read(path, window, size - window)
    found = []
    for sig, name in _ARCHIVE_SIGS:
        i = blob.find(sig, 1 if size <= window else 0)
        if i >= 0:
            if name == "EXE" and blob.find(b"This program cannot be run in DOS mode", i, i + 200) < 0:
                continue
            if name == "ZIP/JAR" and b"PK\x05\x06" not in blob[i:]:
                continue
            found.append(name)
    return found or None


def run_check(ctx):
    if ctx.opts.quick or not IS_WIN:
        roots = [os.environ.get("USERPROFILE", os.path.expanduser("~"))]
    else:
        roots = [r for r, t in drives((2, 3))]
    roots += [p for p in ctx.opts.extra_paths if os.path.isdir(p)]
    out_low = os.path.abspath(ctx.out_dir).lower()

    kw_files, kw_dirs, size_hits, vec, disguised, stego, uni, cleaners, ads = ([] for _ in range(9))
    all_jars, mods_dirs = [], set()
    ads_roots = [os.path.join(os.environ.get("USERPROFILE", ""), d) for d in ("Desktop", "Downloads", "Documents")]
    ads_roots += [os.environ.get("TEMP", ""), os.path.join(os.environ.get("APPDATA", ""), ".minecraft")]
    ads_roots = [a.lower() for a in ads_roots if a]
    files_seen = 0
    t0 = time.time()
    last_log = t0

    for root in roots:
        ctx.log.info(f"Обход {root} …")
        stack = [root]
        while stack:
            d = stack.pop()
            dl = d.lower()
            if dl.startswith(out_low):
                continue
            try:
                it = os.scandir(d)
            except OSError:
                continue
            has_jar = False
            with it:
                for e in it:
                    name = e.name
                    low = name.lower()
                    try:
                        st = e.stat(follow_symlinks=False)
                    except OSError:
                        continue
                    is_dir = stat.S_ISDIR(st.st_mode)
                    if IS_WIN and getattr(st, "st_file_attributes", 0) & 0x400:  # reparse point
                        continue
                    if is_dir:
                        if low in _SKIP_DIRS and not (low == "windows" and dl.count("\\") > 1):
                            continue
                        if maybe_keyword(low):
                            hits = [h for h in keyword_hits(name) if h[1] in ("HIGH", "MEDIUM")]
                            if hits:
                                kw_dirs.append((e.path, hits, _dt(st.st_mtime)))
                        stack.append(e.path)
                        continue
                    files_seen += 1
                    ext = os.path.splitext(low)[1]
                    size = st.st_size
                    path_low = e.path.lower()
                    if ext == ".jar":
                        has_jar = True
                        all_jars.append(e.path)
                    # 1. Имена (Everything → Size by Name)
                    if maybe_keyword(low):
                        hits = keyword_hits(name, weak=ext in _EXEC_LIKE)
                        if hits and (ext in _EXEC_LIKE or any(s in ("HIGH", "MEDIUM") for _, s in hits)):
                            kw_files.append((e.path, hits, size, _dt(st.st_mtime)))
                    if "shellbag_analyzer_cleaner" in low:
                        cleaners.append((e.path, _dt(st.st_mtime)))
                    # 2. Точные размеры (Everything → Jar Sizes / Size by Weight)
                    if ext == ".jar" and size in kb.JAR_CHEAT_SIZES:
                        size_hits.append((e.path, size, _dt(st.st_mtime), "jar"))
                    elif size in kb.FILE_CHEAT_SIZES and ext in (".exe", ".dll", ".jar", "", ".bin") \
                            and _user_area(path_low):
                        size_hits.append((e.path, size, _dt(st.st_mtime), "file"))
                    # 3. vec.dll
                    if ext == ".dll" and size == kb.VEC_DLL_SIZE:
                        blob = _read(e.path, size)
                        if any(m in blob for m in kb.VEC_DLL_MARKERS):
                            vec.append((e.path, _dt(st.st_mtime)))
                    if not _user_area(path_low):
                        continue
                    # 4. Смена расширения: внутри «картинки» исполняемый файл / jar
                    if (ext in kb.MEDIA_EXTS or ext == "") and 1024 < size < (200 << 20) and ext not in (".dat", ".tmp", ".sys"):
                        if ext == "" and not re.search(r"\\(desktop|downloads|documents|temp)\\", path_low):
                            pass
                        else:
                            head = _read(e.path, 4)
                            if head[:2] == b"MZ":
                                disguised.append((e.path, "исполняемый файл (MZ)", size, _dt(st.st_mtime)))
                            elif head == b"PK\x03\x04" and ext not in _ZIPLIKE:
                                try:
                                    with zipfile.ZipFile(e.path) as z:
                                        if any(n.endswith(".class") for n in z.namelist()[:5000]):
                                            disguised.append((e.path, "Java-архив (.jar)", size, _dt(st.st_mtime)))
                                except (zipfile.BadZipFile, OSError, ValueError):
                                    pass
                            elif head[:4] == b"Rar!" and ext in kb.STEGO_EXTS:
                                disguised.append((e.path, "RAR-архив", size, _dt(st.st_mtime)))
                    # 5. Стеганография
                    if ext in kb.STEGO_EXTS and 512 < size <= (64 << 20) and \
                            (ext in (".png", ".jpg", ".jpeg", ".gif", ".bmp") or "\\appdata\\" not in path_low):
                        res = _stego_check(e.path, ext, size)
                        if res:
                            stego.append((e.path, res, size, _dt(st.st_mtime)))
                    # 6. Unicode-имена исполняемых файлов
                    if ext in (".exe", ".jar", ".dll", ".bat", ".cmd") and not name.isascii():
                        bad = unusual_unicode(name)
                        if bad:
                            uni.append((e.path, bad, _dt(st.st_mtime)))
                    # 7. ADS
                    if IS_WIN and any(path_low.startswith(a) for a in ads_roots):
                        for sname, ssize in alt_streams(e.path):
                            if sname.split(":")[0].lower() in kb.BENIGN_ADS or ssize == 0:
                                continue
                            head = _read(e.path + ":" + sname, 4)
                            kind = "EXE" if head[:2] == b"MZ" else ("ZIP/JAR" if head[:2] == b"PK" else "")
                            ads.append((e.path, sname, ssize, kind, _dt(st.st_mtime)))
                    now = time.time()
                    if now - last_log > 15:
                        ctx.log.info(f"  … просмотрено {files_seen} файлов ({d[:80]})")
                        last_log = now
            if has_jar and os.path.basename(dl) in ("mods", "mod"):
                mods_dirs.add(d)
    ctx.log.info(f"Просмотрено файлов: {files_seen} за {time.time() - t0:.0f} с")
    ctx.shared["all_jars"] = all_jars
    ctx.shared.setdefault("mods_dirs", set()).update(mods_dirs)
    _report(ctx, kw_files, kw_dirs, size_hits, vec, disguised, stego, uni, cleaners, ads)


def _src(path):
    z = zone_identifier(path)
    u = z.get("HostUrl") or z.get("ReferrerUrl") or ""
    return u


def _report(ctx, kw_files, kw_dirs, size_hits, vec, disguised, stego, uni, cleaners, ads):
    ev_tools = ["Everything 1.5a"]
    if kw_files or kw_dirs:
        items = []
        for p, hits, size, mt in kw_files:
            u = _src(p)
            items.append((top_severity(hits), Evidence(
                f"{p}  ({size} байт)  [совпадение: {hits_text(hits)}]" + (f"  скачан: {u}" if u else ""),
                path=p, time=mt, url=u if u.startswith("http") else None)))
            ctx.add_exec(p, "Файл на диске", mt, kind="storage")
        for p, hits, mt in kw_dirs:
            items.append((top_severity(hits), Evidence(f"[папка] {p}  [совпадение: {hits_text(hits)}]", path=p, time=mt)))
        order = ["HIGH", "MEDIUM", "LOW"]
        items.sort(key=lambda x: order.index(x[0]))
        top = items[0][0]
        sev = {"HIGH": "CRITICAL", "MEDIUM": "HIGH", "LOW": "MEDIUM"}[top]
        ctx.add(sev, "Файлы", "На дисках найдены файлы/папки с названиями читов",
                "Поиск по списку «Size by Name» из базы (Everything). Сильные совпадения — названия чит-клиентов, "
                "лоадеров и чистильщиков; слабые — общие слова, требующие проверки.",
                [e for _, e in items[:300]], kb=["База/2. Программы/Everything 1.5a"], tools=ev_tools)
    if size_hits:
        ctx.add("HIGH", "Файлы", "Файлы с точным размером известных читов",
                "Размер в байтах совпадает со списками «Jar Sizes» / «Size by Weight» из базы. Совпадение размера "
                "до байта у .jar — сильный признак; у остальных файлов проверьте содержимое.",
                [Evidence(f"{p}  ({s} байт, {kind})", path=p, time=mt) for p, s, mt, kind in size_hits[:200]],
                kb=["База/2. Программы/Everything 1.5a"], tools=ev_tools)
    if vec:
        ctx.add("CRITICAL", "Файлы", "Найден vec.dll (инжект-чит)",
                "DLL размером 30720 байт со строками net/minecraft/client/entity/player/ClientPlayerEntity / "
                "AxisAlignedBB — сигнатура vec.dll из базы.",
                [Evidence(p, path=p, time=mt) for p, mt in vec], kb=["База/2. Программы/Everything 1.5a"])
    if disguised:
        ctx.add("CRITICAL", "Обходы", "Исполняемые файлы/архивы с поддельным расширением",
                "Внутри файла с расширением картинки/текста/без расширения находится .exe или .jar. Так прячут лоадеры "
                "и запускают их через wmic, start или java -jar.",
                [Evidence(f"{p}  → на самом деле {kind} ({s} байт)", path=p, time=mt) for p, kind, s, mt in disguised[:200]],
                kb=["Обходы/Различные методы/Измененные расширения"])
        for p, kind, s, mt in disguised:
            ctx.add_exec(p, "Файл с поддельным расширением", mt, kind="storage")
    if stego:
        ctx.add("CRITICAL", "Обходы", "Стеганография: к медиафайлам приклеены архивы/исполняемые файлы",
                "После конца картинки/видео/текста найдены сигнатуры архивов или EXE (copy /b картинка + чит.rar). "
                "Откройте файл через WinRAR/7-Zip, чтобы увидеть содержимое.",
                [Evidence(f"{p}  → внутри: {', '.join(k)} ({s} байт)", path=p, time=mt) for p, k, s, mt in stego[:200]],
                kb=["Обходы/Различные методы/Стеганография", "База/3. Скрипты/SteganoChecker"])
    if ads:
        sev = "CRITICAL" if any(k for *_, k, _ in ads) else "HIGH"
        ctx.add(sev, "Обходы", "Альтернативные потоки NTFS (ADS) с данными",
                "К файлу прикреплён скрытый поток (file.exe:secret.dll), который не видно в Проводнике. "
                "Потоки с EXE/ZIP-сигнатурой — спрятанный чит.",
                [Evidence(f"{p}:{n}  ({s} байт{', ' + k if k else ''})", path=p, time=mt) for p, n, s, k, mt in ads[:200]],
                kb=["Обходы/Различные методы/ADS"])
    if uni:
        ctx.add("MEDIUM", "Обходы", "Исполняемые файлы с невидимыми/экзотическими Unicode-символами в имени",
                "Такие символы мешают поиску и отображаются в программах проверки как «???».",
                [Evidence(f"{p}  [{', '.join(b)}]", path=p, time=mt) for p, b, mt in uni[:100]],
                kb=["Обходы/Различные методы/Использование UNICODE символов"], tools=ev_tools)
    if cleaners:
        ctx.add("CRITICAL", "Чистка", "Найден shellbag_analyzer_cleaner.ini — ShellBags очищали",
                "Файл автоматически создаётся при очистке ShellBags через ShellBag Analyzer & Cleaner. "
                "Дата изменения файла — дата очистки.",
                [Evidence(f"{p} (изменён {fmt_dt(mt)})", path=p, time=mt) for p, mt in cleaners],
                kb=["Обходы/Обнаружение чистки/Чистка Шеллбага", "База/2. Программы/ShellBagAnalyzer"])
