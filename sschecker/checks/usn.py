"""USN-журнал NTFS (База → 1. Артефакты/USN, Программы → JournalTrace, Обходы)."""
import os
import struct

from .. import kb
from ..core import Evidence, fmt_dt
from ..match import hits_text, keyword_hits, maybe_keyword, unusual_unicode
from ..winutil import IS_WIN, drives, filetime_to_dt, volume_info

if IS_WIN:
    import ctypes
    from ctypes import wintypes
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateFileW.restype = wintypes.HANDLE
    k32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                                wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    k32.DeviceIoControl.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD,
                                    ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
    k32.OpenFileById.restype = wintypes.HANDLE
    k32.OpenFileById.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
                                 ctypes.c_void_p, wintypes.DWORD]
    k32.GetFinalPathNameByHandleW.argtypes = [wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD]
    k32.CloseHandle.argtypes = [wintypes.HANDLE]

FSCTL_QUERY_USN_JOURNAL = 0x000900F4
FSCTL_READ_USN_JOURNAL = 0x000900BB
INVALID = (1 << 64) - 1

R = {"DATA_OVERWRITE": 0x1, "DATA_EXTEND": 0x2, "DATA_TRUNCATION": 0x4, "FILE_CREATE": 0x100,
     "FILE_DELETE": 0x200, "RENAME_OLD_NAME": 0x1000, "RENAME_NEW_NAME": 0x2000,
     "BASIC_INFO_CHANGE": 0x8000, "STREAM_CHANGE": 0x200000, "CLOSE": 0x80000000}


def reason_text(r: int) -> str:
    return " | ".join(k for k, v in R.items() if r & v) or hex(r)


class Volume:
    def __init__(self, letter: str):
        self.letter = letter
        self.h = k32.CreateFileW(f"\\\\.\\{letter}:", 0x80000000, 0x3, None, 3, 0, None)
        if not self.h or self.h == wintypes.HANDLE(-1).value:
            raise PermissionError(ctypes.get_last_error())
        self.cache = {}

    def close(self):
        k32.CloseHandle(self.h)

    def query(self):
        buf = ctypes.create_string_buffer(80)
        got = wintypes.DWORD()
        if not k32.DeviceIoControl(self.h, FSCTL_QUERY_USN_JOURNAL, None, 0, buf, 80, ctypes.byref(got), None):
            raise OSError(ctypes.get_last_error())
        jid, first, nxt, lowest, maxusn, maxsize, delta = struct.unpack_from("<QqqqqQQ", buf.raw, 0)
        return {"id": jid, "first": first, "next": nxt, "max_size": maxsize}

    def records(self, journal):
        start = journal["first"]
        out = ctypes.create_string_buffer(1 << 20)
        got = wintypes.DWORD()
        while True:
            inp = struct.pack("<qIIQQQ", start, 0xFFFFFFFF, 0, 0, 0, journal["id"])
            ib = ctypes.create_string_buffer(inp, len(inp))
            if not k32.DeviceIoControl(self.h, FSCTL_READ_USN_JOURNAL, ib, len(inp), out, len(out),
                                       ctypes.byref(got), None):
                break
            n = got.value
            if n <= 8:
                break
            data = out.raw[:n]
            start = struct.unpack_from("<q", data, 0)[0]
            pos = 8
            while pos + 60 <= n:
                rec_len, major = struct.unpack_from("<IH", data, pos)
                if rec_len == 0:
                    break
                if major == 2:
                    fref, pref, usn, ts, reason = struct.unpack_from("<QQqqI", data, pos + 8)
                    attrs, nlen, noff = struct.unpack_from("<IHH", data, pos + 52)
                elif major == 3:
                    fref = int.from_bytes(data[pos + 8:pos + 16], "little")
                    pref = int.from_bytes(data[pos + 24:pos + 32], "little")
                    usn, ts, reason = struct.unpack_from("<qqI", data, pos + 40)
                    attrs, nlen, noff = struct.unpack_from("<IHH", data, pos + 68)
                else:
                    pos += rec_len
                    continue
                name = data[pos + noff:pos + noff + nlen].decode("utf-16-le", errors="replace")
                yield fref, pref, ts, reason, attrs, name
                pos += rec_len
            if start >= journal["next"]:
                break

    def resolve(self, ref: int) -> str:
        if ref in self.cache:
            return self.cache[ref]
        desc = struct.pack("<IIQQ", 24, 0, ref, 0)
        db = ctypes.create_string_buffer(desc, len(desc))
        h = k32.OpenFileById(self.h, db, 0, 0x7, None, 0x02000000)
        path = ""
        if h and h != wintypes.HANDLE(-1).value:
            buf = ctypes.create_unicode_buffer(1024)
            if k32.GetFinalPathNameByHandleW(h, buf, 1024, 0):
                path = buf.value
                if path.startswith("\\\\?\\"):
                    path = path[4:]
            k32.CloseHandle(h)
        self.cache[ref] = path
        return path


def run_check(ctx):
    if not IS_WIN:
        ctx.log.warn("Не Windows — USN пропущен")
        return
    if not ctx.system.get("admin"):
        ctx.log.warn("USN-журнал требует прав администратора — пропущено")
        return
    for root, dtype in drives((2, 3)):
        label, fs = volume_info(root)
        if fs.upper() != "NTFS":
            continue
        try:
            _scan_volume(ctx, root[0])
        except Exception as e:  # noqa
            ctx.log.error(f"USN {root}: {e}")


def _scan_volume(ctx, letter):
    vol = Volume(letter)
    try:
        try:
            j = vol.query()
        except OSError as e:
            if getattr(e, "args", [0])[0] == 1179:  # ERROR_JOURNAL_NOT_ACTIVE
                ctx.add("CRITICAL", "Чистка", f"USN-журнал на диске {letter}: отключён/удалён",
                        "Журнал изменений NTFS не активен — его удалили (fsutil usn deletejournal) и не пересоздали.",
                        [Evidence(f"{letter}: FSCTL_QUERY_USN_JOURNAL → журнал не активен")],
                        kb=["Обходы/Обнаружение чистки/Чистка JournalTrace"])
            raise
        created = filetime_to_dt(j["id"])
        ctx.log.info(f"USN {letter}: журнал создан {fmt_dt(created)}, размер до {j['max_size'] // (1 << 20)} МБ")
        if created and ctx.system.get("install_date") and (created - ctx.system["install_date"]).days >= 1 \
                or (created and not ctx.system.get("install_date")):
            boot = ctx.system.get("boot")
            if ctx.is_recent(created):
                ctx.add("CRITICAL", "Чистка", f"USN-журнал диска {letter}: пересоздан незадолго до проверки",
                        "Идентификатор журнала — это время его создания. Журнал создан недавно: его удаляли "
                        "(fsutil usn deletejournal) и он пересоздался. Чистка USN — безоговорочный повод для наказания.",
                        [Evidence(f"Журнал {letter}: создан {fmt_dt(created)}", time=created)],
                        kb=["Обходы/Обнаружение чистки/Чистка JournalTrace", "База/1. Артефакты/USN"],
                        tools=["JournalTrace"])
            elif boot and created > boot:
                ctx.add("HIGH", "Чистка", f"USN-журнал диска {letter}: пересоздан после загрузки системы",
                        "Журнал создан после последней загрузки ПК — его удаляли в текущем сеансе.",
                        [Evidence(f"Журнал {letter}: создан {fmt_dt(created)}; загрузка {fmt_dt(boot)}", time=created)],
                        kb=["Обходы/Обнаружение чистки/Чистка JournalTrace"])
        _analyze(ctx, vol, j, letter)
    finally:
        vol.close()


def _analyze(ctx, vol, j, letter):
    created_refs = set()
    pending_rename = {}
    deletes, renames, ext_changes, extends, overwrites, attr_pf, kw, cleaners, uni = ([] for _ in range(9))
    pf_deletes = []
    first_ts = None
    count = 0
    for fref, pref, ts, reason, attrs, name in vol.records(j):
        count += 1
        t = filetime_to_dt(ts)
        if first_ts is None:
            first_ts = t
        low = name.lower()
        ext = os.path.splitext(low)[1]
        if reason & R["FILE_CREATE"]:
            created_refs.add(fref)
        if reason & R["RENAME_OLD_NAME"]:
            pending_rename[fref] = (name, pref, t)
        if reason & R["RENAME_NEW_NAME"] and fref in pending_rename:
            old, opref, ot = pending_rename.pop(fref)
            oext = os.path.splitext(old.lower())[1]
            if old != name:
                rec = (t, old, name, pref, opref)
                if (oext in kb.INTERESTING_EXTS or ext in kb.INTERESTING_EXTS):
                    renames.append(rec)
                if oext != ext and (oext in (".exe", ".jar", ".dll", ".bat") or ext in (".exe", ".jar", ".dll")) \
                        and oext not in (".tmp", ".crdownload", ".part", ".partial", ".download", "") \
                        and ext not in (".tmp", ".old", ".bak", ".delete", ".deleted"):
                    ext_changes.append(rec)
        if reason & R["FILE_DELETE"] and reason & R["CLOSE"]:
            if ext == ".pf":
                pf_deletes.append((t, name, pref))
            elif ext in kb.INTERESTING_EXTS:
                deletes.append((t, name, pref))
        if reason & R["DATA_EXTEND"] and ext in kb.STEGO_EXTS and fref not in created_refs and ctx.is_recent(t):
            extends.append((t, name, pref))
        if reason & (R["DATA_OVERWRITE"] | R["STREAM_CHANGE"]) and ext in (".exe", ".dll", ".jar") \
                and fref not in created_refs and ctx.is_recent(t):
            overwrites.append((t, name, pref, reason))
        if reason & R["BASIC_INFO_CHANGE"] and ext == ".pf" and not reason & (R["DATA_EXTEND"] | R["DATA_TRUNCATION"]):
            attr_pf.append((t, name, pref))
        if reason & (R["FILE_CREATE"] | R["FILE_DELETE"] | R["RENAME_NEW_NAME"]) and maybe_keyword(low):
            hits = [h for h in keyword_hits(name, weak=ext in (".exe", ".jar", ".dll", ".zip", ".rar", ".7z"))
                    if h[1] in ("HIGH", "MEDIUM") or ext in (".exe", ".jar", ".dll")]
            if hits:
                kw.append((t, name, pref, reason, hits))
        if reason & (R["FILE_CREATE"] | R["FILE_DELETE"] | R["RENAME_NEW_NAME"]):
            if "shellbag_analyzer_cleaner" in low or "usboblivion" in low or "privazer" in low:
                cleaners.append((t, name, pref, reason))
            if ext in (".exe", ".jar", ".dll", ".bat") and not name.isascii() and unusual_unicode(name):
                uni.append((t, name, pref, reason))
    ctx.log.info(f"USN {letter}: {count} записей, самая ранняя {fmt_dt(first_ts)}")
    ctx.system.setdefault("usn", {})[letter] = {"records": count, "first": fmt_dt(first_ts)}

    def ev(t, text, pref, extra=""):
        parent = vol.resolve(pref)
        path = os.path.join(parent, text) if parent else f"{letter}:\\…\\{text}"
        return Evidence(f"{path}{extra}", path=path, time=t, source=f"USN {letter}:")

    kb_usn = ["База/1. Артефакты/USN", "База/2. Программы/Spokwn/JournalTrace"]
    if kw:
        items = [ev(t, n, p, f"  [{reason_text(r)}] [совпадение: {hits_text(h)}]") for t, n, p, r, h in kw[-150:]]
        sev = "CRITICAL" if any(any(s == "HIGH" for _, s in h) for *_, h in kw) else "HIGH"
        ctx.add(sev, "Файлы", f"USN {letter}: создание/удаление/переименование файлов с названиями читов",
                "USN-журнал хранит историю файлов, даже если они уже удалены «минуя корзину».", items,
                kb=kb_usn, tools=["JournalTrace"])
    if cleaners:
        ctx.add("CRITICAL", "Чистка", f"USN {letter}: следы программ очистки (ShellBag Cleaner / USBOblivion)",
                "shellbag_analyzer_cleaner.ini создаётся при очистке ShellBags — его дата = дата очистки. "
                "USBOblivion чистит следы USB.",
                [ev(t, n, p, f"  [{reason_text(r)}]") for t, n, p, r in cleaners],
                kb=["Обходы/Обнаружение чистки/Чистка Шеллбага", "Обходы/Обнаружение чистки/Чистка USB-Устройств"])
    if ext_changes:
        recent = [x for x in ext_changes if ctx.is_recent(x[0])]
        items = [ev(t, new, p, f"  ← переименован из «{old}»") for t, old, new, p, op in ext_changes[-100:]]
        ctx.add("HIGH" if recent else "MEDIUM", "Обходы", f"USN {letter}: исполняемым файлам меняли расширение",
                "Файл .exe/.jar/.dll переименовывали в другое расширение (или наоборот) — так прячут читы "
                "и запускают их через wmic/java -jar/rundll32.", items,
                kb=["Обходы/Различные методы/Измененные расширения"] + kb_usn, tools=["JournalTrace"])
    rd = [x for x in deletes if ctx.is_recent(x[0])]
    if rd:
        items = [ev(t, n, p) for t, n, p in rd[-200:]]
        ctx.add("HIGH", "Чистка", f"USN {letter}: незадолго до проверки удалялись исполняемые файлы/архивы/моды",
                "Удаление .jar/.exe/.dll/архивов прямо перед проверкой (в т.ч. Shift+Delete, минуя корзину). "
                "Удаление .jar из папки mods во время «фриза» — основание для блокировки.", items,
                kb=["База/2. Программы/Spokwn/JournalTrace", "Обходы/Обнаружение чистки/Чистка Корзины"],
                tools=["JournalTrace"])
    rows = [[fmt_dt(t), "удалён", vol.resolve(p) + "\\" + n] for t, n, p in deletes[-400:]]
    rows += [[fmt_dt(t), "переименован", f"{vol.resolve(p)}\\{old} → {new}"] for t, old, new, p, op in renames[-400:]]
    rows.sort(key=lambda r: r[0], reverse=True)
    ctx.table(f"usn_{letter}", f"USN {letter}: удаления и переименования интересных файлов", ["Время", "Действие", "Путь"],
              rows[:800], note="Показаны .exe/.jar/.dll/.bat/.zip/.rar/.7z/.pf/.lnk и т.п.")
    rpf = [x for x in pf_deletes if ctx.is_recent(x[0])]
    if len(rpf) >= 3:
        ctx.add("CRITICAL" if len(rpf) >= 5 else "HIGH", "Чистка", f"USN {letter}: незадолго до проверки удалялись .pf-файлы",
                "Удаление файлов Prefetch скрывает факт запуска программ (Windows сама удаляет .pf только при "
                "переполнении — по одному).", [ev(t, n, p) for t, n, p in rpf[-100:]],
                kb=["База/2. Программы/Spokwn/JournalTrace", "База/1. Артефакты/Prefetch"], tools=["PrefetchView++"])
    if extends:
        ctx.add("HIGH", "Обходы", f"USN {letter}: в картинки/видео/текст дописывались данные (Data extended)",
                "Существующий медиафайл увеличился — так приклеивают архив с читом к картинке (copy /b).",
                [ev(t, n, p) for t, n, p in extends[-100:]],
                kb=["Обходы/Различные методы/Data-Modified", "Обходы/Различные методы/Стеганография"])
    if overwrites:
        ctx.add("MEDIUM", "Обходы", f"USN {letter}: незадолго до проверки перезаписывались .exe/.dll/.jar",
                "Флаги data_overwrite / stream_change у исполняемого файла — признак Hex replace (подмена кода "
                "лоадера на легитимный) или подмены мода. Обновления программ дают тот же след — проверьте пути.",
                [ev(t, n, p, f"  [{reason_text(r)}]") for t, n, p, r in overwrites[-100:]],
                kb=["Обходы/Различные методы/Hex replace"])
    if attr_pf:
        recent = [x for x in attr_pf if ctx.is_recent(x[0])]
        if recent:
            ctx.add("HIGH", "Обходы", f"USN {letter}: менялись атрибуты .pf-файлов (BASIC_INFO_CHANGE)",
                    "Изменение базовой информации .pf без изменения данных — установка «Только чтение»/«Скрытый» "
                    "или подмена дат.", [ev(t, n, p) for t, n, p in recent[-80:]],
                    kb=["Обходы/Различные методы/Изменение атрибутов"])
    if uni:
        ctx.add("MEDIUM", "Обходы", f"USN {letter}: исполняемые файлы с необычными Unicode-символами в имени",
                "Невидимые/экзотические символы в имени мешают поиску и отображаются как «???».",
                [ev(t, n, p, f"  [{reason_text(r)}]") for t, n, p, r in uni[-80:]],
                kb=["Обходы/Различные методы/Использование UNICODE символов"])
