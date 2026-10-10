"""Парсеры бинарных артефактов Windows (без зависимостей от WinAPI — тестируются где угодно)."""
import codecs
import re
import struct
import zipfile
from typing import Dict, List, Optional

from . import kb
from .match import keyword_hits, memory_cheat_hits
from .winutil import filetime_to_dt


# ---------------------------------------------------------------------------
# Строки
# ---------------------------------------------------------------------------
_ASCII_RE = re.compile(rb"[\x20-\x7e]{4,}")
_UTF16_RE = re.compile(rb"(?:[\x20-\x7e\xa0-\xff]\x00|[\x00-\xff][\x04]){4,}")


def ascii_strings(data: bytes, min_len: int = 4) -> List[str]:
    rx = _ASCII_RE if min_len == 4 else re.compile(rb"[\x20-\x7e]{%d,}" % min_len)
    return [m.group(0).decode("ascii") for m in rx.finditer(data)]


def utf16_strings(data: bytes, min_len: int = 4) -> List[str]:
    rx = _UTF16_RE if min_len == 4 else re.compile(rb"(?:[\x20-\x7e\xa0-\xff]\x00|[\x00-\xff][\x04]){%d,}" % min_len)
    out = []
    for m in rx.finditer(data):
        s = m.group(0)
        start = m.start()
        if start % 2:  # выравнивание
            s = s[1:]
        try:
            out.append(s.decode("utf-16-le", errors="ignore"))
        except UnicodeDecodeError:
            pass
    return out


def decode_text_file(raw: bytes) -> str:
    if raw.startswith(codecs.BOM_UTF16_LE):
        return raw[2:].decode("utf-16-le", errors="replace")
    if raw.startswith(codecs.BOM_UTF8):
        return raw[3:].decode("utf-8", errors="replace")
    if len(raw) > 4 and raw[1:2] == b"\x00" and raw[3:4] == b"\x00":
        return raw.decode("utf-16-le", errors="replace")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("cp1251", errors="replace")


# ---------------------------------------------------------------------------
# Prefetch (SCCA v17/23/26/30/31)
# ---------------------------------------------------------------------------
def parse_prefetch(data: bytes) -> Optional[Dict]:
    if len(data) < 0x100 or data[4:8] != b"SCCA":
        return None
    version = struct.unpack_from("<I", data, 0)[0]
    exe = data[0x10:0x10 + 60].decode("utf-16-le", errors="ignore").split("\x00", 1)[0]
    pf_hash = "%08X" % struct.unpack_from("<I", data, 0x4C)[0]
    metrics_off = struct.unpack_from("<I", data, 0x54)[0]
    fn_off, fn_size = struct.unpack_from("<II", data, 0x64)
    runs = []
    if version == 17:
        runs = [struct.unpack_from("<Q", data, 0x78)[0]]
        count = struct.unpack_from("<I", data, 0x90)[0]
    elif version == 23:
        runs = [struct.unpack_from("<Q", data, 0x80)[0]]
        count = struct.unpack_from("<I", data, 0x98)[0]
    else:  # 26, 30, 31
        runs = list(struct.unpack_from("<8Q", data, 0x80))
        count_off = 0xC8 if (version >= 30 and metrics_off == 0x128) else 0xD0
        count = struct.unpack_from("<I", data, count_off)[0]
    times = [t for t in (filetime_to_dt(r) for r in runs) if t]
    files = []
    if 0 < fn_off < len(data) and fn_size:
        blob = data[fn_off:fn_off + fn_size]
        files = [s for s in blob.decode("utf-16-le", errors="ignore").split("\x00") if s]
    exe_path = ""
    up = "\\" + exe.upper()
    for f in files:
        if f.upper().endswith(up):
            exe_path = f
            break
    return {"version": version, "exe": exe, "hash": pf_hash, "run_count": count,
            "last_runs": sorted(times, reverse=True), "files": files, "exe_path": exe_path}


# ---------------------------------------------------------------------------
# LNK (Shell Link)
# ---------------------------------------------------------------------------
_DRIVE_TYPES = {0: "неизвестно", 1: "нет корня", 2: "СЪЁМНЫЙ (USB)", 3: "локальный", 4: "сетевой",
                5: "CD-ROM", 6: "RAM-диск"}


def _cstr(data: bytes, off: int, enc: str = "mbcs") -> str:
    end = data.find(b"\x00", off)
    raw = data[off:end if end >= 0 else len(data)]
    for e in (enc, "cp1251", "latin-1"):
        try:
            return raw.decode(e)
        except (LookupError, UnicodeDecodeError):
            continue
    return ""


def _wstr(data: bytes, off: int) -> str:
    i = off
    while i + 1 < len(data) and data[i:i + 2] != b"\x00\x00":
        i += 2
    return data[off:i].decode("utf-16-le", errors="ignore")


def _idlist_path(idl: bytes) -> str:
    parts = []
    pos = 0
    while pos + 2 <= len(idl):
        size = struct.unpack_from("<H", idl, pos)[0]
        if size < 2:
            break
        item = idl[pos:pos + size]
        pos += size
        if len(item) < 3:
            continue
        t = item[2]
        if t == 0x2F:  # том
            parts.append(_cstr(item, 3, "latin-1").rstrip("\\"))
        elif t & 0x70 == 0x30:  # файл/папка
            name = ""
            sig = item.find(b"\x04\x00\xef\xbe")
            if sig > 0:
                cands = [s for s in utf16_strings(item[sig:], 1)]
                cands = [c for c in cands if c.strip() and not c.startswith("\x00")]
                if cands:
                    name = max(cands, key=len)
            if not name:
                name = _cstr(item, 14, "latin-1")
            if name:
                parts.append(name)
    return "\\".join(parts)


def parse_lnk(data: bytes) -> Optional[Dict]:
    if len(data) < 0x4C or struct.unpack_from("<I", data, 0)[0] != 0x4C:
        return None
    flags = struct.unpack_from("<I", data, 0x14)[0]
    ctime, atime, wtime = struct.unpack_from("<QQQ", data, 0x1C)
    fsize = struct.unpack_from("<I", data, 0x34)[0]
    res = {"target": "", "args": "", "workdir": "", "relpath": "", "name": "", "drive_type": "",
           "serial": "", "label": "", "net": "", "size": fsize,
           "target_ctime": filetime_to_dt(ctime), "target_atime": filetime_to_dt(atime),
           "target_mtime": filetime_to_dt(wtime)}
    pos = 0x4C
    unicode = bool(flags & 0x80)
    if flags & 0x1 and pos + 2 <= len(data):
        idsize = struct.unpack_from("<H", data, pos)[0]
        try:
            res["target"] = _idlist_path(data[pos + 2:pos + 2 + idsize])
        except (struct.error, IndexError):
            pass
        pos += 2 + idsize
    if flags & 0x2 and pos + 0x1C <= len(data):
        li = data[pos:]
        li_size, hdr_size, li_flags, vol_off, lbp_off, cnr_off, cps_off = struct.unpack_from("<7I", li, 0)
        lbp_u = cps_u = 0
        if hdr_size >= 0x24:
            lbp_u, cps_u = struct.unpack_from("<II", li, 0x1C)
        base = suffix = ""
        if li_flags & 0x1:
            if vol_off and vol_off + 16 <= len(li):
                _, dtype, serial, label_off = struct.unpack_from("<IIII", li, vol_off)
                res["drive_type"] = _DRIVE_TYPES.get(dtype, str(dtype))
                res["serial"] = "%04X-%04X" % (serial >> 16, serial & 0xFFFF)
                if label_off == 0x14:
                    lu = struct.unpack_from("<I", li, vol_off + 16)[0]
                    res["label"] = _wstr(li, vol_off + lu)
                else:
                    res["label"] = _cstr(li, vol_off + label_off)
            base = _wstr(li, lbp_u) if lbp_u else _cstr(li, lbp_off)
        if li_flags & 0x2 and cnr_off + 20 <= len(li):
            net_off = struct.unpack_from("<I", li, cnr_off + 8)[0]
            res["net"] = _cstr(li, cnr_off + net_off)
            if not base:
                base = res["net"] + "\\"
        suffix = _wstr(li, cps_u) if cps_u else (_cstr(li, cps_off) if cps_off else "")
        if base:
            res["target"] = (base.rstrip("\\") + "\\" + suffix) if suffix else base
        pos += li_size
    for flag, key in ((0x4, "name"), (0x8, "relpath"), (0x10, "workdir"), (0x20, "args"), (0x40, "icon")):
        if flags & flag:
            if pos + 2 > len(data):
                break
            cnt = struct.unpack_from("<H", data, pos)[0]
            pos += 2
            if unicode:
                res[key] = data[pos:pos + cnt * 2].decode("utf-16-le", errors="ignore")
                pos += cnt * 2
            else:
                res[key] = data[pos:pos + cnt].decode("latin-1", errors="ignore")
                pos += cnt
    if not res["target"] and res["relpath"]:
        res["target"] = res["relpath"]
    return res


# ---------------------------------------------------------------------------
# Корзина: $I-файлы
# ---------------------------------------------------------------------------
def parse_recycle_i(data: bytes) -> Optional[Dict]:
    if len(data) < 28:
        return None
    ver, size, ft = struct.unpack_from("<QQQ", data, 0)
    if ver == 1:
        path = data[24:24 + 520].decode("utf-16-le", errors="ignore").split("\x00", 1)[0]
    elif ver == 2:
        n = struct.unpack_from("<I", data, 24)[0]
        path = data[28:28 + n * 2].decode("utf-16-le", errors="ignore").split("\x00", 1)[0]
    else:
        return None
    return {"path": path, "size": size, "deleted": filetime_to_dt(ft)}


# ---------------------------------------------------------------------------
# ShimCache (AppCompatCache) Windows 8/10/11
# ---------------------------------------------------------------------------
def parse_shimcache(data: bytes) -> List[Dict]:
    out = []
    if len(data) < 0x34:
        return out
    pos = struct.unpack_from("<I", data, 0)[0]
    if pos not in (0x30, 0x34, 0x80):
        # ищем первую сигнатуру
        i = data.find(b"10ts")
        if i < 0:
            i = data.find(b"00ts")
        if i < 0:
            return out
        pos = i
    while pos + 12 <= len(data):
        sig = data[pos:pos + 4]
        if sig not in (b"10ts", b"00ts"):
            break
        ce_size = struct.unpack_from("<I", data, pos + 8)[0]
        entry = data[pos + 12:pos + 12 + ce_size]
        pos += 12 + ce_size
        if len(entry) < 2:
            break
        plen = struct.unpack_from("<H", entry, 0)[0]
        path = entry[2:2 + plen].decode("utf-16-le", errors="ignore")
        mtime = None
        if 2 + plen + 8 <= len(entry):
            mtime = filetime_to_dt(struct.unpack_from("<Q", entry, 2 + plen)[0])
        out.append({"path": path, "mtime": mtime})
    return out


# ---------------------------------------------------------------------------
# UserAssist
# ---------------------------------------------------------------------------
def parse_userassist(name: str, data: bytes) -> Dict:
    path = codecs.decode(name, "rot13")
    for guid, folder in kb.KNOWN_FOLDER_GUIDS.items():
        if path.upper().startswith(guid):
            path = folder + path[len(guid):]
            break
    count = focus = 0
    last = None
    if isinstance(data, bytes):
        if len(data) >= 68:
            count = struct.unpack_from("<I", data, 4)[0]
            focus = struct.unpack_from("<I", data, 12)[0]
            last = filetime_to_dt(struct.unpack_from("<Q", data, 60)[0])
        elif len(data) >= 16:
            count = max(0, struct.unpack_from("<I", data, 4)[0] - 5)
            last = filetime_to_dt(struct.unpack_from("<Q", data, 8)[0])
    return {"path": path, "count": count, "focus_ms": focus, "last": last}


# ---------------------------------------------------------------------------
# PCA (C:\Windows\appcompat\pca)
# ---------------------------------------------------------------------------
def parse_pca_launchdic(text: str) -> List[Dict]:
    from .winutil import parse_iso
    out = []
    for line in text.splitlines():
        if "|" not in line:
            continue
        path, ts = line.rsplit("|", 1)
        out.append({"path": path.strip(), "time": parse_iso(ts.strip())})
    return out


def parse_pca_generaldb(text: str) -> List[Dict]:
    from .winutil import parse_iso
    out = []
    for line in text.splitlines():
        parts = line.split("|")
        if len(parts) < 3:
            continue
        rec = {"time": parse_iso(parts[0].strip()), "status": parts[1].strip(), "path": parts[2].strip(),
               "desc": parts[3].strip() if len(parts) > 3 else "",
               "vendor": parts[4].strip() if len(parts) > 4 else "",
               "version": parts[5].strip() if len(parts) > 5 else "",
               "exitcode": parts[-1].strip() if len(parts) > 7 else ""}
        out.append(rec)
    return out


# ---------------------------------------------------------------------------
# Анализ .jar (Моды → внешние признаки, методы, теория)
# ---------------------------------------------------------------------------
_SHORT_CLASS = re.compile(r"^[A-Za-z]{1,2}(\$[\w$]*)?\.class$")
_IIII_CLASS = re.compile(r"^[Il1]{6,}(\$[\w$]*)?\.class$|^[O0]{6,}\.class$")
_CHEAT_PACKAGE = re.compile(
    r"(?:^|/)(?:modules?|features?|hacks?|cheats?|impl/module)/(?:combat|movement|render|visuals?|player|"
    r"misc|world|exploit|ghost|blatant|legit)(?:/|$)", re.I)
_META_FILES = ("mcmod.info", "fabric.mod.json", "meta-inf/mods.toml", "quilt.mod.json",
               "meta-inf/neoforge.mods.toml", "litemod.json", "riftmod.json")


def _meta_info(zf: zipfile.ZipFile, names_lower: Dict[str, str]) -> Dict:
    import json
    info = {"loader": "", "id": "", "name": "", "version": ""}
    try:
        if "fabric.mod.json" in names_lower:
            d = json.loads(zf.read(names_lower["fabric.mod.json"]).decode("utf-8", "replace"), strict=False)
            info.update(loader="Fabric", id=str(d.get("id", "")), name=str(d.get("name", "")),
                        version=str(d.get("version", "")))
        elif "quilt.mod.json" in names_lower:
            d = json.loads(zf.read(names_lower["quilt.mod.json"]).decode("utf-8", "replace"), strict=False)
            ql = d.get("quilt_loader", {})
            info.update(loader="Quilt", id=str(ql.get("id", "")), version=str(ql.get("version", "")),
                        name=str(ql.get("metadata", {}).get("name", "")))
        elif "meta-inf/mods.toml" in names_lower or "meta-inf/neoforge.mods.toml" in names_lower:
            key = "meta-inf/mods.toml" if "meta-inf/mods.toml" in names_lower else "meta-inf/neoforge.mods.toml"
            t = zf.read(names_lower[key]).decode("utf-8", "replace")
            info["loader"] = "Forge" if "neoforge" not in key else "NeoForge"
            for k in ("modId", "displayName", "version"):
                m = re.search(r'^\s*%s\s*=\s*"([^"]*)"' % k, t, re.M)
                if m:
                    info[{"modId": "id", "displayName": "name", "version": "version"}[k]] = m.group(1)
        elif "mcmod.info" in names_lower:
            t = zf.read(names_lower["mcmod.info"]).decode("utf-8", "replace")
            info["loader"] = "Forge (legacy)"
            for k, dst in (("modid", "id"), ("name", "name"), ("version", "version")):
                m = re.search(r'"%s"\s*:\s*"([^"]*)"' % k, t)
                if m:
                    info[dst] = m.group(1)
        elif "litemod.json" in names_lower:
            info["loader"] = "LiteLoader"
    except (KeyError, ValueError, zipfile.BadZipFile, RuntimeError, OSError):
        pass
    return info


def analyze_jar(path: str, size: int, max_scan_bytes: int = 48 << 20) -> Dict:
    """Статический разбор jar: структура, обфускация, вложенные DLL, строки читов, методы."""
    r = {"path": path, "size": size, "error": "", "classes": 0, "short_classes": 0, "weird_classes": 0,
         "natives": [], "has_meta": False, "meta": {}, "cheat_strings": [], "cheat_packages": [],
         "class_keywords": [], "methods": {}, "imports": [], "l_png": False, "keywords_txt": False,
         "flags": [], "score": 0, "severity": "INFO"}
    try:
        zf = zipfile.ZipFile(path)
    except (zipfile.BadZipFile, OSError, ValueError) as e:
        r["error"] = f"не открывается как zip: {e}"
        r["flags"].append(("MEDIUM", "Файл .jar повреждён или не является архивом"))
        r["score"] += 2
        _finalize_jar(r)
        return r
    with zf:
        infos = zf.infolist()
        names_lower = {i.filename.lower(): i.filename for i in infos}
        r["has_meta"] = any(m in names_lower for m in _META_FILES)
        r["meta"] = _meta_info(zf, names_lower)
        r["l_png"] = "l.png" in names_lower
        r["mcmod"] = "mcmod.info" in names_lower
        r["keywords_txt"] = any(n.endswith("keywords.txt") for n in names_lower)
        scanned = 0
        mem_hits, pkg_hits, kw_hits = set(), set(), set()
        meth_hits = {}
        imp_hits = set()
        for info in infos:
            name = info.filename
            low = name.lower()
            base = name.rsplit("/", 1)[-1]
            if low.endswith((".dll", ".so", ".dylib", ".exe", ".sys")):
                r["natives"].append(name)
            if low.endswith(".class"):
                r["classes"] += 1
                if _SHORT_CLASS.match(base):
                    r["short_classes"] += 1
                if _IIII_CLASS.match(base) or any(ord(c) > 127 for c in base):
                    r["weird_classes"] += 1
                if _CHEAT_PACKAGE.search(low):
                    pkg_hits.add(name.rsplit("/", 1)[0])
                for k, sev in keyword_hits(name):
                    if sev == "HIGH":
                        kw_hits.add(k)
                if scanned < max_scan_bytes and info.file_size < 8 << 20:
                    try:
                        blob = zf.read(info)
                    except (zipfile.BadZipFile, RuntimeError, OSError, NotImplementedError, ValueError):
                        continue
                    scanned += len(blob)
                    text = blob.decode("latin-1")
                    for h in memory_cheat_hits(text):
                        mem_hits.add(h)
                    for loader, table in kb.SUSPICIOUS_METHODS.items():
                        for m in table:
                            if m in text:
                                meth_hits.setdefault(loader, set()).add(m)
                    for imp in kb.SUSPICIOUS_IMPORTS:
                        if imp in text:
                            imp_hits.add(imp)
        r["cheat_strings"] = sorted(mem_hits)
        r["cheat_packages"] = sorted(pkg_hits)[:15]
        r["class_keywords"] = sorted(kw_hits)
        r["methods"] = {k: sorted(v) for k, v in meth_hits.items()}
        r["imports"] = sorted(imp_hits)
    _score_jar(r)
    return r


def _score_jar(r: Dict):
    f = r["flags"]
    if r["cheat_strings"]:
        f.append(("HIGH", "В байткоде есть строки модулей читов: " + ", ".join(r["cheat_strings"][:10])))
        r["score"] += 6
    if r["cheat_packages"]:
        f.append(("HIGH", "Структура пакетов как у чит-клиента (module/combat, module/render…): "
                  + ", ".join(r["cheat_packages"][:5])))
        r["score"] += 5
    if r["class_keywords"]:
        f.append(("HIGH", "Имена классов содержат названия читов: " + ", ".join(r["class_keywords"])))
        r["score"] += 5
    natives = r["natives"]
    if natives:
        sev = "HIGH" if any("inject" in n.lower() for n in natives) else "MEDIUM"
        f.append((sev, "Внутри мода нативные библиотеки: " + ", ".join(natives[:5])))
        r["score"] += 4 if sev == "HIGH" else 2
    if r["keywords_txt"]:
        f.append(("MEDIUM", "Внутри мода keywords.txt (конфиг назначения клавиш)"))
        r["score"] += 2
    cls = r["classes"]
    if cls >= 10:
        ratio = (r["short_classes"] + r["weird_classes"]) / cls
        if ratio >= 0.5:
            f.append(("MEDIUM", f"Обфускация: {r['short_classes'] + r['weird_classes']} из {cls} классов "
                                f"с именами вида a.class / IIIIIII.class"))
            r["score"] += 2
    if r["weird_classes"] >= 3 and cls < 10:
        f.append(("MEDIUM", "Классы со странными именами (IIIII / иероглифы)"))
        r["score"] += 2
    if not r["has_meta"] and cls > 0:
        f.append(("MEDIUM", "Нет метаданных мода (mcmod.info / fabric.mod.json / mods.toml)"))
        r["score"] += 2
    lo, hi = kb.DOOMSDAY_SIZE_RANGE
    if r["l_png"] and r.get("mcmod"):
        if lo <= r["size"] <= hi:
            f.append(("HIGH", "Сигнатура Doomsday Client: l.png + mcmod.info, размер 21 КБ–10 МБ"))
            r["score"] += 5
    if r["size"] in kb.JAR_CHEAT_SIZES:
        f.append(("HIGH", f"Точный размер {r['size']} байт совпадает с известным читом (база Everything)"))
        r["score"] += 5
    total_methods = sum(len(v) for v in r["methods"].values())
    if total_methods >= 4 and r["score"] >= 2:
        f.append(("MEDIUM", "Используются методы, которые часто меняют читы: "
                  + "; ".join(f"{m} ({kb.SUSPICIOUS_METHODS[l][m]})" for l, ms in r["methods"].items()
                              for m in ms[:4])))
        r["score"] += 1
    _finalize_jar(r)


def _finalize_jar(r: Dict):
    sevs = [s for s, _ in r["flags"]]
    for s in ("HIGH", "MEDIUM", "LOW"):
        if s in sevs:
            r["severity"] = s
            break
    if r["score"] >= 8:
        r["severity"] = "CRITICAL" if any(s == "HIGH" for s in sevs) else r["severity"]
