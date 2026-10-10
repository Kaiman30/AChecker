"""Обёртки над WinAPI/реестром/консольными утилитами. На не-Windows возвращают пустые значения."""
import json
import os
import re
import struct
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple

IS_WIN = sys.platform == "win32"

if IS_WIN:
    import ctypes
    import winreg
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    ntdll = ctypes.WinDLL("ntdll")
    shell32 = ctypes.WinDLL("shell32")
else:  # чтобы модуль импортировался при тестах на Linux
    ctypes = None
    winreg = None

_EPOCH_1601 = datetime(1601, 1, 1, tzinfo=timezone.utc)
CREATE_NO_WINDOW = 0x08000000


# ---------------------------------------------------------------------------
# Время
# ---------------------------------------------------------------------------
def filetime_to_dt(ft: int) -> Optional[datetime]:
    if not ft or ft <= 0:
        return None
    try:
        dt = _EPOCH_1601 + timedelta(microseconds=ft // 10)
    except OverflowError:
        return None
    if dt.year < 1995 or dt.year > 2100:
        return None
    return dt


def unix_to_dt(ts) -> Optional[datetime]:
    try:
        ts = float(ts)
        if ts <= 0:
            return None
        return datetime.fromtimestamp(ts, timezone.utc)
    except (ValueError, OSError, OverflowError):
        return None


def mtime_dt(path: str) -> Optional[datetime]:
    try:
        return datetime.fromtimestamp(os.path.getmtime(path), timezone.utc)
    except OSError:
        return None


def ctime_dt(path: str) -> Optional[datetime]:
    try:
        return datetime.fromtimestamp(os.path.getctime(path), timezone.utc)
    except OSError:
        return None


def parse_iso(s: str) -> Optional[datetime]:
    if not s:
        return None
    s = s.strip().replace("Z", "+00:00")
    m = re.match(r"(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})(\.\d+)?(.*)", s)
    if not m:
        return None
    frac = (m.group(3) or "")[:7]
    try:
        base = datetime.strptime(f"{m.group(1)} {m.group(2)}", "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None
    if frac:
        base = base.replace(microsecond=int(float(frac) * 1_000_000))
    tz = m.group(4).strip()
    if tz:
        tm = re.match(r"([+-])(\d{2}):?(\d{2})", tz)
        if tm:
            off = timedelta(hours=int(tm.group(2)), minutes=int(tm.group(3)))
            if tm.group(1) == "-":
                off = -off
            return base.replace(tzinfo=timezone(off)).astimezone(timezone.utc)
    return base.replace(tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# Процессы/консоль
# ---------------------------------------------------------------------------
def _decode(b: bytes) -> str:
    if not b:
        return ""
    try:
        return b.decode("utf-8")
    except UnicodeDecodeError:
        pass
    if IS_WIN:
        try:
            return b.decode("cp%d" % kernel32.GetOEMCP())
        except (UnicodeDecodeError, LookupError):
            pass
        try:
            return b.decode("mbcs", errors="replace")
        except LookupError:
            pass
    return b.decode("latin-1", errors="replace")


def run(cmd: List[str], timeout: int = 120) -> Tuple[int, str]:
    try:
        kw = {"creationflags": CREATE_NO_WINDOW} if IS_WIN else {}
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout,
                           stdin=subprocess.DEVNULL, **kw)
        return p.returncode, _decode(p.stdout)
    except (OSError, subprocess.TimeoutExpired) as e:
        return -1, str(e)


def run_bytes(cmd: List[str], timeout: int = 120) -> bytes:
    try:
        kw = {"creationflags": CREATE_NO_WINDOW} if IS_WIN else {}
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout,
                           stdin=subprocess.DEVNULL, **kw)
        return p.stdout or b""
    except (OSError, subprocess.TimeoutExpired):
        return b""


def powershell(script: str, timeout: int = 300) -> str:
    prefix = ("[Console]::OutputEncoding=[System.Text.Encoding]::UTF8;"
              "$ProgressPreference='SilentlyContinue';$ErrorActionPreference='SilentlyContinue';")
    rc, out = run(["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                   "-Command", prefix + script], timeout=timeout)
    return out


def ps_json(script: str, timeout: int = 300):
    out = powershell(script, timeout).strip()
    if not out:
        return None
    try:
        data = json.loads(out)
    except ValueError:
        # иногда перед JSON бывает мусор
        i = min([x for x in (out.find("["), out.find("{")) if x >= 0] or [0])
        try:
            data = json.loads(out[i:])
        except ValueError:
            return None
    if isinstance(data, dict):
        data = [data]
    return data


def is_admin() -> bool:
    if not IS_WIN:
        return os.geteuid() == 0 if hasattr(os, "geteuid") else False
    try:
        return bool(shell32.IsUserAnAdmin())
    except Exception:
        return False


def enable_vt_mode():
    if not IS_WIN:
        return
    try:
        h = kernel32.GetStdHandle(-11)
        mode = wintypes.DWORD()
        if kernel32.GetConsoleMode(h, ctypes.byref(mode)):
            kernel32.SetConsoleMode(h, mode.value | 0x0004)
        kernel32.SetConsoleOutputCP(65001)
    except Exception:
        pass


def enable_privilege(name: str = "SeDebugPrivilege") -> bool:
    if not IS_WIN:
        return False

    class LUID(ctypes.Structure):
        _fields_ = [("LowPart", wintypes.DWORD), ("HighPart", wintypes.LONG)]

    class LUID_AND_ATTRIBUTES(ctypes.Structure):
        _fields_ = [("Luid", LUID), ("Attributes", wintypes.DWORD)]

    class TOKEN_PRIVILEGES(ctypes.Structure):
        _fields_ = [("PrivilegeCount", wintypes.DWORD), ("Privileges", LUID_AND_ATTRIBUTES * 1)]

    token = wintypes.HANDLE()
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), 0x0020 | 0x0008, ctypes.byref(token)):
        return False
    luid = LUID()
    if not advapi32.LookupPrivilegeValueW(None, name, ctypes.byref(luid)):
        kernel32.CloseHandle(token)
        return False
    tp = TOKEN_PRIVILEGES(1, (LUID_AND_ATTRIBUTES * 1)(LUID_AND_ATTRIBUTES(luid, 0x2)))
    ok = advapi32.AdjustTokenPrivileges(token, False, ctypes.byref(tp), 0, None, None)
    err = ctypes.get_last_error()
    kernel32.CloseHandle(token)
    return bool(ok) and err == 0


# ---------------------------------------------------------------------------
# Диски и пути
# ---------------------------------------------------------------------------
_DEVICE_MAP: Optional[Dict[str, str]] = None


def device_map() -> Dict[str, str]:
    """\\device\\harddiskvolume3 -> C:"""
    global _DEVICE_MAP
    if _DEVICE_MAP is not None:
        return _DEVICE_MAP
    m = {}
    if IS_WIN:
        buf = ctypes.create_unicode_buffer(1024)
        for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
            if kernel32.QueryDosDeviceW(f"{letter}:", buf, 1024):
                m[buf.value.lower()] = f"{letter}:"
    _DEVICE_MAP = m
    return m


def drives(types=(2, 3)) -> List[Tuple[str, int]]:
    """Список (корень, тип): 2 — съёмный, 3 — локальный, 4 — сетевой, 5 — CD."""
    out = []
    if not IS_WIN:
        return out
    mask = kernel32.GetLogicalDrives()
    for i in range(26):
        if mask & (1 << i):
            root = f"{chr(65 + i)}:\\"
            t = kernel32.GetDriveTypeW(root)
            if t in types:
                out.append((root, t))
    return out


def volume_info(root: str) -> Tuple[str, str]:
    """(метка, файловая система)."""
    if not IS_WIN:
        return "", ""
    name = ctypes.create_unicode_buffer(261)
    fs = ctypes.create_unicode_buffer(261)
    serial = wintypes.DWORD()
    if kernel32.GetVolumeInformationW(root, name, 261, ctypes.byref(serial), None, None, fs, 261):
        return name.value, fs.value
    return "", ""


_ENV_RE = re.compile(r"%([^%]+)%")


def normalize_path(p: str) -> str:
    """Приводит пути из разных артефактов к виду C:\\..."""
    if not p:
        return p
    p = p.strip().strip("\x00").strip('"')
    p = p.replace("/", "\\")
    if p.lower().startswith("file:\\\\\\"):
        p = p[8:]
    for pre in ("\\\\?\\", "\\??\\", "\\\\.\\"):
        if p.startswith(pre):
            p = p[len(pre):]
    low = p.lower()
    if low.startswith("\\device\\"):
        for dev, letter in device_map().items():
            if low.startswith(dev + "\\"):
                p = letter + p[len(dev):]
                break
    elif low.startswith("\\systemroot\\"):
        p = os.environ.get("SystemRoot", "C:\\Windows") + p[11:]
    elif low.startswith("sysvol\\"):
        p = os.environ.get("SystemDrive", "C:") + p[6:]
    if "%" in p:
        p = _ENV_RE.sub(lambda m: os.environ.get(m.group(1), m.group(0)), p)
    return p


def path_exists(p: str) -> Optional[bool]:
    """None — путь не локальный (нельзя проверить)."""
    if not re.match(r"^[A-Za-z]:\\", p or ""):
        return None
    try:
        return os.path.exists(p)
    except (OSError, ValueError):
        return None


# ---------------------------------------------------------------------------
# Реестр
# ---------------------------------------------------------------------------
HIVES = {}
if IS_WIN:
    HIVES = {"HKLM": winreg.HKEY_LOCAL_MACHINE, "HKCU": winreg.HKEY_CURRENT_USER,
             "HKU": winreg.HKEY_USERS, "HKCR": winreg.HKEY_CLASSES_ROOT}


def reg_open(hive: str, path: str):
    if not IS_WIN:
        return None
    for flag in (winreg.KEY_READ | winreg.KEY_WOW64_64KEY, winreg.KEY_READ):
        try:
            return winreg.OpenKey(HIVES[hive], path, 0, flag)
        except OSError:
            continue
    return None


def reg_values(key) -> List[Tuple[str, object, int]]:
    out = []
    if key is None:
        return out
    i = 0
    while True:
        try:
            out.append(winreg.EnumValue(key, i))
        except OSError:
            break
        i += 1
    return out


def reg_subkeys(key) -> List[str]:
    out = []
    if key is None:
        return out
    i = 0
    while True:
        try:
            out.append(winreg.EnumKey(key, i))
        except OSError:
            break
        i += 1
    return out


def reg_last_write(key) -> Optional[datetime]:
    if key is None:
        return None
    try:
        return filetime_to_dt(winreg.QueryInfoKey(key)[2])
    except OSError:
        return None


def reg_get(hive: str, path: str, name: str, default=None):
    k = reg_open(hive, path)
    if k is None:
        return default
    try:
        return winreg.QueryValueEx(k, name)[0]
    except OSError:
        return default
    finally:
        k.Close()


def current_user_sid() -> str:
    rc, out = run(["whoami", "/user", "/fo", "csv", "/nh"], timeout=20)
    m = re.search(r"(S-1-5-[\d-]+)", out or "")
    return m.group(1) if m else ""


def profile_list() -> List[Tuple[str, str]]:
    """[(SID, путь профиля)] реальных пользователей."""
    out = []
    k = reg_open("HKLM", r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList")
    for sid in reg_subkeys(k):
        if not sid.startswith("S-1-5-21-"):
            continue
        p = reg_get("HKLM", rf"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\{sid}",
                    "ProfileImagePath", "")
        if p:
            out.append((sid, os.path.expandvars(p)))
    return out


# ---------------------------------------------------------------------------
# Файлы: атрибуты, ADS, Zone.Identifier
# ---------------------------------------------------------------------------
FILE_ATTRIBUTE_READONLY = 0x1
FILE_ATTRIBUTE_HIDDEN = 0x2
FILE_ATTRIBUTE_SYSTEM = 0x4


def file_attrs(path: str) -> int:
    if not IS_WIN:
        return 0
    a = kernel32.GetFileAttributesW(path)
    return 0 if a == 0xFFFFFFFF else a


def alt_streams(path: str) -> List[Tuple[str, int]]:
    """Альтернативные потоки NTFS (кроме основного ::$DATA)."""
    if not IS_WIN:
        return []

    class WIN32_FIND_STREAM_DATA(ctypes.Structure):
        _fields_ = [("StreamSize", ctypes.c_longlong), ("cStreamName", ctypes.c_wchar * 296)]

    data = WIN32_FIND_STREAM_DATA()
    kernel32.FindFirstStreamW.restype = wintypes.HANDLE
    h = kernel32.FindFirstStreamW(path, 0, ctypes.byref(data), 0)
    if not h or h == wintypes.HANDLE(-1).value:
        return []
    out = []
    try:
        while True:
            name = data.cStreamName
            if name and name != "::$DATA":
                out.append((name.lstrip(":").rsplit(":$DATA", 1)[0], data.StreamSize))
            if not kernel32.FindNextStreamW(wintypes.HANDLE(h), ctypes.byref(data)):
                break
    finally:
        kernel32.FindClose(wintypes.HANDLE(h))
    return out


def zone_identifier(path: str) -> Dict[str, str]:
    """HostUrl/ReferrerUrl из Zone.Identifier — откуда скачан файл."""
    if not IS_WIN:
        return {}
    try:
        with open(path + ":Zone.Identifier", "r", encoding="utf-8", errors="replace") as f:
            txt = f.read(4096)
    except OSError:
        return {}
    out = {}
    for line in txt.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            if k.strip() in ("HostUrl", "ReferrerUrl", "ZoneId"):
                out[k.strip()] = v.strip()
    return out


def authenticode(paths: List[str], timeout: int = 600) -> Dict[str, Tuple[str, str]]:
    """{путь: (статус, издатель)} через Get-AuthenticodeSignature (проверка доверенными корнями)."""
    paths = [p for p in dict.fromkeys(paths) if p and os.path.isfile(p)]
    if not IS_WIN or not paths:
        return {}
    fd, tmp = tempfile.mkstemp(suffix=".txt")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write("\n".join(paths))
    script = (
        f"$paths = Get-Content -LiteralPath '{tmp}' -Encoding UTF8;"
        "$r = foreach($p in $paths){ try { $s = Get-AuthenticodeSignature -LiteralPath $p -ErrorAction Stop;"
        "$n=''; if($s.SignerCertificate){$n=$s.SignerCertificate.Subject};"
        "[pscustomobject]@{p=$p;s=[string]$s.Status;n=$n} } catch { [pscustomobject]@{p=$p;s='Error';n=''} } };"
        "ConvertTo-Json -Compress -InputObject @($r)"
    )
    try:
        data = ps_json(script, timeout) or []
    finally:
        try:
            os.remove(tmp)
        except OSError:
            pass
    return {d.get("p"): (d.get("s") or "", d.get("n") or "") for d in data if isinstance(d, dict)}


# ---------------------------------------------------------------------------
# Процессы
# ---------------------------------------------------------------------------
def process_list() -> List[dict]:
    script = (
        "$r = Get-CimInstance Win32_Process | ForEach-Object { [pscustomobject]@{"
        "pid=$_.ProcessId; ppid=$_.ParentProcessId; name=$_.Name; path=$_.ExecutablePath;"
        "cmd=$_.CommandLine; created=$(if($_.CreationDate){$_.CreationDate.ToUniversalTime().ToString('o')}else{''})} };"
        "ConvertTo-Json -Compress -Depth 2 -InputObject @($r)"
    )
    return ps_json(script, 180) or []


def service_pids() -> Dict[str, int]:
    """{имя службы (lower): PID} по tasklist /svc."""
    rc, out = run(["tasklist", "/svc", "/fo", "csv", "/nh"], timeout=60)
    res = {}
    for line in out.splitlines():
        parts = re.findall(r'"([^"]*)"', line)
        if len(parts) >= 3 and parts[1].isdigit():
            for svc in parts[2].split(","):
                svc = svc.strip()
                if svc and svc not in ("N/A", "Н/Д"):
                    res[svc.lower()] = int(parts[1])
    return res


def process_create_time(pid: int) -> Optional[datetime]:
    if not IS_WIN:
        return None
    h = kernel32.OpenProcess(0x1000, False, pid)
    if not h:
        return None
    try:
        c, e, k, u = (wintypes.FILETIME() for _ in range(4))
        if kernel32.GetProcessTimes(h, ctypes.byref(c), ctypes.byref(e), ctypes.byref(k), ctypes.byref(u)):
            return filetime_to_dt((c.dwHighDateTime << 32) | c.dwLowDateTime)
    finally:
        kernel32.CloseHandle(h)
    return None


def boot_time() -> Optional[datetime]:
    if not IS_WIN:
        return None
    kernel32.GetTickCount64.restype = ctypes.c_ulonglong
    ms = kernel32.GetTickCount64()
    return datetime.now(timezone.utc) - timedelta(milliseconds=ms)


if IS_WIN:
    class MEMORY_BASIC_INFORMATION(ctypes.Structure):
        _fields_ = [("BaseAddress", ctypes.c_void_p), ("AllocationBase", ctypes.c_void_p),
                    ("AllocationProtect", wintypes.DWORD), ("PartitionId", wintypes.WORD),
                    ("RegionSize", ctypes.c_size_t), ("State", wintypes.DWORD),
                    ("Protect", wintypes.DWORD), ("Type", wintypes.DWORD)]

    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.VirtualQueryEx.restype = ctypes.c_size_t
    kernel32.VirtualQueryEx.argtypes = [wintypes.HANDLE, ctypes.c_void_p,
                                        ctypes.POINTER(MEMORY_BASIC_INFORMATION), ctypes.c_size_t]
    kernel32.ReadProcessMemory.restype = wintypes.BOOL
    kernel32.ReadProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                                           ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4


MEM_COMMIT, MEM_PRIVATE, MEM_MAPPED, MEM_IMAGE = 0x1000, 0x20000, 0x40000, 0x1000000
PAGE_NOACCESS, PAGE_GUARD = 0x01, 0x100


def read_process_memory(pid: int, limit_bytes: int, include_image: bool = False, chunk: int = 8 << 20):
    """Генератор блоков памяти процесса (Private + Mapped, как в System Informer → Strings).

    Если открыть процесс нельзя (защищённый PPL-процесс, нет прав) — бросает PermissionError.
    """
    if not IS_WIN:
        return
    h = kernel32.OpenProcess(0x0400 | 0x0010, False, pid)
    if not h:
        h = kernel32.OpenProcess(0x1000 | 0x0010, False, pid)
    if not h:
        raise PermissionError(ctypes.get_last_error())
    try:
        mbi = MEMORY_BASIC_INFORMATION()
        addr = 0
        total = 0
        types = {MEM_PRIVATE, MEM_MAPPED} | ({MEM_IMAGE} if include_image else set())
        while total < limit_bytes:
            if not kernel32.VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)):
                break
            base = mbi.BaseAddress or 0
            size = mbi.RegionSize or 0
            if size == 0:
                break
            if (mbi.State == MEM_COMMIT and mbi.Type in types and not (mbi.Protect & PAGE_GUARD)
                    and not (mbi.Protect & PAGE_NOACCESS) and mbi.Protect != 0):
                off = 0
                while off < size and total < limit_bytes:
                    n = min(chunk, size - off)
                    buf = ctypes.create_string_buffer(n)
                    got = ctypes.c_size_t(0)
                    kernel32.ReadProcessMemory(h, ctypes.c_void_p(base + off), buf, n, ctypes.byref(got))
                    if got.value:
                        total += got.value
                        yield buf.raw[:got.value]
                    off += n
            addr = base + size
            if addr >= 0x7FFFFFFFFFFF:
                break
    finally:
        kernel32.CloseHandle(h)


# ---------------------------------------------------------------------------
# Распаковка Prefetch (MAM, XPRESS Huffman) через ntdll
# ---------------------------------------------------------------------------
def decompress_mam(data: bytes) -> Optional[bytes]:
    if data[:4] != b"MAM\x04":
        return data
    if not IS_WIN:
        return None
    out_size = struct.unpack_from("<I", data, 4)[0]
    comp = data[8:]
    fmt = 4  # COMPRESSION_FORMAT_XPRESS_HUFF
    ws_size = ctypes.c_ulong()
    frag = ctypes.c_ulong()
    if ntdll.RtlGetCompressionWorkSpaceSize(ctypes.c_ushort(fmt), ctypes.byref(ws_size), ctypes.byref(frag)):
        return None
    ws = ctypes.create_string_buffer(ws_size.value)
    out = ctypes.create_string_buffer(out_size)
    final = ctypes.c_ulong()
    src = ctypes.create_string_buffer(comp, len(comp))
    st = ntdll.RtlDecompressBufferEx(ctypes.c_ushort(fmt), out, ctypes.c_ulong(out_size), src,
                                     ctypes.c_ulong(len(comp)), ctypes.byref(final), ws)
    if st != 0:
        return None
    return out.raw[:final.value]
