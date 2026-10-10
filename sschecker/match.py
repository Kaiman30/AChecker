"""Сопоставление имён/путей/строк с базой ключевых слов."""
import os
import re
from typing import List, Tuple

from . import kb

_USER_PREFIX = re.compile(r"^(?:\\\\\?\\)?(?:[a-z]:|\\device\\harddiskvolume\d+)\\users\\[^\\]+\\", re.I)

_STRONG = [(k, "HIGH") for k in kb.CHEAT_STRONG]
_MEDIUM_RE = [(re.compile(r"(?<![a-z0-9])" + re.escape(k)), k) for k in kb.CHEAT_MEDIUM]
_WEAK_RE = [(re.compile(r"(?<![a-z0-9])" + re.escape(k) + r"(?![a-z0-9])"), k) for k in kb.CHEAT_WEAK]
_MEM_RE = re.compile("|".join("(?:%s)" % p for p in kb.CHEAT_MEMORY_STRINGS), re.I)

# Имена, которые случайно содержат сильные слова, но легитимны
_WHITELIST_SUBSTR = ["wurstmeister", "doomsdayclock"]

# Быстрый префильтр: один regex на все сильные/средние слова
_QUICK = re.compile("|".join(re.escape(k) for k in kb.CHEAT_STRONG + kb.CHEAT_MEDIUM + kb.CHEAT_WEAK
                             + kb.CHEAT_EXTENSIONS), re.I)


def maybe_keyword(text: str) -> bool:
    return bool(text) and _QUICK.search(text) is not None


# Сами компоненты нашего сканера
_SELF = re.compile(r"ss_?checker|ss_report_", re.I)


def strip_user_prefix(path: str) -> str:
    """Убираем C:\\Users\\<имя>\\, чтобы имя пользователя не давало ложных срабатываний."""
    return _USER_PREFIX.sub("", path)


def keyword_hits(text: str, weak: bool = False) -> List[Tuple[str, str]]:
    """Возвращает список (ключевое слово, критичность)."""
    if not text:
        return []
    low = strip_user_prefix(text).lower()
    if _SELF.search(low):
        return []
    if any(w in low for w in _WHITELIST_SUBSTR):
        return []
    hits = []
    for k, sev in _STRONG:
        if k in low:
            hits.append((k, sev))
    for rx, k in _MEDIUM_RE:
        if rx.search(low):
            hits.append((k, "MEDIUM"))
    if weak:
        base = os.path.basename(low.replace("/", "\\").rstrip("\\")) if ("\\" in low or "/" in low) else low
        for rx, k in _WEAK_RE:
            if rx.search(base):
                hits.append((k, "LOW"))
    ext = os.path.splitext(low)[1]
    if ext in kb.CHEAT_EXTENSIONS:
        hits.append((ext, "HIGH"))
    # убрать дубли, оставив наивысшую критичность
    best = {}
    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    for k, s in hits:
        if k not in best or order[s] < order[best[k]]:
            best[k] = s
    return sorted(best.items(), key=lambda x: order[x[1]])


def top_severity(hits: List[Tuple[str, str]]) -> str:
    for s in ("HIGH", "MEDIUM", "LOW"):
        if any(h[1] == s for h in hits):
            return s
    return "INFO"


def hits_text(hits: List[Tuple[str, str]]) -> str:
    return ", ".join(k for k, _ in hits)


def memory_cheat_hits(text: str) -> List[str]:
    return sorted({m.group(0).lower() for m in _MEM_RE.finditer(text)})


def suspicious_commands(text: str):
    """Ищет в строке команды обхода из базы. Возвращает [(severity, описание, совпадение)]."""
    out = []
    low = text.lower()
    for pat, sev, desc in kb.SUSPICIOUS_COMMANDS:
        m = re.search(pat, low)
        if m:
            out.append((sev, desc, m.group(0)))
    return out


_HOMOGLYPHS = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "к": "k", "т": "t",
    "н": "h", "м": "m", "в": "b", "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "ɡ": "g",
    "А": "A", "Е": "E", "О": "O", "Р": "P", "С": "C", "Х": "X", "У": "Y", "К": "K", "Т": "T",
    "Н": "H", "М": "M", "В": "B", "І": "I",
})


def deconfuse(s: str) -> str:
    """Заменяет кириллические «двойники» латиницей (обход Prefetch с русской «е»)."""
    return s.translate(_HOMOGLYPHS)


def unusual_unicode(name: str) -> List[str]:
    """Символы, которыми прячут файлы: невидимые, RTL-override, приватная зона, не латиница/кириллица."""
    import unicodedata
    bad = []
    for ch in name:
        o = ord(ch)
        if o < 128:
            continue
        cat = unicodedata.category(ch)
        if cat in ("Cf", "Co", "Cn", "Cc", "Zl", "Zp") or ch in "\u00a0\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u3000\u2800":
            bad.append(f"U+{o:04X}")
        elif not (0x0400 <= o <= 0x04FF) and cat.startswith("L") and not (0x00C0 <= o <= 0x024F):
            # буква не из латиницы/кириллицы (иероглифы, греческий и т.п.)
            bad.append(f"U+{o:04X}")
    return bad
