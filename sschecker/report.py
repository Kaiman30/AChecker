"""Формирование отчёта: report.html (для модератора) и report.json (для машинной обработки)."""
import html
import json

from . import kb
from .core import SEV_RANK, SEV_RU, SEVERITIES, fmt_dt

E = html.escape


def verdict(ctx):
    counts = {s: 0 for s in SEVERITIES}
    for f in ctx.findings:
        counts[f.severity] += 1
    if counts["CRITICAL"]:
        v = ("crit", "Найдены критические признаки читов или обхода проверки",
             "Есть прямые доказательства (следы читов, очистка артефактов, подмена файлов). Изучите доказательства "
             "ниже и подтвердите их вручную указанными инструментами перед вынесением решения.")
    elif counts["HIGH"]:
        v = ("high", "Найдены серьёзные подозрительные признаки",
             "Автоматических прямых доказательств нет, но есть признаки, которые требуют ручной проверки.")
    elif counts["MEDIUM"]:
        v = ("med", "Есть отдельные подозрительные моменты",
             "Серьёзных признаков не найдено. Просмотрите находки среднего уровня.")
    else:
        v = ("ok", "Явных признаков читов не найдено",
             "Автоматическая проверка ничего значимого не нашла. Это не гарантирует чистоту ПК — используйте "
             "ручные методики из базы.")
    return counts, v


def write_json(ctx, path):
    counts, v = verdict(ctx)
    data = {
        "system": {k: (fmt_dt(x) if hasattr(x, "astimezone") else x) for k, x in ctx.system.items()},
        "verdict": {"level": v[0], "title": v[1], "text": v[2], "counts": counts},
        "findings": [f.to_dict() for f in sorted(ctx.findings, key=lambda f: SEV_RANK[f.severity])],
        "tables": {k: {"title": t["title"], "columns": t["columns"], "rows": [[str(c) for c in r] for r in t["rows"]],
                       "note": t["note"]} for k, t in ctx.tables.items()},
        "errors": ctx.errors,
        "timings": ctx.timings,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=1, default=str)


CSS = """
:root{--bg:#f6f7f9;--card:#fff;--fg:#1d2330;--muted:#5f6b7a;--line:#e3e7ec;--code:#f0f2f5;
--crit:#b3261e;--crit-bg:#fdecea;--high:#c2410c;--high-bg:#fff1e6;--med:#a16207;--med-bg:#fef9e7;
--low:#0e7490;--low-bg:#e6f6fa;--info:#475569;--info-bg:#eef1f5;--ok:#15803d;--ok-bg:#e8f6ec;--link:#1d4ed8}
@media (prefers-color-scheme:dark){:root:not([data-theme=light]){--bg:#0f1218;--card:#171b23;--fg:#e5e9f0;--muted:#97a3b4;
--line:#262c38;--code:#1f2430;--crit:#ff8a80;--crit-bg:#3a1513;--high:#ffab70;--high-bg:#3a2112;--med:#f5cf63;--med-bg:#352c10;
--low:#67d4ec;--low-bg:#0f2f36;--info:#aab4c3;--info-bg:#1f2430;--ok:#6ee7a0;--ok-bg:#12301e;--link:#8ab4ff}}
:root[data-theme=dark]{--bg:#0f1218;--card:#171b23;--fg:#e5e9f0;--muted:#97a3b4;--line:#262c38;--code:#1f2430;--crit:#ff8a80;
--crit-bg:#3a1513;--high:#ffab70;--high-bg:#3a2112;--med:#f5cf63;--med-bg:#352c10;--low:#67d4ec;--low-bg:#0f2f36;--info:#aab4c3;
--info-bg:#1f2430;--ok:#6ee7a0;--ok-bg:#12301e;--link:#8ab4ff}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 "Segoe UI",system-ui,sans-serif}
.wrap{max-width:1280px;margin:0 auto;padding:24px 16px 80px}
h1{font-size:24px;margin:0 0 4px}h2{font-size:18px;margin:32px 0 12px}a{color:var(--link)}
.meta{color:var(--muted);display:flex;flex-wrap:wrap;gap:6px 22px;margin-bottom:18px}
.verdict{border-radius:10px;padding:16px 18px;margin:16px 0;border-left:6px solid}
.verdict.crit{background:var(--crit-bg);border-color:var(--crit)}.verdict.high{background:var(--high-bg);border-color:var(--high)}
.verdict.med{background:var(--med-bg);border-color:var(--med)}.verdict.ok{background:var(--ok-bg);border-color:var(--ok)}
.verdict b{font-size:17px;display:block;margin-bottom:4px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px;margin:16px 0}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 14px;cursor:pointer;user-select:none}
.card .n{font-size:26px;font-weight:700}.card.off{opacity:.35}
.CRITICAL .n,.b-CRITICAL{color:var(--crit)}.HIGH .n,.b-HIGH{color:var(--high)}.MEDIUM .n,.b-MEDIUM{color:var(--med)}
.LOW .n,.b-LOW{color:var(--low)}.INFO .n,.b-INFO{color:var(--info)}
.toolbar{display:flex;gap:10px;flex-wrap:wrap;margin:10px 0 16px}
input[type=search]{flex:1;min-width:220px;padding:9px 12px;border-radius:8px;border:1px solid var(--line);background:var(--card);color:var(--fg)}
button{padding:8px 12px;border-radius:8px;border:1px solid var(--line);background:var(--card);color:var(--fg);cursor:pointer}
.f{background:var(--card);border:1px solid var(--line);border-left:5px solid;border-radius:10px;margin:10px 0;overflow:hidden}
.f.CRITICAL{border-left-color:var(--crit)}.f.HIGH{border-left-color:var(--high)}.f.MEDIUM{border-left-color:var(--med)}
.f.LOW{border-left-color:var(--low)}.f.INFO{border-left-color:var(--info)}
.f summary{list-style:none;cursor:pointer;padding:12px 14px;display:flex;gap:10px;align-items:baseline;flex-wrap:wrap}
.f summary::-webkit-details-marker{display:none}
.badge{font-size:11px;font-weight:700;letter-spacing:.04em;padding:2px 8px;border-radius:99px}
.bg-CRITICAL{background:var(--crit-bg);color:var(--crit)}.bg-HIGH{background:var(--high-bg);color:var(--high)}
.bg-MEDIUM{background:var(--med-bg);color:var(--med)}.bg-LOW{background:var(--low-bg);color:var(--low)}.bg-INFO{background:var(--info-bg);color:var(--info)}
.cat{color:var(--muted);font-size:12px}.ttl{font-weight:600;flex:1;min-width:240px}.cnt{color:var(--muted);font-size:12px}
.body{padding:0 14px 14px}.desc{margin:0 0 10px}.rec{background:var(--code);padding:8px 10px;border-radius:8px;margin:8px 0}
ul.ev{list-style:none;padding:0;margin:8px 0;border-top:1px solid var(--line)}
ul.ev li{padding:6px 0;border-bottom:1px solid var(--line);display:flex;gap:10px;align-items:flex-start}
.t{color:var(--muted);white-space:nowrap;font-variant-numeric:tabular-nums;min-width:140px;font-size:12px;padding-top:2px}
.x{flex:1;word-break:break-all;font-family:Consolas,"Cascadia Mono",monospace;font-size:12.5px}
.cp{font-size:11px;padding:1px 6px;margin-left:6px}
.refs{font-size:12px;color:var(--muted);margin-top:8px}.refs span{display:inline-block;background:var(--code);border-radius:6px;padding:1px 7px;margin:2px 4px 2px 0}
details.tbl{background:var(--card);border:1px solid var(--line);border-radius:10px;margin:8px 0}
details.tbl>summary{cursor:pointer;padding:10px 14px;font-weight:600}
.tw{overflow:auto;max-height:560px;border-top:1px solid var(--line)}
table{border-collapse:collapse;width:100%;font-size:12.5px}th,td{text-align:left;padding:5px 9px;border-bottom:1px solid var(--line);vertical-align:top}
th{position:sticky;top:0;background:var(--card);z-index:1}td{word-break:break-all}
.tf{margin:8px 14px;width:calc(100% - 28px)}.note{color:var(--muted);font-size:12px;padding:0 14px 8px}
pre{white-space:pre-wrap;word-break:break-all;background:var(--code);padding:12px;border-radius:8px;font-size:12px;max-height:600px;overflow:auto}
.hidden{display:none!important}
@media print{.toolbar,.cards,button{display:none}.f{break-inside:avoid}details{open:true}}
@media (max-width:640px){.t{min-width:90px}.wrap{padding:16px 12px 60px}}
"""

JS = """
const active=new Set(['CRITICAL','HIGH','MEDIUM','LOW','INFO']);
function apply(){const q=document.getElementById('q').value.toLowerCase();
document.querySelectorAll('.f').forEach(f=>{const ok=active.has(f.dataset.sev)&&(!q||f.textContent.toLowerCase().includes(q));
f.classList.toggle('hidden',!ok)});}
document.querySelectorAll('.card[data-sev]').forEach(c=>c.onclick=()=>{const s=c.dataset.sev;
if(active.has(s)){active.delete(s);c.classList.add('off')}else{active.add(s);c.classList.remove('off')}apply();});
document.getElementById('q').oninput=apply;
document.getElementById('expand').onclick=()=>document.querySelectorAll('.f').forEach(d=>d.open=true);
document.getElementById('collapse').onclick=()=>document.querySelectorAll('.f').forEach(d=>d.open=false);
document.getElementById('theme').onclick=()=>{const r=document.documentElement;
r.dataset.theme=(r.dataset.theme==='dark'||(!r.dataset.theme&&matchMedia('(prefers-color-scheme: dark)').matches))?'light':'dark'};
document.querySelectorAll('.tf').forEach(i=>i.oninput=()=>{const q=i.value.toLowerCase();
i.parentElement.querySelectorAll('tbody tr').forEach(tr=>tr.classList.toggle('hidden',q&&!tr.textContent.toLowerCase().includes(q)))});
document.addEventListener('click',e=>{if(e.target.classList.contains('cp')){navigator.clipboard&&navigator.clipboard.writeText(e.target.dataset.v);
e.target.textContent='✓';setTimeout(()=>e.target.textContent='копировать',900);e.preventDefault()}});
"""


def _ev_html(ev):
    t = E(fmt_dt(ev.time)) if ev.time else ""
    txt = E(ev.text)
    extra = ""
    if ev.path:
        extra += f'<button class="cp" data-v="{E(ev.path)}">копировать</button>'
    if ev.url:
        extra += f' <a href="{E(ev.url)}" target="_blank" rel="noopener noreferrer">ссылка ↗</a>'
    src = f'<div class="cat">{E(ev.source)}</div>' if ev.source else ""
    return f'<li><span class="t">{t}</span><span class="x">{txt}{extra}{src}</span></li>'


def _tools_html(tools):
    out = []
    for t in tools:
        url = kb.TOOLS.get(t)
        if url and url.startswith("http"):
            out.append(f'<span><a href="{E(url)}" target="_blank" rel="noopener noreferrer">{E(t)}</a></span>')
        else:
            out.append(f"<span>{E(t)}{(' (' + E(url) + ')') if url else ''}</span>")
    return "".join(out)


def write_html(ctx, path, duration):
    counts, v = verdict(ctx)
    s = ctx.system
    findings = sorted(ctx.findings, key=lambda f: (SEV_RANK[f.severity], f.category))
    parts = [f"""<!doctype html><html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Отчёт SS-проверки</title>
<style>{CSS}</style></head><body><div class="wrap">
<h1>Отчёт SS-проверки — {E(str(s.get('hostname', '')))}</h1>
<div class="meta"><span>Пользователь: <b>{E(str(s.get('user', '')))}</b></span><span>{E(str(s.get('os', '')))}</span>
<span>Модель: {E(str(s.get('model', '—')))}</span>
<span>Проверка: {E(fmt_dt(ctx.start))} ({duration:.0f} с)</span><span>Загрузка ПК: {E(fmt_dt(s.get('boot')))}</span>
<span>«Незадолго до проверки» = после {E(fmt_dt(ctx.window_start))}</span>
<span>Права администратора: <b>{'да' if s.get('admin') else 'НЕТ — результаты неполные'}</b></span></div>
<div class="verdict {v[0]}"><b>{E(v[1])}</b>{E(v[2])}</div>
<div class="cards">"""]
    for sev in SEVERITIES:
        parts.append(f'<div class="card {sev}" data-sev="{sev}" title="Показать/скрыть"><div class="n">{counts[sev]}</div>'
                     f'<div>{SEV_RU[sev]}</div></div>')
    parts.append("""</div><div class="toolbar"><input id="q" type="search" placeholder="Поиск по находкам: путь, название, источник…">
<button id="expand">Развернуть все</button><button id="collapse">Свернуть все</button><button id="theme">Тема</button></div>
<h2>Находки</h2>""")
    if not findings:
        parts.append("<p>Находок нет.</p>")
    for f in findings:
        open_attr = " open" if f.severity in ("CRITICAL", "HIGH") else ""
        parts.append(f'<details class="f {f.severity}" data-sev="{f.severity}"{open_attr}><summary>'
                     f'<span class="badge bg-{f.severity}">{SEV_RU[f.severity]}</span>'
                     f'<span class="cat">{E(f.category)}</span><span class="ttl">{E(f.title)}</span>'
                     f'<span class="cnt">доказательств: {len(f.evidence)}</span></summary><div class="body">')
        if f.description:
            parts.append(f'<p class="desc">{E(f.description)}</p>')
        if f.recommendation:
            parts.append(f'<div class="rec">Что сделать: {E(f.recommendation)}</div>')
        if f.evidence:
            parts.append('<ul class="ev">' + "".join(_ev_html(e) for e in f.evidence) + "</ul>")
        refs = ""
        if f.kb:
            refs += "База знаний: " + "".join(f"<span>{E(k)}</span>" for k in f.kb)
        if f.tools:
            refs += "<br>Перепроверить: " + _tools_html(f.tools)
        if refs:
            parts.append(f'<div class="refs">{refs}</div>')
        parts.append("</div></details>")

    parts.append("<h2>Собранные данные</h2>")
    order = ["timeline", "mods", "prefetch", "bam", "pca", "dps", "userassist", "recent", "recycle", "services",
             "memory", "processes"]
    keys = [k for k in order if k in ctx.tables] + [k for k in ctx.tables if k not in order]
    for k in keys:
        t = ctx.tables[k]
        rows = t["rows"]
        parts.append(f'<details class="tbl"><summary>{E(t["title"])} — {len(rows)}</summary>')
        if t.get("note"):
            parts.append(f'<div class="note">{E(t["note"])}</div>')
        if rows:
            parts.append('<input class="tf" type="search" placeholder="Фильтр таблицы…"><div class="tw"><table><thead><tr>'
                         + "".join(f"<th>{E(str(c))}</th>" for c in t["columns"]) + "</tr></thead><tbody>")
            for r in rows:
                parts.append("<tr>" + "".join(f"<td>{E(str(c))}</td>" for c in r) + "</tr>")
            parts.append("</tbody></table></div>")
        else:
            parts.append('<div class="note">Пусто.</div>')
        parts.append("</details>")

    parts.append("<h2>Ограничения и служебная информация</h2>")
    lim = ["Отчёт строится автоматически по методикам из базы знаний. Любую находку перед наказанием нужно "
           "подтвердить вручную указанными инструментами.",
           "Защищённые процессы (MsMpEng, иногда csrss) нельзя прочитать без драйвера — для них используйте System Informer "
           "с включённым Kernel-Mode Driver.",
           "Amcache.hve, SRUM и $MFT заблокированы системой — для них используйте AmcacheParser / SRUMECmd / MFTECmd."]
    parts.append("<ul>" + "".join(f"<li>{E(x)}</li>" for x in lim) + "</ul>")
    if ctx.errors:
        parts.append(f"<details class='tbl'><summary>Ошибки во время проверки — {len(ctx.errors)}</summary><pre>"
                     + E("\n\n".join(ctx.errors)) + "</pre></details>")
    parts.append("<details class='tbl'><summary>Время выполнения проверок</summary><div class='tw'><table><tbody>"
                 + "".join(f"<tr><td>{E(k)}</td><td>{v} с</td></tr>" for k, v in ctx.timings.items())
                 + "</tbody></table></div></details>")
    parts.append("<details class='tbl'><summary>Полный лог</summary><pre>" + E("\n".join(ctx.log.lines)) + "</pre></details>")
    parts.append(f"</div><script>{JS}</script></body></html>")
    with open(path, "w", encoding="utf-8") as f:
        f.write("".join(parts))
