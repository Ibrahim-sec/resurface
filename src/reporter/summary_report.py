"""
Resurface — Summary HTML Report Generator

Generates a single-page dark-themed dashboard showing ALL replay results
with filtering, charts (pure CSS/JS, no external deps), and color-coded status.
"""
import json
from pathlib import Path
from datetime import datetime

try:
    from loguru import logger
except ImportError:
    import logging as logger


def _esc(text: str) -> str:
    """Minimal HTML escaping."""
    if not text:
        return ""
    return (str(text)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;"))


def generate_summary_report(results: list[dict], stats: dict,
                            output_path: str = "data/results/summary.html") -> str:
    """
    Build a self-contained HTML summary page.

    Args:
        results:  list of dicts from database.get_all_results()
        stats:    dict from database.get_stats()
        output_path: where to write the HTML file

    Returns:
        The output file path.
    """

    # ── Stat cards ──────────────────────────────────
    total = stats.get("total_reports", 0)
    parsed = stats.get("parsed_count", 0)
    replays = stats.get("total_replays", 0)
    rb = stats.get("result_breakdown", {})
    vuln_count   = rb.get("vulnerable", 0)
    fixed_count  = rb.get("fixed", 0)
    partial_count = rb.get("partial", 0)
    inconclusive = rb.get("inconclusive", 0)
    error_count  = rb.get("error", 0)
    avg_dur = stats.get("avg_duration_seconds", 0)

    # ── Build table rows ────────────────────────────
    table_rows = ""
    for r in results:
        status = r.get("result", "error")
        report_id = r.get("report_id", "?")
        title = _esc(r.get("title", "Unknown"))[:80]
        severity = _esc(r.get("severity", ""))
        vuln_type = _esc(r.get("vuln_type", ""))
        team = _esc(r.get("team", ""))
        target = _esc(r.get("target_url", ""))[:60]
        confidence = r.get("confidence", 0)
        conf_pct = f"{confidence * 100:.0f}%" if isinstance(confidence, float) else str(confidence)
        duration = f"{r.get('duration_seconds', 0):.1f}s"
        replayed = r.get("replayed_at", "")[:19]

        table_rows += f"""
        <tr data-status="{status}" data-severity="{severity.lower()}" data-vuln="{vuln_type}">
            <td>{report_id}</td>
            <td class="title-cell" title="{title}">{title}</td>
            <td><span class="badge sev-{severity.lower()}">{severity}</span></td>
            <td><span class="badge status-{status}">{status}</span></td>
            <td>{vuln_type}</td>
            <td>{team}</td>
            <td class="mono">{target}</td>
            <td>{conf_pct}</td>
            <td>{duration}</td>
            <td class="mono">{replayed}</td>
        </tr>"""

    # ── Vuln type chart data ────────────────────────
    vtd = stats.get("vuln_type_distribution", {})
    vtype_bars = ""
    max_vt = max(vtd.values()) if vtd else 1
    for vt, cnt in sorted(vtd.items(), key=lambda x: -x[1]):
        pct = cnt / max_vt * 100
        vtype_bars += f"""
        <div class="bar-row">
            <span class="bar-label">{_esc(vt)}</span>
            <div class="bar-track"><div class="bar-fill" style="width:{pct:.0f}%"></div></div>
            <span class="bar-count">{cnt}</span>
        </div>"""

    # ── Severity chart data ─────────────────────────
    sd = stats.get("severity_distribution", {})
    sev_bars = ""
    max_sv = max(sd.values()) if sd else 1
    for sv, cnt in sorted(sd.items(), key=lambda x: -x[1]):
        pct = cnt / max_sv * 100
        sev_bars += f"""
        <div class="bar-row">
            <span class="bar-label sev-{sv.lower()}">{_esc(sv)}</span>
            <div class="bar-track"><div class="bar-fill sev-fill-{sv.lower()}" style="width:{pct:.0f}%"></div></div>
            <span class="bar-count">{cnt}</span>
        </div>"""

    # ── Top teams ───────────────────────────────────
    tt = stats.get("top_teams", {})
    team_bars = ""
    max_tt = max(tt.values()) if tt else 1
    for t, cnt in list(sorted(tt.items(), key=lambda x: -x[1]))[:10]:
        pct = cnt / max_tt * 100
        team_bars += f"""
        <div class="bar-row">
            <span class="bar-label">{_esc(t)}</span>
            <div class="bar-track"><div class="bar-fill team-fill" style="width:{pct:.0f}%"></div></div>
            <span class="bar-count">{cnt}</span>
        </div>"""

    # ── Collect unique values for filter dropdowns ──
    all_statuses = sorted(set(r.get("result", "") for r in results))
    all_severities = sorted(set(r.get("severity", "") for r in results if r.get("severity")))
    all_vulns = sorted(set(r.get("vuln_type", "") for r in results if r.get("vuln_type")))

    status_opts = "".join(f'<option value="{s}">{s}</option>' for s in all_statuses)
    sev_opts = "".join(f'<option value="{s.lower()}">{s}</option>' for s in all_severities)
    vuln_opts = "".join(f'<option value="{v}">{v}</option>' for v in all_vulns)

    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Resurface — Summary Report</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:'Segoe UI',system-ui,-apple-system,sans-serif;background:#0a0a0f;color:#e0e0e0;line-height:1.6}}
.container{{max-width:1400px;margin:0 auto;padding:1.5rem}}
header{{text-align:center;padding:1.5rem 0;border-bottom:1px solid #1a1a2e;margin-bottom:1.5rem}}
header h1{{font-size:2rem;background:linear-gradient(135deg,#00d4ff,#7b2ff7);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}}
header .subtitle{{color:#888;margin-top:.3rem;font-size:.95rem}}

/* Stat cards */
.stats-grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:1rem;margin-bottom:1.5rem}}
.stat-card{{background:#12121a;border:1px solid #1a1a2e;border-radius:10px;padding:1rem;text-align:center}}
.stat-card .num{{font-size:1.8rem;font-weight:700}}
.stat-card .lbl{{font-size:.75rem;text-transform:uppercase;color:#888;margin-top:.2rem}}
.num-vuln{{color:#ff4444}} .num-fixed{{color:#44ff44}} .num-partial{{color:#ffcc00}}
.num-incon{{color:#888}} .num-error{{color:#ff0000}} .num-total{{color:#00d4ff}}

/* Charts area */
.charts{{display:grid;grid-template-columns:1fr 1fr 1fr;gap:1rem;margin-bottom:1.5rem}}
@media(max-width:900px){{.charts{{grid-template-columns:1fr}}}}
.chart-card{{background:#12121a;border:1px solid #1a1a2e;border-radius:10px;padding:1rem}}
.chart-card h3{{color:#00d4ff;font-size:.95rem;margin-bottom:.8rem}}
.bar-row{{display:flex;align-items:center;margin:.35rem 0;font-size:.8rem}}
.bar-label{{width:130px;flex-shrink:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}}
.bar-track{{flex:1;height:14px;background:#1a1a2e;border-radius:7px;margin:0 .5rem;overflow:hidden}}
.bar-fill{{height:100%;border-radius:7px;background:linear-gradient(90deg,#7b2ff7,#00d4ff);transition:width .3s}}
.bar-count{{width:32px;text-align:right;color:#888}}

/* Severity fill colors */
.sev-fill-critical{{background:linear-gradient(90deg,#ff0000,#cc0000)}}
.sev-fill-high{{background:linear-gradient(90deg,#ff4444,#cc3333)}}
.sev-fill-medium{{background:linear-gradient(90deg,#ffaa00,#cc8800)}}
.sev-fill-low{{background:linear-gradient(90deg,#44ff44,#33cc33)}}
.sev-fill-none,.sev-fill-{{background:#555}}
.team-fill{{background:linear-gradient(90deg,#00d4ff,#0088cc)}}

/* Donut chart */
.donut-wrap{{display:flex;align-items:center;justify-content:center;gap:1.5rem;flex-wrap:wrap}}
.donut{{width:120px;height:120px;border-radius:50%;position:relative}}
.donut-hole{{width:70px;height:70px;background:#12121a;border-radius:50%;position:absolute;top:25px;left:25px;display:flex;align-items:center;justify-content:center;font-weight:700;font-size:1.1rem}}
.donut-legend{{font-size:.8rem}}
.donut-legend div{{margin:.25rem 0;display:flex;align-items:center;gap:.4rem}}
.donut-legend .dot{{width:10px;height:10px;border-radius:50%;display:inline-block}}

/* Filters */
.filters{{display:flex;gap:.8rem;margin-bottom:1rem;flex-wrap:wrap;align-items:center}}
.filters label{{font-size:.8rem;color:#888;text-transform:uppercase}}
.filters select,.filters input{{background:#12121a;border:1px solid #1a1a2e;color:#e0e0e0;padding:.4rem .6rem;border-radius:6px;font-size:.85rem}}
.filters select:focus,.filters input:focus{{outline:none;border-color:#7b2ff7}}

/* Table */
.table-wrap{{overflow-x:auto;border:1px solid #1a1a2e;border-radius:10px;background:#12121a}}
table{{width:100%;border-collapse:collapse;font-size:.85rem}}
th{{background:#0d0d14;padding:.6rem .5rem;text-align:left;color:#888;font-size:.75rem;text-transform:uppercase;position:sticky;top:0}}
td{{padding:.5rem;border-top:1px solid #1a1a2e;white-space:nowrap}}
tr:hover{{background:#1a1a2e}}
.title-cell{{max-width:250px;overflow:hidden;text-overflow:ellipsis}}
.mono{{font-family:'Fira Code',monospace;font-size:.8rem}}

/* Badges */
.badge{{display:inline-block;padding:.15rem .5rem;border-radius:4px;font-size:.75rem;font-weight:600}}
.status-vulnerable{{background:#2d0000;color:#ff4444;border:1px solid #ff4444}}
.status-fixed{{background:#002d00;color:#44ff44;border:1px solid #44ff44}}
.status-partial{{background:#2d2d00;color:#ffcc00;border:1px solid #ffcc00}}
.status-inconclusive{{background:#1a1a2e;color:#888;border:1px solid #555}}
.status-error{{background:#2d0000;color:#ff0000;border:1px solid #ff0000}}
.sev-critical{{color:#ff0000}} .sev-high{{color:#ff4444}} .sev-medium{{color:#ffaa00}} .sev-low{{color:#44ff44}} .sev-none,.sev-{{color:#888}}

footer{{text-align:center;padding:1.5rem 0;color:#555;border-top:1px solid #1a1a2e;margin-top:2rem;font-size:.85rem}}
footer em{{color:#7b2ff7}}

.hidden{{display:none!important}}
</style>
</head>
<body>
<div class="container">

<header>
    <h1>🔄 Resurface — Summary Report</h1>
    <p class="subtitle">LLM-Powered Vulnerability Regression Analysis &middot; Generated {generated_at}</p>
</header>

<!-- ── Stat Cards ──────────────────── -->
<div class="stats-grid">
    <div class="stat-card"><div class="num num-total">{total}</div><div class="lbl">Reports Scraped</div></div>
    <div class="stat-card"><div class="num num-total">{parsed}</div><div class="lbl">Parsed</div></div>
    <div class="stat-card"><div class="num num-total">{replays}</div><div class="lbl">Replays Run</div></div>
    <div class="stat-card"><div class="num num-vuln">{vuln_count}</div><div class="lbl">Vulnerable</div></div>
    <div class="stat-card"><div class="num num-fixed">{fixed_count}</div><div class="lbl">Fixed</div></div>
    <div class="stat-card"><div class="num num-partial">{partial_count}</div><div class="lbl">Partial</div></div>
    <div class="stat-card"><div class="num num-incon">{inconclusive}</div><div class="lbl">Inconclusive</div></div>
    <div class="stat-card"><div class="num num-error">{error_count}</div><div class="lbl">Errors</div></div>
</div>

<!-- ── Charts ──────────────────────── -->
<div class="charts">
    <div class="chart-card">
        <h3>📊 Result Distribution</h3>
        <div class="donut-wrap">
            <div class="donut" id="resultDonut"></div>
            <div class="donut-legend">
                <div><span class="dot" style="background:#ff4444"></span> Vulnerable ({vuln_count})</div>
                <div><span class="dot" style="background:#44ff44"></span> Fixed ({fixed_count})</div>
                <div><span class="dot" style="background:#ffcc00"></span> Partial ({partial_count})</div>
                <div><span class="dot" style="background:#888"></span> Inconclusive ({inconclusive})</div>
                <div><span class="dot" style="background:#ff0000"></span> Error ({error_count})</div>
            </div>
        </div>
    </div>
    <div class="chart-card">
        <h3>🐛 Vulnerability Types</h3>
        {vtype_bars if vtype_bars else '<p style="color:#555">No data yet</p>'}
    </div>
    <div class="chart-card">
        <h3>🏢 Top Programs</h3>
        {team_bars if team_bars else '<p style="color:#555">No data yet</p>'}
    </div>
</div>

<div class="charts" style="grid-template-columns:1fr">
    <div class="chart-card">
        <h3>⚡ Severity Distribution</h3>
        {sev_bars if sev_bars else '<p style="color:#555">No data yet</p>'}
    </div>
</div>

<!-- ── Filters ─────────────────────── -->
<div class="filters">
    <label>Status:</label>
    <select id="filterStatus"><option value="">All</option>{status_opts}</select>
    <label>Severity:</label>
    <select id="filterSev"><option value="">All</option>{sev_opts}</select>
    <label>Vuln Type:</label>
    <select id="filterVuln"><option value="">All</option>{vuln_opts}</select>
    <label>Search:</label>
    <input id="filterSearch" placeholder="title / team / target…" style="width:180px">
</div>

<!-- ── Results Table ───────────────── -->
<div class="table-wrap">
<table>
<thead>
<tr>
    <th>ID</th><th>Title</th><th>Severity</th><th>Status</th><th>Vuln Type</th>
    <th>Program</th><th>Target</th><th>Conf.</th><th>Duration</th><th>Replayed</th>
</tr>
</thead>
<tbody id="resultsBody">
{table_rows}
</tbody>
</table>
</div>

<footer>
    <p>Resurface v0.1.0 &middot; <em>Bugs don't die. They resurface.</em></p>
    <p>Avg replay duration: {avg_dur:.1f}s &middot; {replays} total replays</p>
</footer>

</div>

<script>
// ── Donut chart (pure CSS conic-gradient) ──
(function(){{
    const vals = [{vuln_count},{fixed_count},{partial_count},{inconclusive},{error_count}];
    const cols = ['#ff4444','#44ff44','#ffcc00','#888','#ff0000'];
    const total = vals.reduce((a,b)=>a+b,0) || 1;
    let grad = [], acc = 0;
    vals.forEach((v,i)=>{{
        const start = acc/total*360;
        acc += v;
        const end = acc/total*360;
        grad.push(cols[i]+' '+start+'deg '+end+'deg');
    }});
    const el = document.getElementById('resultDonut');
    if(el){{
        el.style.background = 'conic-gradient('+grad.join(',')+')';
        el.innerHTML = '<div class="donut-hole">'+total+'</div>';
    }}
}})();

// ── Table filtering ──
(function(){{
    const body = document.getElementById('resultsBody');
    const rows = body ? Array.from(body.querySelectorAll('tr')) : [];
    const fStatus = document.getElementById('filterStatus');
    const fSev = document.getElementById('filterSev');
    const fVuln = document.getElementById('filterVuln');
    const fSearch = document.getElementById('filterSearch');

    function applyFilters(){{
        const s = fStatus.value, sv = fSev.value, vt = fVuln.value;
        const q = fSearch.value.toLowerCase();
        rows.forEach(r=>{{
            let show = true;
            if(s && r.dataset.status !== s) show = false;
            if(sv && r.dataset.severity !== sv) show = false;
            if(vt && r.dataset.vuln !== vt) show = false;
            if(q && !r.textContent.toLowerCase().includes(q)) show = false;
            r.classList.toggle('hidden', !show);
        }});
    }}

    [fStatus, fSev, fVuln, fSearch].forEach(el=>{{
        if(el) el.addEventListener('input', applyFilters);
    }});
}})();
</script>
</body>
</html>"""

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        f.write(html)

    logger.info(f"Summary report saved to {output_path}")
    return output_path
