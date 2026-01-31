"""
Resurface Dashboard — LLM-Powered Vulnerability Regression Hunter
Dark-themed Streamlit dashboard for report visualization & analysis.
"""

import json
import glob
import os
import base64
from pathlib import Path
from collections import Counter

import streamlit as st
import plotly.express as px
import plotly.graph_objects as go

# ──────────────────────────────────────────────────────────────────────
# Config & Paths
# ──────────────────────────────────────────────────────────────────────
PROJECT_ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = PROJECT_ROOT / "data"
REPORTS_DIR = DATA_DIR / "reports"
PARSED_DIR = DATA_DIR / "parsed"
RESULTS_DIR = DATA_DIR / "results"

CYAN = "#00d4ff"
PURPLE = "#7b2ff7"
DARK_BG = "#0e1117"
CARD_BG = "#1a1d23"
TEXT_COLOR = "#e0e0e0"

# ──────────────────────────────────────────────────────────────────────
# Page config & global CSS
# ──────────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Resurface Dashboard",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    f"""
    <style>
    /* --- Global dark theme overrides --- */
    .stApp {{
        background-color: {DARK_BG};
        color: {TEXT_COLOR};
    }}
    [data-testid="stSidebar"] {{
        background-color: #12151a;
    }}
    [data-testid="stSidebar"] h1,
    [data-testid="stSidebar"] h2,
    [data-testid="stSidebar"] h3,
    [data-testid="stSidebar"] label {{
        color: {CYAN} !important;
    }}

    /* Metric cards */
    .metric-card {{
        background: {CARD_BG};
        border: 1px solid #2a2d35;
        border-radius: 12px;
        padding: 24px 20px;
        text-align: center;
        transition: border-color 0.2s;
    }}
    .metric-card:hover {{
        border-color: {CYAN};
    }}
    .metric-value {{
        font-size: 2.8rem;
        font-weight: 700;
        background: linear-gradient(135deg, {CYAN}, {PURPLE});
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
    }}
    .metric-label {{
        font-size: 0.85rem;
        color: #888;
        text-transform: uppercase;
        letter-spacing: 1.5px;
        margin-top: 6px;
    }}

    /* Section headers */
    .section-header {{
        font-size: 1.3rem;
        font-weight: 600;
        color: {CYAN};
        border-left: 4px solid {PURPLE};
        padding-left: 12px;
        margin: 32px 0 16px 0;
    }}

    /* Badge pills */
    .badge {{
        display: inline-block;
        padding: 3px 10px;
        border-radius: 999px;
        font-size: 0.75rem;
        font-weight: 600;
        text-transform: uppercase;
    }}
    .badge-critical {{ background: #ff1744; color: #fff; }}
    .badge-high     {{ background: #ff6d00; color: #fff; }}
    .badge-medium   {{ background: #ffd600; color: #000; }}
    .badge-low      {{ background: #00e676; color: #000; }}
    .badge-none     {{ background: #555;    color: #ccc; }}

    .badge-vulnerable {{ background: #ff1744; color: #fff; }}
    .badge-fixed      {{ background: #00e676; color: #000; }}
    .badge-partial    {{ background: #ffd600; color: #000; }}
    .badge-inconclusive {{ background: #555; color: #ccc; }}
    .badge-error      {{ background: #b71c1c; color: #fff; }}

    /* Deep-dive card */
    .detail-card {{
        background: {CARD_BG};
        border: 1px solid #2a2d35;
        border-radius: 10px;
        padding: 20px;
        margin-bottom: 16px;
    }}

    /* Override Streamlit dataframe header */
    .stDataFrame thead th {{
        background: #1e2028 !important;
        color: {CYAN} !important;
    }}
    </style>
    """,
    unsafe_allow_html=True,
)


# ──────────────────────────────────────────────────────────────────────
# Data loaders
# ──────────────────────────────────────────────────────────────────────
@st.cache_data(ttl=30)
def load_reports() -> list[dict]:
    """Load all scraped report JSON files."""
    reports = []
    for fp in sorted(REPORTS_DIR.glob("*.json")):
        try:
            with open(fp) as f:
                data = json.load(f)
            data["_file"] = fp.name
            reports.append(data)
        except Exception:
            pass
    return reports


@st.cache_data(ttl=30)
def load_parsed() -> list[dict]:
    """Load all *_parsed.json files."""
    parsed = []
    for fp in sorted(PARSED_DIR.glob("*_parsed.json")):
        try:
            with open(fp) as f:
                parsed.append(json.load(f))
        except Exception:
            pass
    return parsed


@st.cache_data(ttl=30)
def load_results() -> list[dict]:
    """Load all *_result.json files."""
    results = []
    for fp in sorted(RESULTS_DIR.glob("*_result.json")):
        try:
            with open(fp) as f:
                results.append(json.load(f))
        except Exception:
            pass
    return results


def get_screenshots() -> list[Path]:
    """Return all screenshot PNGs from results dir."""
    return sorted(RESULTS_DIR.glob("*.png"))


# ──────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────
def severity_badge(sev: str) -> str:
    s = (sev or "none").lower()
    cls = f"badge-{s}" if s in ("critical", "high", "medium", "low") else "badge-none"
    return f'<span class="badge {cls}">{sev or "N/A"}</span>'


def result_badge(res: str) -> str:
    r = (res or "unknown").lower()
    cls = f"badge-{r}" if r in ("vulnerable", "fixed", "partial", "inconclusive", "error") else "badge-none"
    return f'<span class="badge {cls}">{res or "N/A"}</span>'


def extract_field(report: dict, *keys, default="—"):
    """Drill into nested dicts safely."""
    for k in keys:
        if isinstance(report, dict):
            report = report.get(k)
        else:
            return default
    return report if report is not None else default


def metric_card(value, label):
    return f"""
    <div class="metric-card">
        <div class="metric-value">{value}</div>
        <div class="metric-label">{label}</div>
    </div>
    """


def plotly_dark_layout(fig, **kwargs):
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font_color=TEXT_COLOR,
        margin=dict(l=20, r=20, t=40, b=20),
        **kwargs,
    )
    return fig


# ──────────────────────────────────────────────────────────────────────
# Sidebar navigation
# ──────────────────────────────────────────────────────────────────────
st.sidebar.markdown(
    f"""
    <div style="text-align:center;padding:20px 0 10px 0;">
        <span style="font-size:2.4rem;">🔍</span><br>
        <span style="font-size:1.4rem;font-weight:700;
              background:linear-gradient(135deg,{CYAN},{PURPLE});
              -webkit-background-clip:text;-webkit-text-fill-color:transparent;">
        RESURFACE</span><br>
        <span style="font-size:0.7rem;color:#666;letter-spacing:2px;">
        VULNERABILITY REGRESSION HUNTER</span>
    </div>
    """,
    unsafe_allow_html=True,
)

page = st.sidebar.radio(
    "Navigate",
    ["📊 Overview", "📋 Reports", "🧩 Parsed", "🎯 Results", "🔬 Deep Dive"],
    label_visibility="collapsed",
)

# ──────────────────────────────────────────────────────────────────────
# Load data once
# ──────────────────────────────────────────────────────────────────────
reports = load_reports()
parsed = load_parsed()
results = load_results()
screenshots = get_screenshots()


# ══════════════════════════════════════════════════════════════════════
# PAGE: Overview
# ══════════════════════════════════════════════════════════════════════
if page == "📊 Overview":
    st.markdown(
        f'<h1 style="color:{CYAN};margin-bottom:4px;">Dashboard Overview</h1>'
        f'<p style="color:#666;font-size:0.9rem;">Real-time pipeline status</p>',
        unsafe_allow_html=True,
    )

    # --- Metric row ---
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.markdown(metric_card(len(reports), "Reports Scraped"), unsafe_allow_html=True)
    with c2:
        st.markdown(metric_card(len(parsed), "Parsed"), unsafe_allow_html=True)
    with c3:
        st.markdown(metric_card(len(results), "Replayed"), unsafe_allow_html=True)
    with c4:
        st.markdown(metric_card(len(screenshots), "Screenshots"), unsafe_allow_html=True)

    st.markdown("")  # spacer

    # --- Charts row ---
    left, right = st.columns(2)

    # Severity distribution
    with left:
        st.markdown('<div class="section-header">Severity Distribution</div>', unsafe_allow_html=True)
        sevs = [r.get("severity_rating", r.get("severity", {}).get("rating", "unknown")) or "unknown" for r in reports]
        sev_counts = Counter(sevs)
        order = ["critical", "high", "medium", "low", "none", "unknown"]
        colors_map = {
            "critical": "#ff1744",
            "high": "#ff6d00",
            "medium": "#ffd600",
            "low": "#00e676",
            "none": "#555",
            "unknown": "#888",
        }
        labels = [s for s in order if sev_counts.get(s, 0) > 0]
        values = [sev_counts[s] for s in labels]
        colors = [colors_map.get(s, "#888") for s in labels]

        if values:
            fig = go.Figure(
                go.Bar(
                    x=labels,
                    y=values,
                    marker_color=colors,
                    text=values,
                    textposition="outside",
                )
            )
            plotly_dark_layout(fig, title="", yaxis_title="Count", xaxis_title="")
            fig.update_layout(height=340)
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No severity data available yet.")

    # Vulnerability type distribution (from weakness field or parsed vuln_type)
    with right:
        st.markdown('<div class="section-header">Vulnerability Types</div>', unsafe_allow_html=True)
        vuln_types = []
        for r in reports:
            w = extract_field(r, "weakness", "name", default=None)
            if w:
                vuln_types.append(w)
            else:
                # Try to guess from title
                title = r.get("title", "")
                if "XSS" in title.upper():
                    vuln_types.append("XSS")
                elif "IDOR" in title.upper():
                    vuln_types.append("IDOR")
                elif "REDIRECT" in title.upper():
                    vuln_types.append("Open Redirect")
                elif "PATH" in title.upper() and "TRAVERSAL" in title.upper():
                    vuln_types.append("Path Traversal")
                elif "DISCLOSURE" in title.upper():
                    vuln_types.append("Info Disclosure")
                elif "ESCALAT" in title.upper():
                    vuln_types.append("Privilege Escalation")
                elif "SQL" in title.upper():
                    vuln_types.append("SQL Injection")
                elif "SSRF" in title.upper():
                    vuln_types.append("SSRF")
                else:
                    vuln_types.append("Other")

        if vuln_types:
            vt_counts = Counter(vuln_types)
            fig = go.Figure(
                go.Pie(
                    labels=list(vt_counts.keys()),
                    values=list(vt_counts.values()),
                    hole=0.45,
                    marker=dict(
                        colors=px.colors.sequential.Plasma_r[: len(vt_counts)],
                        line=dict(color=DARK_BG, width=2),
                    ),
                    textinfo="label+percent",
                    textfont=dict(size=11),
                )
            )
            plotly_dark_layout(fig, title="", showlegend=False, height=340)
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No vulnerability type data available yet.")

    # --- Pipeline funnel ---
    st.markdown('<div class="section-header">Pipeline Funnel</div>', unsafe_allow_html=True)
    funnel_data = {
        "Stage": ["Scraped", "Parsed", "Replayed"],
        "Count": [len(reports), len(parsed), len(results)],
    }
    fig = go.Figure(
        go.Funnel(
            y=funnel_data["Stage"],
            x=funnel_data["Count"],
            marker=dict(color=[CYAN, PURPLE, "#ff6d00"]),
            textinfo="value+percent initial",
        )
    )
    plotly_dark_layout(fig, title="", height=260)
    st.plotly_chart(fig, use_container_width=True)

    # --- Teams breakdown ---
    if reports:
        st.markdown('<div class="section-header">Reports by Team</div>', unsafe_allow_html=True)
        teams = []
        for r in reports:
            t = extract_field(r, "team", "handle", default=None) or extract_field(r, "team", "name", default="unknown")
            teams.append(t)
        team_counts = Counter(teams).most_common(15)
        if team_counts:
            fig = go.Figure(
                go.Bar(
                    x=[c for _, c in team_counts],
                    y=[t for t, _ in team_counts],
                    orientation="h",
                    marker_color=CYAN,
                    text=[c for _, c in team_counts],
                    textposition="outside",
                )
            )
            plotly_dark_layout(fig, title="", height=max(200, len(team_counts) * 32), yaxis=dict(autorange="reversed"))
            st.plotly_chart(fig, use_container_width=True)


# ══════════════════════════════════════════════════════════════════════
# PAGE: Reports Table
# ══════════════════════════════════════════════════════════════════════
elif page == "📋 Reports":
    st.markdown(
        f'<h1 style="color:{CYAN};">Scraped Reports</h1>',
        unsafe_allow_html=True,
    )

    if not reports:
        st.warning("No reports found in `data/reports/`. Run the scraper first.")
    else:
        # Filters
        fc1, fc2, fc3 = st.columns(3)
        all_sevs = sorted({r.get("severity_rating", "unknown") or "unknown" for r in reports})
        all_teams = sorted({
            extract_field(r, "team", "handle", default=None) or extract_field(r, "team", "name", default="unknown")
            for r in reports
        })
        with fc1:
            filt_sev = st.multiselect("Severity", all_sevs, default=all_sevs)
        with fc2:
            filt_team = st.multiselect("Team", all_teams, default=all_teams)
        with fc3:
            search_q = st.text_input("🔍 Search titles", "")

        # Build table rows
        rows = []
        for r in reports:
            rid = r.get("id", "—")
            title = r.get("title", "—")
            sev = r.get("severity_rating", "unknown") or "unknown"
            weakness = extract_field(r, "weakness", "name", default="—")
            team = extract_field(r, "team", "handle", default=None) or extract_field(r, "team", "name", default="—")
            state = r.get("substate", r.get("state", "—"))

            if sev not in filt_sev:
                continue
            if team not in filt_team:
                continue
            if search_q and search_q.lower() not in title.lower():
                continue

            rows.append({
                "ID": rid,
                "Title": title,
                "Severity": sev,
                "Weakness": weakness,
                "Team": team,
                "Status": state,
            })

        st.markdown(f"**{len(rows)}** reports matched", unsafe_allow_html=True)

        if rows:
            # Build HTML table for styled output
            header = "".join(f"<th style='padding:10px 14px;text-align:left;color:{CYAN};border-bottom:2px solid #2a2d35;'>{c}</th>" for c in rows[0].keys())
            body = ""
            for row in rows:
                cells = ""
                for k, v in row.items():
                    if k == "Severity":
                        cells += f"<td style='padding:8px 14px;'>{severity_badge(v)}</td>"
                    else:
                        cells += f"<td style='padding:8px 14px;color:{TEXT_COLOR};'>{v}</td>"
                body += f"<tr style='border-bottom:1px solid #1e2028;'>{cells}</tr>"

            st.markdown(
                f"""
                <div style="overflow-x:auto;">
                <table style="width:100%;border-collapse:collapse;background:{CARD_BG};border-radius:10px;overflow:hidden;">
                <thead><tr>{header}</tr></thead>
                <tbody>{body}</tbody>
                </table>
                </div>
                """,
                unsafe_allow_html=True,
            )


# ══════════════════════════════════════════════════════════════════════
# PAGE: Parsed View
# ══════════════════════════════════════════════════════════════════════
elif page == "🧩 Parsed":
    st.markdown(
        f'<h1 style="color:{CYAN};">Parsed Reports</h1>',
        unsafe_allow_html=True,
    )

    if not parsed:
        st.info(
            "No parsed reports yet. Run the LLM parser to generate `data/parsed/*_parsed.json` files.\n\n"
            "```bash\npython resurface.py parse --all\n```"
        )
    else:
        for p in parsed:
            rid = p.get("report_id", p.get("id", "?"))
            title = p.get("title", "Untitled")
            vuln_type = p.get("vuln_type", "unknown")
            confidence = p.get("confidence", 0)
            steps = p.get("steps", [])
            severity = p.get("severity", "—")
            replay_method = p.get("replay_method", "—")

            with st.expander(f"**#{rid}** — {title}", expanded=False):
                mc1, mc2, mc3, mc4 = st.columns(4)
                mc1.metric("Vuln Type", vuln_type)
                mc2.metric("Severity", severity)
                mc3.metric("Confidence", f"{confidence:.0%}" if isinstance(confidence, (int, float)) else confidence)
                mc4.metric("Replay Method", replay_method)

                if steps:
                    st.markdown(f'<div class="section-header">PoC Steps ({len(steps)})</div>', unsafe_allow_html=True)
                    for i, step in enumerate(steps, 1):
                        desc = step.get("description", "") if isinstance(step, dict) else str(step)
                        method = step.get("method", "") if isinstance(step, dict) else ""
                        url = step.get("url", "") if isinstance(step, dict) else ""
                        payload = step.get("payload", "") if isinstance(step, dict) else ""

                        st.markdown(
                            f"""
                            <div class="detail-card">
                                <strong style="color:{CYAN};">Step {i}</strong>
                                {'<code>' + method + '</code> ' if method else ''}
                                {'<code>' + url + '</code>' if url else ''}
                                <p style="margin:6px 0 0 0;color:#bbb;">{desc}</p>
                                {'<p style="color:#ff6d00;font-family:monospace;font-size:0.85rem;">Payload: ' + payload + '</p>' if payload else ''}
                            </div>
                            """,
                            unsafe_allow_html=True,
                        )
                else:
                    st.caption("No PoC steps extracted.")

                # Show raw JSON
                with st.expander("Raw parsed JSON"):
                    st.json(p)


# ══════════════════════════════════════════════════════════════════════
# PAGE: Results View
# ══════════════════════════════════════════════════════════════════════
elif page == "🎯 Results":
    st.markdown(
        f'<h1 style="color:{CYAN};">Replay Results</h1>',
        unsafe_allow_html=True,
    )

    if not results:
        st.info(
            "No replay results yet. Run the replay engine to generate `data/results/*_result.json` files.\n\n"
            "```bash\npython resurface.py replay --all\n```"
        )
    else:
        # Summary bar
        result_statuses = [r.get("result", "unknown") for r in results]
        rc = Counter(result_statuses)
        cols = st.columns(len(rc) if rc else 1)
        colors = {
            "vulnerable": "#ff1744",
            "fixed": "#00e676",
            "partial": "#ffd600",
            "inconclusive": "#888",
            "error": "#b71c1c",
        }
        for i, (status, count) in enumerate(rc.most_common()):
            with cols[i % len(cols)]:
                st.markdown(
                    f"""
                    <div class="metric-card" style="border-color:{colors.get(status, '#555')};">
                        <div class="metric-value" style="background:none;-webkit-text-fill-color:{colors.get(status, '#888')};">{count}</div>
                        <div class="metric-label">{status.upper()}</div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

        st.markdown("")

        for res in results:
            rid = res.get("report_id", res.get("id", "?"))
            status = res.get("result", "unknown")
            confidence = res.get("confidence", 0)
            analysis = res.get("llm_analysis", "")
            duration = res.get("duration_seconds", 0)
            target = res.get("target_url", "—")
            error = res.get("error_message", "")
            title = ""
            pr = res.get("parsed_report", {})
            if pr:
                title = pr.get("title", "")

            with st.expander(f"{result_badge(status)}  **#{rid}** {title or ''}", expanded=False):
                st.markdown(
                    f"""
                    <div class="detail-card">
                        <table style="width:100%;color:{TEXT_COLOR};">
                        <tr><td style="color:#888;width:140px;">Status</td><td>{result_badge(status)}</td></tr>
                        <tr><td style="color:#888;">Confidence</td><td>{confidence:.0%}</td></tr>
                        <tr><td style="color:#888;">Duration</td><td>{duration:.1f}s</td></tr>
                        <tr><td style="color:#888;">Target</td><td><code>{target}</code></td></tr>
                        {f'<tr><td style="color:#888;">Error</td><td style="color:#ff1744;">{error}</td></tr>' if error else ''}
                        </table>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

                if analysis:
                    st.markdown(f'<div class="section-header">LLM Analysis</div>', unsafe_allow_html=True)
                    st.markdown(analysis)

                # Evidence
                evidence = res.get("evidence", [])
                if evidence:
                    st.markdown(f'<div class="section-header">Evidence ({len(evidence)} steps)</div>', unsafe_allow_html=True)
                    for ev in evidence:
                        step_n = ev.get("step_number", "?")
                        st.markdown(f"**Step {step_n}** — {ev.get('notes', '')}")
                        if ev.get("request_sent"):
                            st.code(ev["request_sent"], language="http")
                        if ev.get("response_received"):
                            st.code(ev["response_received"][:2000], language="http")
                        sc = ev.get("screenshot_path")
                        if sc and Path(sc).exists():
                            st.image(str(sc), caption=f"Step {step_n} screenshot")

                # Raw JSON
                with st.expander("Raw result JSON"):
                    st.json(res)


# ══════════════════════════════════════════════════════════════════════
# PAGE: Deep Dive
# ══════════════════════════════════════════════════════════════════════
elif page == "🔬 Deep Dive":
    st.markdown(
        f'<h1 style="color:{CYAN};">Report Deep Dive</h1>',
        unsafe_allow_html=True,
    )

    if not reports:
        st.warning("No reports available.")
    else:
        # Report selector
        report_options = {f"#{r.get('id', '?')} — {r.get('title', 'Untitled')[:80]}": r for r in reports}
        selected_label = st.selectbox("Select a report", list(report_options.keys()))
        report = report_options[selected_label]

        rid = report.get("id", "?")
        title = report.get("title", "Untitled")
        sev = report.get("severity_rating", "unknown") or "unknown"
        state = report.get("substate", report.get("state", "—"))
        team = extract_field(report, "team", "handle", default=None) or extract_field(report, "team", "name", default="—")
        weakness = extract_field(report, "weakness", "name", default="—")
        reporter = extract_field(report, "reporter", "username", default="—")
        disclosed = report.get("disclosed_at", "—")
        bounty = report.get("bounty_amount", None)
        url = report.get("url", "")
        vuln_info = report.get("vulnerability_information", "")

        # --- Header ---
        st.markdown(
            f"""
            <div class="detail-card" style="border-color:{PURPLE};">
                <h2 style="color:{CYAN};margin-top:0;">#{rid} — {title}</h2>
                <div style="display:flex;gap:24px;flex-wrap:wrap;margin-top:12px;">
                    <div><span style="color:#888;">Severity:</span> {severity_badge(sev)}</div>
                    <div><span style="color:#888;">Status:</span> <code>{state}</code></div>
                    <div><span style="color:#888;">Team:</span> <code>{team}</code></div>
                    <div><span style="color:#888;">Weakness:</span> <code>{weakness}</code></div>
                    <div><span style="color:#888;">Reporter:</span> <code>{reporter}</code></div>
                    <div><span style="color:#888;">Disclosed:</span> <code>{disclosed}</code></div>
                    {f'<div><span style="color:#888;">Bounty:</span> <code style="color:#00e676;">${bounty}</code></div>' if bounty else ''}
                    {f'<div><a href="{url}" target="_blank" style="color:{CYAN};">HackerOne Link ↗</a></div>' if url else ''}
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        # --- Tabs for content ---
        tab_report, tab_parsed, tab_result, tab_screenshots = st.tabs(
            ["📝 Original Report", "🧩 Parsed", "🎯 Replay Result", "📸 Screenshots"]
        )

        # TAB: Original report text
        with tab_report:
            if vuln_info:
                st.markdown(vuln_info)
            else:
                st.info("No vulnerability information text available for this report.")

        # TAB: Parsed data
        with tab_parsed:
            # Find matching parsed report
            matched_parsed = None
            for p in parsed:
                if p.get("report_id") == rid or p.get("id") == rid:
                    matched_parsed = p
                    break

            if matched_parsed:
                vuln_type = matched_parsed.get("vuln_type", "—")
                confidence = matched_parsed.get("confidence", 0)
                steps = matched_parsed.get("steps", [])

                mc1, mc2 = st.columns(2)
                mc1.metric("Vuln Type", vuln_type)
                mc2.metric("Confidence", f"{confidence:.0%}" if isinstance(confidence, (int, float)) else confidence)

                if steps:
                    st.markdown(f'<div class="section-header">PoC Steps</div>', unsafe_allow_html=True)
                    for i, step in enumerate(steps, 1):
                        desc = step.get("description", "") if isinstance(step, dict) else str(step)
                        method = step.get("method", "") if isinstance(step, dict) else ""
                        url_s = step.get("url", "") if isinstance(step, dict) else ""
                        payload = step.get("payload", "") if isinstance(step, dict) else ""
                        st.markdown(
                            f"""
                            <div class="detail-card">
                                <strong style="color:{CYAN};">Step {i}</strong>
                                {'<code>' + method + '</code> ' if method else ''}
                                {'<code>' + url_s + '</code>' if url_s else ''}
                                <p style="margin:6px 0 0 0;color:#bbb;">{desc}</p>
                                {'<p style="color:#ff6d00;font-family:monospace;font-size:0.85rem;">Payload: ' + payload + '</p>' if payload else ''}
                            </div>
                            """,
                            unsafe_allow_html=True,
                        )

                with st.expander("Raw parsed JSON"):
                    st.json(matched_parsed)
            else:
                st.info(f"No parsed data found for report #{rid}. Run: `python resurface.py parse --id {rid}`")

        # TAB: Replay result
        with tab_result:
            matched_result = None
            for res in results:
                if res.get("report_id") == rid or res.get("id") == rid:
                    matched_result = res
                    break

            if matched_result:
                status = matched_result.get("result", "unknown")
                confidence = matched_result.get("confidence", 0)
                analysis = matched_result.get("llm_analysis", "")
                duration = matched_result.get("duration_seconds", 0)
                target = matched_result.get("target_url", "—")
                error = matched_result.get("error_message", "")

                st.markdown(
                    f"""
                    <div class="detail-card">
                        <table style="width:100%;color:{TEXT_COLOR};">
                        <tr><td style="color:#888;width:140px;">Result</td><td>{result_badge(status)}</td></tr>
                        <tr><td style="color:#888;">Confidence</td><td>{confidence:.0%}</td></tr>
                        <tr><td style="color:#888;">Duration</td><td>{duration:.1f}s</td></tr>
                        <tr><td style="color:#888;">Target</td><td><code>{target}</code></td></tr>
                        {f'<tr><td style="color:#888;">Error</td><td style="color:#ff1744;">{error}</td></tr>' if error else ''}
                        </table>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

                if analysis:
                    st.markdown(f'<div class="section-header">LLM Analysis</div>', unsafe_allow_html=True)
                    st.markdown(analysis)

                evidence = matched_result.get("evidence", [])
                if evidence:
                    st.markdown(f'<div class="section-header">Evidence</div>', unsafe_allow_html=True)
                    for ev in evidence:
                        step_n = ev.get("step_number", "?")
                        st.markdown(f"**Step {step_n}** — {ev.get('notes', '')}")
                        if ev.get("request_sent"):
                            st.code(ev["request_sent"], language="http")
                        if ev.get("response_received"):
                            st.code(ev["response_received"][:2000], language="http")

                with st.expander("Raw result JSON"):
                    st.json(matched_result)
            else:
                st.info(f"No replay result found for report #{rid}. Run: `python resurface.py replay --id {rid}`")

        # TAB: Screenshots
        with tab_screenshots:
            # Match screenshots by report ID in filename
            matched_shots = [s for s in screenshots if str(rid) in s.stem]
            # Also show all screenshots if nothing matches specifically
            if matched_shots:
                for shot in matched_shots:
                    st.image(str(shot), caption=shot.name, use_container_width=True)
            elif screenshots:
                st.info(f"No screenshots matched report #{rid}. Showing all available screenshots:")
                for shot in screenshots:
                    st.image(str(shot), caption=shot.name, use_container_width=True)
            else:
                st.info("No screenshots available in `data/results/`.")


# ──────────────────────────────────────────────────────────────────────
# Footer
# ──────────────────────────────────────────────────────────────────────
st.sidebar.markdown("---")
st.sidebar.markdown(
    f"""
    <div style="text-align:center;color:#555;font-size:0.7rem;padding:10px 0;">
        Resurface v1.0<br>
        {len(reports)} reports · {len(parsed)} parsed · {len(results)} replayed
    </div>
    """,
    unsafe_allow_html=True,
)
