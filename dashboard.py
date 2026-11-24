"""Mini-SIEM dashboard.   Run from the project folder:   streamlit run dashboard.py"""
from __future__ import annotations

import os
import re
import tempfile
from datetime import datetime, timezone

import altair as alt
import pandas as pd
import streamlit as st

from siem import sample_data
from siem.engine import detect, ingest_file, load_blocklist
from siem.models import SEVERITIES
from siem.rules import CORRELATION_RULES, all_rules
from siem.storage import Storage

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_DB = os.environ.get("SIEM_DB", "siem.db")
SAMPLE_DIR = os.path.join(BASE_DIR, "data", "sample")

st.set_page_config(page_title="Mini SIEM", page_icon="🛡️", layout="wide")

# ------------------------------------------------------------------ palette --
# Colors follow the dataviz method and were run through its validator in both modes:
#   * log sources   -> categorical slots 1-3 (validated under the strict all-pairs check)
#   * severity      -> one-hue ordinal ramp (validated with --ordinal); it is also always
#                      spelled out in text, so color is never the only carrier of meaning.
# In dark mode the ramp runs the other way so "critical" is the brightest step.
LIGHT = dict(
    surface="#fcfcfb", text="#0b0b0b", text2="#52514e", grid="#e1e0d9", axis="#c3c2b7",
    cat=["#2a78d6", "#eb6834", "#1baf7a"],
    sev=["#86b6ef", "#5598e7", "#256abf", "#184f95"],  # low -> critical
)
DARK = dict(
    surface="#1a1a19", text="#f0efec", text2="#c3c2b7", grid="#2c2c2a", axis="#383835",
    cat=["#3987e5", "#d95926", "#199e70"],
    sev=["#184f95", "#256abf", "#5598e7", "#86b6ef"],  # low -> critical
)
SOURCE_LABELS = {"auth": "Auth log", "web": "Web access", "app": "Application"}
SEV_DESC = list(reversed(SEVERITIES))  # critical first, for display
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}


def headroom(max_value: float) -> alt.Scale:
    """x-scale with room on the right so the direct value labels are never clipped."""
    return alt.Scale(domain=[0, max(2.0, float(max_value) * 1.18 + 0.4)], nice=False)


def palette() -> dict:
    try:
        return DARK if st.context.theme.type == "dark" else LIGHT
    except Exception:
        return LIGHT


def style(chart, P: dict, height: int):
    return (
        chart.properties(height=height)
        .configure(background="transparent")
        .configure_view(stroke=None)
        .configure_axis(
            labelColor=P["text2"], titleColor=P["text2"], gridColor=P["grid"], domainColor=P["axis"],
            tickColor=P["axis"], labelFontSize=12, titleFontSize=12, titleFontWeight="normal", labelLimit=320,
        )
        .configure_legend(labelColor=P["text2"], titleColor=P["text2"], labelFontSize=12,
                          symbolType="square", orient="top")
    )


# ------------------------------------------------------------------ storage --
@st.cache_resource
def get_store(path: str) -> Storage:
    return Storage(path)


def _blocklist() -> list[str]:
    text = st.session_state.get("blocklist_text", "")
    return [ln.strip() for ln in text.splitlines() if ln.strip() and not ln.startswith("#")]


# Callbacks run before the page re-renders, so they may safely edit widget state.
def _cb_demo() -> None:
    store = get_store(st.session_state["db_path"])
    store.reset()
    files = sample_data.generate(SAMPLE_DIR)
    for src, path in (("auth", files.auth), ("web", files.web), ("app", files.app)):
        ingest_file(store, path, src, year=files.year)
    st.session_state["blocklist_text"] = "\n".join(load_blocklist(files.blocklist))
    found, _ = detect(store, {"blocklist": _blocklist()})
    st.session_state["flash"] = f"Demo data loaded - detection raised {found} alerts."


def _cb_detect() -> None:
    found, new = detect(get_store(st.session_state["db_path"]), {"blocklist": _blocklist()})
    st.session_state["flash"] = f"Detection finished: {found} alerts ({new} new)."


def _cb_reset() -> None:
    get_store(st.session_state["db_path"]).reset()
    st.session_state["flash"] = "Database cleared."


def _cb_ingest() -> None:
    up = st.session_state.get("upload")
    if up is None:
        st.session_state["flash"] = "Choose a log file first."
        return
    store = get_store(st.session_state["db_path"])
    with tempfile.NamedTemporaryFile(delete=False, suffix=".log") as tmp:
        tmp.write(up.getvalue())
    try:
        src = st.session_state["upload_src"]
        res = ingest_file(store, tmp.name, src, year=int(st.session_state["auth_year"]))
    finally:
        os.unlink(tmp.name)
    found, _ = detect(store, {"blocklist": _blocklist()})
    st.session_state["flash"] = (
        f"{up.name}: {res.parsed} events parsed, {res.skipped} lines skipped, {res.new} new. "
        f"Detection now reports {found} alerts."
    )


# ------------------------------------------------------------------ sidebar --
with st.sidebar:
    st.title("🛡️ Mini SIEM")
    st.text_input("Database file", value=DEFAULT_DB, key="db_path")
    store = get_store(st.session_state["db_path"])
    counts = store.counts()
    st.caption(f"{counts['events']:,} events · {counts['alerts']:,} alerts stored")

    st.subheader("Data")
    has_data = counts["events"] > 0
    ok = st.checkbox("Allow replacing existing data", key="allow_replace") if has_data else True
    st.button("Load demo data", on_click=_cb_demo, disabled=not ok, type="primary",
              help="Generates a day of synthetic logs with injected attacks (replaces what is stored).")

    with st.expander("Ingest your own log file"):
        st.selectbox("Log type", ["auth", "web", "app"], key="upload_src",
                     format_func=lambda s: {"auth": "auth.log (sshd / sudo)",
                                            "web": "Web access log (combined)",
                                            "app": "App log (JSON lines)"}[s])
        st.number_input("Year (auth logs only)", 2000, 2100, datetime.now(timezone.utc).year, key="auth_year",
                        help="Syslog timestamps do not contain a year.")
        st.file_uploader("Log file", key="upload")
        st.button("Ingest and run detection", on_click=_cb_ingest)

    st.subheader("Detection")
    st.text_area("Known-bad IPs (one per line)", key="blocklist_text", height=90,
                 help="Feeds rule TI-001. Lines starting with # are ignored.")
    st.button("Re-run detection", on_click=_cb_detect)
    st.button("Clear database", on_click=_cb_reset, disabled=not ok)

if msg := st.session_state.pop("flash", None):
    st.toast(msg)

# --------------------------------------------------------------------- data --
EVENT_COLS = ["timestamp", "source", "event_type", "src_ip", "username", "message"]
ALERT_COLS = ["id", "rule_id", "title", "severity", "timestamp", "src_ip", "username",
              "description", "mitre", "event_count", "evidence"]

events = pd.DataFrame(
    store.query("SELECT timestamp, source, event_type, src_ip, username, message FROM events ORDER BY timestamp"),
    columns=EVENT_COLS,
)
events["timestamp"] = pd.to_datetime(events["timestamp"])
alerts = pd.DataFrame(store.fetch_alerts(), columns=ALERT_COLS)
alerts["timestamp"] = pd.to_datetime(alerts["timestamp"])

st.title("Security operations overview")
st.caption("Logs from three sources are normalized, checked by detection rules, and surfaced as alerts. All times UTC.")

if events.empty:
    st.info("The database is empty. Click **Load demo data** in the sidebar, or ingest your own log file.")
    st.stop()

# ------------------------------------------------------------------ filters --
f1, f2 = st.columns([2, 1])
sev_sel = f1.multiselect("Severity", SEV_DESC, default=SEV_DESC)
query = f2.text_input("Search alerts", placeholder="IP, user, rule or title")

f_alerts = alerts[alerts["severity"].isin(sev_sel)]
if query:
    hay = (f_alerts[["src_ip", "username", "rule_id", "title"]].fillna("").astype(str).agg(" ".join, axis=1))
    f_alerts = f_alerts[hay.str.contains(query, case=False, regex=False)]

# --------------------------------------------------------------------- KPIs --
k = st.columns(5)
k[0].metric("Events ingested", f"{len(events):,}")
k[1].metric("Alerts", f"{len(f_alerts):,}")
k[2].metric("Critical + high", f"{f_alerts['severity'].isin(['critical', 'high']).sum():,}")
k[3].metric("Source IPs flagged", f"{f_alerts['src_ip'].nunique():,}")
k[4].metric("Rules triggered", f"{f_alerts['rule_id'].nunique()} of {len(all_rules())}")

P = palette()
RULE_LABEL = {r.id: f"{r.id} · {r.title}" for r in all_rules()}
tab_over, tab_alerts, tab_events, tab_rules = st.tabs(["Overview", "Alerts & investigation", "Events", "Detection rules"])

# ----------------------------------------------------------------- overview --
with tab_over:
    st.subheader("Alert timeline")
    st.caption("Each circle is an alert. Larger circles involve more log events.")
    if f_alerts.empty:
        st.info("No alerts match the current filters.")
    else:
        tl = f_alerts.assign(rule=f_alerts["rule_id"].map(RULE_LABEL)).fillna({"src_ip": "-", "username": "-"})
        # most severe detections first, so the top of the chart is what to look at first
        rule_order = (tl.assign(_r=tl["severity"].map(SEV_RANK)).groupby("rule")["_r"].max().reset_index()
                      .sort_values(["_r", "rule"], ascending=[False, True])["rule"].tolist())
        timeline = (
            alt.Chart(tl)
            .mark_circle(opacity=0.95, stroke=P["surface"], strokeWidth=2)
            .encode(
                x=alt.X("timestamp:T", title="Time (UTC)", scale=alt.Scale(padding=30)),
                y=alt.Y("rule:N", title=None, sort=rule_order),
                size=alt.Size("event_count:Q", scale=alt.Scale(range=[110, 800]), legend=None),
                color=alt.Color("severity:N", scale=alt.Scale(domain=SEVERITIES, range=P["sev"]),
                                legend=alt.Legend(title="Severity")),
                tooltip=[alt.Tooltip("timestamp:T", title="Time", format="%H:%M:%S"),
                         alt.Tooltip("severity:N", title="Severity"), alt.Tooltip("title:N", title="Rule"),
                         alt.Tooltip("src_ip:N", title="Source IP"), alt.Tooltip("username:N", title="User"),
                         alt.Tooltip("event_count:Q", title="Events")],
            )
        )
        st.altair_chart(style(timeline, P, max(180, 30 * tl["rule"].nunique() + 70)), theme=None, width="stretch")

    c1, c2 = st.columns([3, 2])
    with c1:
        st.subheader("Event volume by source")
        vol = events.assign(bucket=events["timestamp"].dt.floor("30min"),
                            source_label=events["source"].map(SOURCE_LABELS))
        vol = vol.groupby(["bucket", "source_label"]).size().reset_index(name="events")
        volume = (
            alt.Chart(vol)
            .mark_bar(size=11, stroke=P["surface"], strokeWidth=2)
            .encode(
                x=alt.X("bucket:T", title="Time (UTC, 30-minute buckets)"),
                y=alt.Y("events:Q", title="Events"),
                color=alt.Color("source_label:N", scale=alt.Scale(domain=list(SOURCE_LABELS.values()), range=P["cat"]),
                                legend=alt.Legend(title=None)),
                tooltip=[alt.Tooltip("bucket:T", title="Bucket start", format="%H:%M"),
                         alt.Tooltip("source_label:N", title="Source"), alt.Tooltip("events:Q", title="Events")],
            )
        )
        st.altair_chart(style(volume, P, 300), theme=None, width="stretch")
        with st.expander("Table view"):
            st.dataframe(vol.rename(columns={"bucket": "Bucket start (UTC)", "source_label": "Source", "events": "Events"}),
                         hide_index=True)
    with c2:
        st.subheader("Alerts by severity")
        sev_counts = (f_alerts["severity"].value_counts().reindex(SEVERITIES, fill_value=0)
                      .rename_axis("severity").reset_index(name="alerts"))
        sev_base = alt.Chart(sev_counts).encode(
            y=alt.Y("severity:N", sort=SEV_DESC, title=None),
            x=alt.X("alerts:Q", title="Alerts", axis=alt.Axis(tickMinStep=1), scale=headroom(sev_counts["alerts"].max())),
        )
        sev_chart = (
            sev_base.mark_bar(size=24, cornerRadiusTopRight=3, cornerRadiusBottomRight=3)
            .encode(color=alt.Color("severity:N", scale=alt.Scale(domain=SEVERITIES, range=P["sev"]), legend=None),
                    tooltip=[alt.Tooltip("severity:N", title="Severity"), alt.Tooltip("alerts:Q", title="Alerts")])
            + sev_base.mark_text(align="left", dx=5, color=P["text"], fontSize=13).encode(text="alerts:Q")
        )
        st.altair_chart(style(sev_chart, P, 300), theme=None, width="stretch")

    c3, c4 = st.columns(2)
    with c3:
        st.subheader("Top offending IPs")
        ip_alerts = f_alerts[f_alerts["src_ip"].notna()].copy()
        if ip_alerts.empty:
            st.info("No IP-based alerts.")
        else:
            rank = {s: i for i, s in enumerate(SEVERITIES)}
            ip_alerts["rank"] = ip_alerts["severity"].map(rank)
            top = ip_alerts.groupby("src_ip").agg(alerts=("id", "count"), rank=("rank", "max")).reset_index()
            top["severity"] = top["rank"].map(lambda i: SEVERITIES[i])
            top = top.sort_values(["alerts", "rank"], ascending=False).head(8)
            ip_base = alt.Chart(top).encode(
                y=alt.Y("src_ip:N", sort=top["src_ip"].tolist(), title=None),  # already ordered by count
                x=alt.X("alerts:Q", title="Alerts", axis=alt.Axis(tickMinStep=1), scale=headroom(top["alerts"].max())),
            )
            ip_chart = (
                ip_base.mark_bar(size=20, cornerRadiusTopRight=3, cornerRadiusBottomRight=3)
                .encode(color=alt.Color("severity:N", scale=alt.Scale(domain=SEVERITIES, range=P["sev"]),
                                        legend=alt.Legend(title="Highest severity")),
                        tooltip=[alt.Tooltip("src_ip:N", title="Source IP"), alt.Tooltip("alerts:Q", title="Alerts"),
                                 alt.Tooltip("severity:N", title="Highest severity")])
                + ip_base.mark_text(align="left", dx=5, color=P["text"], fontSize=13).encode(text="alerts:Q")
            )
            st.altair_chart(style(ip_chart, P, max(160, 34 * len(top) + 60)), theme=None, width="stretch")
    with c4:
        st.subheader("MITRE ATT&CK coverage")
        mitre = f_alerts[f_alerts["mitre"].fillna("") != ""]
        if mitre.empty:
            st.info("No mapped alerts.")
        else:
            m = (mitre.groupby(["mitre", "title"]).size().reset_index(name="alerts")
                 .sort_values("alerts", ascending=False))
            st.dataframe(m.rename(columns={"mitre": "Technique", "title": "Detection", "alerts": "Alerts"}),
                         hide_index=True)


# ------------------------------------------------------ alerts & investigation --
def mitre_links(value: str) -> str:
    out = []
    for tid in [t.strip() for t in (value or "").split(",") if t.strip()]:
        if re.fullmatch(r"T\d{4}(\.\d{3})?", tid):
            out.append(f"[{tid}](https://attack.mitre.org/techniques/{tid.replace('.', '/')}/)")
        elif re.fullmatch(r"TA\d{4}", tid):
            out.append(f"[{tid}](https://attack.mitre.org/tactics/{tid}/)")
        else:
            out.append(tid)
    return ", ".join(out) or "n/a"


with tab_alerts:
    if f_alerts.empty:
        st.info("No alerts match the current filters.")
    else:
        rank = {s: i for i, s in enumerate(SEVERITIES)}
        view = (f_alerts.assign(_r=f_alerts["severity"].map(rank))
                .sort_values(["_r", "timestamp"], ascending=[False, False]).reset_index(drop=True))
        st.dataframe(
            view[["timestamp", "severity", "rule_id", "title", "src_ip", "username", "event_count", "mitre"]],
            hide_index=True,
            column_config={
                "timestamp": st.column_config.DatetimeColumn("Time (UTC)", format="YYYY-MM-DD HH:mm:ss"),
                "severity": "Severity", "rule_id": "Rule", "title": "Detection", "src_ip": "Source IP",
                "username": "User", "event_count": st.column_config.NumberColumn("Events"), "mitre": "MITRE",
            },
        )

        st.subheader("Investigate")
        idx = st.selectbox(
            "Select an alert", list(view.index),
            format_func=lambda i: (f"[{view.at[i, 'severity'].upper()}] {view.at[i, 'timestamp']:%H:%M:%S} · "
                                   f"{view.at[i, 'title']} · {view.at[i, 'src_ip'] or view.at[i, 'username'] or '-'}"),
        )
        a = view.loc[idx]
        left, right = st.columns([3, 2])
        with left:
            st.markdown(f"**{a['severity'].upper()}** · {a['rule_id']} · {a['title']}")
            st.write(a["description"])
            st.markdown(f"**MITRE ATT&CK:** {mitre_links(a['mitre'])}")
            st.markdown("**Evidence**")
            st.code("\n".join(a["evidence"]) or "(none)", language="text")
        with right:
            if a["src_ip"]:
                related = events[events["src_ip"] == a["src_ip"]]
                st.markdown(f"**All activity from {a['src_ip']}**")
            else:
                related = events[events["username"] == a["username"]]
                st.markdown(f"**All activity by {a['username']}**")
            if related.empty:
                st.caption("No other events found.")
            else:
                summary = (related.assign(source=related["source"].map(SOURCE_LABELS))
                           .groupby(["source", "event_type"]).size().reset_index(name="events")
                           .sort_values("events", ascending=False))
                st.dataframe(summary.rename(columns={"source": "Source", "event_type": "Type", "events": "Events"}),
                             hide_index=True)
        if not related.empty:
            with st.expander(f"Event trail ({len(related):,} events, newest 300 shown)"):
                st.dataframe(related.sort_values("timestamp", ascending=False).head(300), hide_index=True)

# -------------------------------------------------------------------- events --
with tab_events:
    e1, e2, e3 = st.columns(3)
    src_sel = e1.multiselect("Source", list(SOURCE_LABELS), default=list(SOURCE_LABELS),
                             format_func=SOURCE_LABELS.get)
    type_sel = e2.multiselect("Event type", sorted(events["event_type"].unique()))
    ev_query = e3.text_input("Search events", placeholder="IP, user or text")
    ev = events[events["source"].isin(src_sel)]
    if type_sel:
        ev = ev[ev["event_type"].isin(type_sel)]
    if ev_query:
        hay = ev[["src_ip", "username", "message"]].fillna("").astype(str).agg(" ".join, axis=1)
        ev = ev[hay.str.contains(ev_query, case=False, regex=False)]
    st.caption(f"{len(ev):,} matching events" + (" (newest 2,000 shown)" if len(ev) > 2000 else ""))
    st.dataframe(ev.sort_values("timestamp", ascending=False).head(2000), hide_index=True,
                 column_config={"timestamp": st.column_config.DatetimeColumn("Time (UTC)", format="YYYY-MM-DD HH:mm:ss")})

# --------------------------------------------------------------------- rules --
with tab_rules:
    fired = alerts["rule_id"].value_counts()
    rules_df = pd.DataFrame([
        {"Rule": r.id, "Severity": r.severity, "MITRE": r.mitre or "-", "Detection": r.title,
         "What it catches": r.description, "Alerts raised": int(fired.get(r.id, 0)),
         "Type": "Correlation" if r in CORRELATION_RULES else "Single-source"}
        for r in all_rules()
    ])
    st.dataframe(rules_df, hide_index=True)
    st.caption("Thresholds live in DEFAULT_CONFIG in siem/rules.py. Correlation rules combine the alerts of other rules.")
