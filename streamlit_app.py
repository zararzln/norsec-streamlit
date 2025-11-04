import streamlit as st
import pandas as pd
import numpy as np
from datetime import datetime
import plotly.express as px
import plotly.graph_objects as go

# ---------------------- PAGE CONFIG ----------------------
st.set_page_config(
    page_title="AI Threat Intelligence Dashboard",
    page_icon="🛡️",
    layout="wide"
)

# ---------------------- GLOBAL STYLE (CSS) ----------------------
st.markdown("""
<style>
.header-card { position:relative; overflow:hidden; }
.header-card::after{
  content:""; position:absolute; inset:-40px -60px auto auto; width:220px; height:220px;
  background: radial-gradient(closest-side, rgba(30,136,229,.35), rgba(30,136,229,0));
  filter: blur(18px);
}
.kpi-grid { display:grid; grid-template-columns: repeat(4, minmax(0,1fr)); gap:16px; }
.kpi-card { background:#112240; border:1px solid #1F3B63; border-radius:18px; padding:16px 18px; }
.kpi-top { display:flex; align-items:center; justify-content:space-between; margin-bottom:6px; color:#A8B2D1; font-size:12px; }
.kpi-main { display:flex; align-items:baseline; gap:8px; }
.kpi-value { font-size:30px; font-weight:700; color:#E6EDF3; }
.kpi-delta { font-size:12px; border-radius:10px; padding:2px 8px; }
.kpi-delta.up { background:rgba(239,68,68,.12); color:#FF9CA3; }   /* worse */
.kpi-delta.down { background:rgba(34,197,94,.12); color:#77E2A5; } /* better */
.spark { height:42px; }
.gauge-card { background:#112240; border:1px solid #1F3B63; border-radius:18px; padding:16px; }
.insight-pill { display:flex; gap:10px; align-items:flex-start; }
.ins-icon { width:20px; line-height:20px; }
.badge { display:inline-block; background:#1C2E4A; border:1px solid #2B4B73; color:#D9E2EC; padding:4px 10px; border-radius:999px; font-size:12px; margin-right:6px; }
.btn-row { display:flex; gap:8px; }
</style>
""", unsafe_allow_html=True)



# ---------------------- SAMPLE / SIM DATA ----------------------
def generate_sample_cve(n=15, seed=42):
    rng = np.random.default_rng(seed)
    types = ["Encryption Weakness","Code Injection","Insecure Permissions",
             "API Security Flaw","Memory Corruption","Insecure Data Storage","Session Management"]
    platforms = ["Android","iOS","Cross-platform"]
    severities = ["Low","Medium","High","Critical"]
    rows = []
    year = datetime.now().year
    for i in range(n):
        t = rng.choice(types)
        p = rng.choice(platforms, p=[0.45,0.35,0.20])
        sev_label = rng.choice(severities, p=[0.15,0.30,0.30,0.25])
        base = {"Low": (4.0,5.9), "Medium": (6.0,7.4), "High": (7.5,8.4), "Critical": (8.5,9.8)}[sev_label]
        sev_score = float(np.round(rng.uniform(*base),1))
        expl_score = float(np.round(rng.uniform(max(5.0, sev_score-1.5), 9.9),1))
        cve_id = f"CVE-{year}-{rng.integers(1000,9999)}"
        app = rng.choice(["DNB","Sbanken","SpareBank 1","Nordea","Vipps"])
        rows.append({
            "cve_id": cve_id,
            "type": t,
            "platform": p,
            "severity": sev_label,
            "severity_score": sev_score,
            "exploitability": expl_score,
            "app_name": app
        })
    return pd.DataFrame(rows)

# Data source (upload or generated)
with st.sidebar:
    st.header("Data")
    up = st.file_uploader("Upload CVE-like CSV", type=["csv"], help="Columns: cve_id,type,platform,severity,severity_score,exploitability,app_name")
    st.caption("No file? Using simulated CVE-style data.")
    st.header("Filters")
    platform_filter = st.multiselect("Platform", ["Android","iOS","Cross-platform"], default=["Android","iOS","Cross-platform"])
    st.header("Display")
    show_counts = st.checkbox("Show counts in heatmap cells", value=True)

df = pd.read_csv(up) if up else generate_sample_cve(n=24)

# Apply filter
df = df[df["platform"].isin(platform_filter)].reset_index(drop=True)

# ---------------------- HEADER ----------------------
st.markdown("""
<div class="header-card">
  <div class="header-title">
    <span>🛡️ AI Threat Intelligence Dashboard</span>
    <span class="flag">🇳🇴</span>
  </div>
  <div class="header-sub">Norwegian Mobile App Security Monitor • CVE-style analysis (simulated data)</div>
</div>
""", unsafe_allow_html=True)

# ---------------------- KPIs ----------------------# 
total = len(df)
critical = int((df["severity"]=="Critical").sum())
high = int((df["severity"]=="High").sum())
medium_low = int((df["severity"].isin(["Medium","Low"])).sum())

def delta_chip(current, previous, higher_is_good=False):
    diff = current - previous
    if diff == 0:
        return '<span class="kpi-delta">0</span>'
    good = (diff < 0) if not higher_is_good else (diff > 0)
    klass = "down" if good else "up"
    sign = "+" if diff>0 else "−"
    return f'<span class="kpi-delta {klass}">{sign}{abs(diff)}</span>'

def sparkline(vals):
    fig = px.area(y=vals, height=42)
    fig.update_traces(hoverinfo="skip")
    fig.update_layout(
        margin=dict(l=0,r=0,t=0,b=0),
        paper_bgcolor="#112240", plot_bgcolor="#112240",
        xaxis=dict(visible=False), yaxis=dict(visible=False)
    )
    return fig

# little histories for sparklines
hist_total    = np.clip(np.cumsum(np.random.randint(-2,3, size=12)) + total, 0, None)
hist_critical = np.clip(np.cumsum(np.random.randint(-1,2, size=12)) + critical, 0, None)
hist_high     = np.clip(np.cumsum(np.random.randint(-1,2, size=12)) + high, 0, None)
hist_ml       = np.clip(np.cumsum(np.random.randint(-2,3, size=12)) + medium_low, 0, None)

st.markdown('<div class="kpi-grid">', unsafe_allow_html=True)
c1, c2, c3, c4 = st.columns(4)

with c1:
    st.markdown(f'''
    <div class="kpi-card">
      <div class="kpi-top">Total Vulnerabilities <span>🛡️</span></div>
      <div class="kpi-main"><div class="kpi-value">{total}</div>{delta_chip(total, last_total)}</div>
    </div>''', unsafe_allow_html=True)
    st.plotly_chart(sparkline(hist_total), use_container_width=True, config={"displayModeBar": False})

with c2:
    st.markdown(f'''
    <div class="kpi-card">
      <div class="kpi-top">Critical <span>❗</span></div>
      <div class="kpi-main"><div class="kpi-value">{critical}</div>{delta_chip(critical, last_critical)}</div>
    </div>''', unsafe_allow_html=True)
    st.plotly_chart(sparkline(hist_critical), use_container_width=True, config={"displayModeBar": False})

with c3:
    st.markdown(f'''
    <div class="kpi-card">
      <div class="kpi-top">High Priority <span>⚠️</span></div>
      <div class="kpi-main"><div class="kpi-value">{high}</div>{delta_chip(high, last_high)}</div>
    </div>''', unsafe_allow_html=True)
    st.plotly_chart(sparkline(hist_high), use_container_width=True, config={"displayModeBar": False})

with c4:
    st.markdown(f'''
    <div class="kpi-card">
      <div class="kpi-top">Medium & Low <span>ℹ️</span></div>
      <div class="kpi-main"><div class="kpi-value">{medium_low}</div>{delta_chip(medium_low, last_ml, higher_is_good=False)}</div>
    </div>''', unsafe_allow_html=True)
    st.plotly_chart(sparkline(hist_ml), use_container_width=True, config={"displayModeBar": False})

st.markdown('</div>', unsafe_allow_html=True)

# ------- Risk Index gauge -------
weighted = np.average(
    df["severity_score"],
    weights=np.clip(df["exploitability"], 0.1, None)
)
risk_index = float(np.round(weighted, 1))  # 4.0–10.0 scale

gauge = go.Figure(go.Indicator(
    mode="gauge+number",
    value=risk_index,
    number={'font': {'color':'#E6EDF3'}},
    gauge={
        'axis': {'range': [4, 10], 'tickcolor':'#A8B2D1', 'tickwidth':1},
        'bar': {'color': '#1E88E5'},
        'bgcolor': '#112240',
        'borderwidth': 0,
        'steps': [
            {'range': [4,6],  'color':'#064E3B'},
            {'range': [6,7.5],'color':'#92400E'},
            {'range': [7.5,8.5],'color':'#7C2D12'},
            {'range': [8.5,10],'color':'#7F1D1D'}
        ]
    },
    title={'text': "Risk Index", 'font': {'color':'#66B2FF'}}
))
gauge.update_layout(
    height=220, margin=dict(l=10,r=10,t=40,b=0),
    paper_bgcolor="#112240"
)

gc1, gc2 = st.columns([1,3])
with gc1:
    st.markdown('<div class="gauge-card">', unsafe_allow_html=True)
    st.plotly_chart(gauge, use_container_width=True, config={"displayModeBar": False})
    st.markdown('</div>', unsafe_allow_html=True)
with gc2:
    st.markdown('<div class="gauge-card"><div class="section-title">Current posture</div>', unsafe_allow_html=True)
    st.markdown(
        f'<span class="badge">Top type: {top_type}</span>'
        f'<span class="badge">Critical: {critical}</span>'
        f'<span class="badge">Avg severity: {df["severity_score"].mean():.1f}</span>'
        f'<span class="badge">Avg exploitability: {df["exploitability"].mean():.1f}</span>',
        unsafe_allow_html=True
    )
    st.markdown('</div>', unsafe_allow_html=True)

# ---------------------- AI-POWERED INSIGHTS ----------------------
st.markdown('<div class="card"><div class="section-title">🤖 AI-Powered Insights</div>', unsafe_allow_html=True)

insights = []

# 1: critical count
if critical >= 5:
    insights.append(f"🔴 {critical} critical vulnerabilities detected that require immediate attention.")

# 2: most common type
top_type = df["type"].value_counts().idxmax()
top_type_n = df["type"].value_counts().max()
insights.append(f"⚠️ {top_type} is the most frequently observed threat, appearing {top_type_n} times across scanned apps.")

# 3: iOS vs Android severity comparison
ios_avg = df.loc[df["platform"] == "iOS", "severity_score"].mean()
and_avg = df.loc[df["platform"] == "Android", "severity_score"].mean()
if pd.notna(ios_avg) and pd.notna(and_avg):
    delta = ios_avg - and_avg
    arrow = "higher" if delta > 0 else "lower"
    insights.append(f"📱 iOS apps show an average severity that is {abs(delta):.1f}% {arrow} than Android applications.")

# 4: overall average severity
overall = df["severity_score"].mean()
insights.append(f"🏦 The average severity score across Norwegian banking apps is {overall:.1f}, suggesting closer monitoring for top-risk applications.")

for tip in insights:
    st.markdown(f'<div class="insight-pill">{tip}</div>', unsafe_allow_html=True)

st.markdown('</div>', unsafe_allow_html=True)


# ---------------------- VULNERABILITY DISTRIBUTION (BAR) ----------------------
counts = df["type"].value_counts().reset_index()
counts.columns = ["type","count"]
fig_bar = px.bar(
    counts, x="type", y="count",
    title="Vulnerability Distribution by Type",
    text="count",
    color="count",
    color_continuous_scale=["#F59E0B","#F97316","#EF4444"]  # yellow→orange→red
)
fig_bar.update_traces(textposition="outside")
fig_bar.update_layout(
    margin=dict(l=10,r=10,t=50,b=10),
    paper_bgcolor="white", plot_bgcolor="white",
    xaxis_title=None, yaxis_title=None
)
st.plotly_chart(fig_bar, use_container_width=True)

# ---------------------- SEVERITY HEATMAP (PLATFORM × TYPE) ----------------------
# Pivot average severity score
pivot = df.pivot_table(index="type", columns="platform", values="severity_score", aggfunc="mean")
counts_pt = df.groupby(["type","platform"]).size().unstack(fill_value=0)

# Build heatmap with annotations
types_order = pivot.index.tolist()
platforms_order = pivot.columns.tolist()

z = pivot.values
x = platforms_order
y = types_order

# choose colors by ranges
colorscale = [
    [0.00, "#D1FAE5"], # low green
    [0.25, "#FDE68A"], # medium yellow
    [0.50, "#FDBA74"], # high orange
    [0.75, "#FCA5A5"], # critical light red
    [1.00, "#F87171"], # deeper red
]

# normalize scores to 0-1 by 4-10 range
def norm(v):
    return (v-4.0)/6.0

z_norm = np.vectorize(lambda v: None if pd.isna(v) else max(0.0, min(1.0, norm(v))))(z)

fig_hm = go.Figure(data=go.Heatmap(
    z=z_norm,
    x=x, y=y,
    colorscale=colorscale,
    colorbar=dict(title="Severity", tickvals=[0,0.33,0.66,1], ticktext=["Low","Medium","High","Critical"])
))
# add annotations (score + counts)
for i, ty in enumerate(y):
    for j, plat in enumerate(x):
        score = pivot.loc[ty, plat] if plat in pivot.columns else np.nan
        cnt = counts_pt.loc[ty, plat] if (ty in counts_pt.index and plat in counts_pt.columns) else 0
        label = ""
        if pd.notna(score):
            label = f"{score:.1f}" + (f" ({cnt})" if {show_counts} else "")
        fig_hm.add_annotation(x=plat, y=ty, text=label, showarrow=False, font=dict(color="#111", size=12))

fig_hm.update_layout(
    title="Severity Heatmap (Platform × Type)",
    margin=dict(l=10,r=10,t=50,b=10),
    paper_bgcolor="white", plot_bgcolor="white",
    xaxis_title=None, yaxis_title=None
)
st.plotly_chart(fig_hm, use_container_width=True)
st.markdown('<div class="legend">Legend: Critical (≥8.5) • High (7.5–8.4) • Medium (6–7.4) • Low (&lt;6)</div>', unsafe_allow_html=True)

# ---------------------- TOP VULNERABILITIES TABLE ----------------------
st.markdown('<div class="section-title">Top Vulnerabilities (CVEs)</div>', unsafe_allow_html=True)

colf1, colf2 = st.columns([1,1])
with colf1:
    platform_pick = st.selectbox("Filter platform", ["All Platforms","Android","iOS","Cross-platform"], index=0)
with colf2:
    sort_key = st.selectbox("Sort by", ["Severity Score","Exploitability"], index=0)

df_table = df.copy()
if platform_pick != "All Platforms":
    df_table = df_table[df_table["platform"]==platform_pick]

df_table = df_table.sort_values("severity_score" if sort_key=="Severity Score" else "exploitability", ascending=False)

def sev_chip(s):
    s_lower = s.lower()
    cls = "sev-low" if s_lower=="low" else "sev-medium" if s_lower=="medium" else "sev-high" if s_lower=="high" else "sev-critical"
    return f'<span class="sev-chip {cls}">{s}</span>'

tbl = pd.DataFrame({
    "CVE ID": df_table["cve_id"],
    "Type": df_table["type"],
    "Platform": df_table["platform"],
    "Severity": [sev_chip(s) for s in df_table["severity"]],
    "Severity Score": df_table["severity_score"].map(lambda v: f"{v:.1f}"),
    "Exploitability": df_table["exploitability"].map(lambda v: f"{v:.1f}"),
    "App": df_table["app_name"]
})

st.markdown('<div class="table-wrap">', unsafe_allow_html=True)
st.write(tbl.to_html(escape=False, index=False), unsafe_allow_html=True)
st.markdown('</div>', unsafe_allow_html=True)

# ---------------------- FOOTER ----------------------
st.markdown("---")
st.caption("Designed & analyzed by Zara — part of *Zara’s Norske AI-prosjekter* 🇳🇴  •  Data simulated for educational use only.")
