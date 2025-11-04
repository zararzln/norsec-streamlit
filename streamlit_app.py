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
/* Header gradient & rounded */
.header-card {
  background: linear-gradient(135deg, #0A2540 0%, #184E77 60%, #1E88E5 100%);
  color: #FFFFFF;
  padding: 26px 28px;
  border-radius: 18px;
  box-shadow: 0 8px 24px rgba(10,37,64,0.25);
  margin-bottom: 18px;
}
.header-title { font-size: 28px; font-weight: 700; margin: 0; display:flex; gap:12px; align-items:center; }
.header-sub  { font-size: 14px; opacity: 0.9; margin-top: 4px; }

.flag { font-size: 24px; margin-left:auto; }

.card {
  background: #FFFFFF;
  border: 1px solid #EEF2F8;
  border-radius: 16px;
  padding: 18px 18px 14px 18px;
  box-shadow: 0 8px 18px rgba(16,24,40,0.05);
}

.kpi-number { font-size: 30px; font-weight: 700; color: #0A2540; margin: 0; }
.kpi-label  { font-size: 13px; color: #4B5563; margin-top: 4px; }
.kpi-icon   { font-size: 20px; opacity: 0.75; }

.insight-pill {
  background:#F6F8FB;
  border: 1px solid #E5ECF3;
  border-radius: 12px;
  padding: 10px 12px;
  margin-bottom: 10px;
}

.sev-chip {
  padding: 4px 10px;
  border-radius: 999px;
  font-size: 12px; font-weight:700;
  color:#fff; display:inline-block;
}
.sev-critical { background:#E11D48; } /* red */
.sev-high     { background:#F97316; } /* orange */
.sev-medium   { background:#EAB308; } /* yellow */
.sev-low      { background:#10B981; } /* green */

.table-wrap {
  border: 1px solid #EEF2F8; border-radius: 16px; padding: 10px 10px 2px 10px;
  background:#FFFFFF; box-shadow: 0 8px 18px rgba(16,24,40,0.05);
}

.legend { font-size:12px; color:#6B7280; margin-top:8px;}
.small-muted { font-size:12px; color:#6B7280;}
.section-title { font-size:20px; font-weight:700; color:#0A2540; margin-bottom:10px;}
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

# ---------------------- KPIs ----------------------
total = len(df)
critical = int((df["severity"]=="Critical").sum())
high = int((df["severity"]=="High").sum())
medium_low = int((df["severity"].isin(["Medium","Low"])).sum())

c1,c2,c3,c4 = st.columns(4)
with c1:
    st.markdown('<div class="card"><div class="kpi-icon">🛡️</div><p class="kpi-number">{}</p><p class="kpi-label">Total Vulnerabilities</p></div>'.format(total), unsafe_allow_html=True)
with c2:
    st.markdown('<div class="card"><div class="kpi-icon">❗</div><p class="kpi-number">{}</p><p class="kpi-label">Critical</p></div>'.format(critical), unsafe_allow_html=True)
with c3:
    st.markdown('<div class="card"><div class="kpi-icon">⚠️</div><p class="kpi-number">{}</p><p class="kpi-label">High Priority</p></div>'.format(high), unsafe_allow_html=True)
with c4:
    st.markdown('<div class="card"><div class="kpi-icon">ℹ️</div><p class="kpi-number">{}</p><p class="kpi-label">Medium & Low</p></div>'.format(medium_low), unsafe_allow_html=True)

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
