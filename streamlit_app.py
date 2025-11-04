import streamlit as st
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import plotly.express as px

st.set_page_config(page_title="AI Threat Intelligence Dashboard", layout="wide")
st.title("AI Threat Intelligence Dashboard — Norwegian Banking Apps")
st.caption("Data is simulated for educational purposes. Part of *Zara’s Norske AI-prosjekter* 🇳🇴")

# --------- Sidebar inputs
with st.sidebar:
    st.header("Data")
    uploaded = st.file_uploader("Upload CSV", type=["csv"], help="Use columns shown in sample_data.csv")
    st.markdown("[Download sample CSV](https://raw.githubusercontent.com/youruser/norsec-streamlit/main/sample_data.csv)")
    st.header("Model")
    n_estimators = st.slider("Trees (Random Forest)", 100, 600, 300, 50)
    threshold = st.slider("High-risk sensitivity", 0.20, 0.90, 0.60, 0.05)
    st.caption("Threshold is used for marking 'High' probability alerts.")

# --------- Load data
if uploaded:
    df = pd.read_csv(uploaded)
else:
    df = pd.read_csv("sample_data.csv")

required = [
    "app_name","permission_count","uses_encryption","uses_ssl",
    "api_calls","severity_score","exploitability_score","risk_level"
]
missing = [c for c in required if c not in df.columns]
if missing:
    st.error(f"Missing columns: {missing}")
    st.stop()

# --------- Clean + encode
df_enc = df.copy()
df_enc["risk_level_num"] = df_enc["risk_level"].map({"Low":0,"Medium":1,"High":2})
if df_enc["risk_level_num"].isna().any():
    st.error("`risk_level` must be Low/Medium/High.")
    st.stop()

features = ["permission_count","uses_encryption","uses_ssl","api_calls","severity_score","exploitability_score"]
X = df_enc[features].astype(float)
y = df_enc["risk_level_num"].astype(int)

scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# --------- Train quick demo model
rf = RandomForestClassifier(n_estimators=n_estimators, random_state=42)
rf.fit(X_scaled, y)
proba = rf.predict_proba(X_scaled)
df_out = df.copy()
df_out["p_low"]  = proba[:,0]
df_out["p_med"]  = proba[:,1]
df_out["p_high"] = proba[:,2]
df_out["predicted"] = np.argmax(proba, axis=1)
df_out["predicted"] = df_out["predicted"].map({0:"Low",1:"Medium",2:"High"})
df_out["alert_high"] = (df_out["p_high"] >= threshold)

# --------- Top KPIs
c1,c2,c3,c4 = st.columns(4)
c1.metric("Apps analyzed", len(df_out))
c2.metric("High-risk (predicted)", int((df_out["predicted"]=="High").sum()))
c3.metric("High-risk (alerts)", int(df_out["alert_high"].sum()))
c4.metric("Avg. severity", f"{df_out['severity_score'].mean():.2f}")

# --------- Table
st.subheader("Risk overview")
st.dataframe(
    df_out[["app_name","predicted","p_high","severity_score","exploitability_score","permission_count","uses_encryption","uses_ssl","api_calls","alert_high"]],
    use_container_width=True
)

# --------- Charts
left, right = st.columns(2)
with left:
    fig1 = px.bar(df_out, x="app_name", y="p_high", title="High-risk probability by app")
    st.plotly_chart(fig1, use_container_width=True)
with right:
    fig2 = px.scatter(
        df_out, x="permission_count", y="severity_score",
        size="api_calls", color="predicted", hover_name="app_name",
        title="Severity vs Permissions (bubble=size API calls)"
    )
    st.plotly_chart(fig2, use_container_width=True)

# --------- App detail
st.subheader("App detail")
sel = st.selectbox("Select app", df_out["app_name"].tolist())
row = df_out[df_out["app_name"]==sel].iloc[0]
st.write(pd.DataFrame({
    "metric":["Predicted","p_low","p_med","p_high","Severity","Exploitability","Permissions","Encryption","SSL","API calls","Alert (threshold)"],
    "value":[row["predicted"], f"{row['p_low']:.2f}", f"{row['p_med']:.2f}", f"{row['p_high']:.2f}",
             f"{row['severity_score']:.2f}", f"{row['exploitability_score']:.2f}", int(row["permission_count"]),
             "Yes" if row["uses_encryption"] else "No", "Yes" if row["uses_ssl"] else "No", int(row["api_calls"]),
             "🚨" if row["alert_high"] else "—"]
}))

# --------- Simple "AI insights"
st.subheader("Insights")
insights = []
if (df_out["uses_ssl"]==0).mean() > 0.25:
    insights.append("Apps without SSL appear frequently and correlate with higher predicted risk.")
if df_out["permission_count"].mean() > 25:
    insights.append("Average permission count is elevated; consider minimizing sensitive permissions.")
if df_out["p_high"].mean() > 0.4:
    insights.append("Overall high-risk probability is non-trivial; prioritize code review for top apps.")
if not insights:
    insights.append("No dominant single risk factor detected; risks appear distributed across multiple features.")
for tip in insights:
    st.write("• " + tip)

st.markdown("---")
st.caption("Designed and analyzed by Zara — part of *Zara’s Norske AI-prosjekter* 🇳🇴")
