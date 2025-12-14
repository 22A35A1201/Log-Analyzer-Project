import re
from datetime import datetime, time
import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
from collections import Counter

# ---------------- Page Config ----------------
st.set_page_config(page_title="Security Dashboard", layout="wide")
st.title("🔐 Suspicious Login Detection Dashboard")

# ---------------- Sidebar ----------------
st.sidebar.header("⚙️ Control Panel")

threshold = st.sidebar.slider(
    "Brute-force threshold",
    min_value=1,
    max_value=10,
    value=2
)

# ---------------- Read Logs ----------------
log_file = "sample_logs.txt"

with open(log_file, "r", encoding="utf-8", errors="ignore") as file:
    logs = file.readlines()

failed_records = []

# ---------------- Parse Logs ----------------
for line in logs:
    if "Failed password" in line:
        time_match = re.match(r"(\w+\s+\d+\s+\d+:\d+:\d+)", line)
        login_match = re.search(
            r"Failed password for (\w+) from (\d+\.\d+\.\d+\.\d+)",
            line
        )

        if time_match and login_match:
            timestamp = datetime.strptime(f"{datetime.now().year} {time_match.group(1)}",
    "%Y %b %d %H:%M:%S"
)

            username = login_match.group(1)
            ip = login_match.group(2)

            failed_records.append((timestamp, username, ip))

if not failed_records:
    st.warning("No failed login attempts found.")
    st.stop()

# ---------------- Count Attempts ----------------
ip_count = Counter(ip for _, _, ip in failed_records)

# ---------------- Build DataFrame ----------------
data = []
for ip, count in ip_count.items():
    users = ", ".join(set(u for t, u, ip_addr in failed_records if ip_addr == ip))
    times = [t for t, u, ip_addr in failed_records if ip_addr == ip]
    data.append([ip, count, users, min(times), max(times)])

df = pd.DataFrame(
    data,
    columns=["IP Address", "Failed Attempts", "Usernames", "First Seen", "Last Seen"]
)

# ---------------- Time Filter (SAFE DEFAULTS) ----------------
st.sidebar.subheader("🕒 Time Filter")

start_time = st.sidebar.time_input("Start time", value=time(0, 0))
end_time = st.sidebar.time_input("End time", value=time(23, 59))

df = df[
    (df["First Seen"].dt.time >= start_time) &
    (df["Last Seen"].dt.time <= end_time)
]

if df.empty:
    st.warning("No records in selected time range.")
    st.stop()

# ---------------- Status (CSV-friendly) ----------------
df["Status"] = df["Failed Attempts"].apply(
    lambda x: "Suspicious" if x > threshold else "Normal"
)

# ---------------- Metrics ----------------
col1, col2, col3 = st.columns(3)

col1.metric("Total Failed Attempts", int(df["Failed Attempts"].sum()))
col2.metric("Suspicious IPs", int(len(df[df["Failed Attempts"] > threshold])))
col3.metric(
    "Security Status",
    "ALERT" if len(df[df["Failed Attempts"] > threshold]) > 0 else "SAFE"
)

st.divider()

# ---------------- Table ----------------
st.subheader("🚨 Failed Login Details")

def highlight_rows(row):
    return [
        "background-color: #ffcccc"
        if row["Status"] == "Suspicious"
        else ""
        for _ in row
    ]

st.dataframe(
    df.style.apply(highlight_rows, axis=1),
    width="stretch"
)

# ---------------- Download ----------------
st.download_button(
    "⬇️ Download Security Report (CSV)",
    df.to_csv(index=False),
    "security_report.csv",
    "text/csv"
)

# ---------------- Graph ----------------
st.subheader("📊 Failed Login Attempts per IP")

colors = ["red" if x > threshold else "green" for x in df["Failed Attempts"]]

fig, ax = plt.subplots()
ax.bar(df["IP Address"], df["Failed Attempts"], color=colors)
ax.set_xlabel("IP Address")
ax.set_ylabel("Failed Attempts")
ax.set_title("Attack Frequency")

st.pyplot(fig)
