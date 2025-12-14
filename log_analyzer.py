import re
import csv
import smtplib
from email.message import EmailMessage
from collections import Counter
import matplotlib.pyplot as plt

# ---------------- CONFIG ----------------
SENDER_EMAIL = "arigelalavanya55@gmail.com"
APP_PASSWORD = "akbw fwfv qjus vblw"
RECEIVER_EMAIL = "arigelalavanya55@gmail.com"
THRESHOLD = 2
# ----------------------------------------

log_file = "sample_logs.txt"

# Read logs
with open(log_file, "r") as file:
    logs = file.readlines()

failed_records = []

# Extract failed login data
for line in logs:
    if "Failed password" in line:
        match = re.search(r"Failed password for (\w+) from (\d+\.\d+\.\d+\.\d+)", line)
        if match:
            failed_records.append((match.group(1), match.group(2)))

# Count attempts per IP
ip_count = Counter(ip for _, ip in failed_records)

# -------- CSV REPORT --------
with open("security_report.csv", "w", newline="") as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(["Username(s)", "IP Address", "Failed Attempts"])

    for ip, count in ip_count.items():
        users = set(u for u, ip_addr in failed_records if ip_addr == ip)
        writer.writerow([", ".join(users), ip, count])

print("security_report.csv created successfully")

# -------- EMAIL ALERT --------
alerts = []

for ip, count in ip_count.items():
    if count > THRESHOLD:
        alerts.append(f"⚠️ Brute-force detected from IP {ip} ({count} attempts)")

if alerts:
    msg = EmailMessage()
    msg["Subject"] = "🚨 Security Alert: Brute-force Login Detected"
    msg["From"] = SENDER_EMAIL
    msg["To"] = RECEIVER_EMAIL
    msg.set_content("\n".join(alerts))

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
        server.login(SENDER_EMAIL, APP_PASSWORD)
        server.send_message(msg)

    print("🚨 Email alert sent successfully")
else:
    print("No suspicious activity detected")

# -------- GRAPH --------
plt.bar(ip_count.keys(), ip_count.values())
plt.xlabel("IP Address")
plt.ylabel("Failed Login Attempts")
plt.title("Failed Login Attempts per IP")
plt.tight_layout()
plt.savefig("failed_login_graph.png")
plt.show()

print("failed_login_graph.png created successfully")
