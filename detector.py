import re
import pandas as pd
import matplotlib.pyplot as plt
from datetime import datetime

# Path to your log file
log_path = "logs/access.log"

# Regex patterns for security anomalies
patterns = {
    "Failed Password": r"Failed password",
    "Invalid User": r"Invalid user",
    "SQL Injection": r"(%20OR%20\d+=\d+)|(\bunion\b.*\bselect\b)|(\bunion\b)|(\bselect\b)|(')|(--)",
    "XSS": r"<script>.*</script>",
    "Brute Force": r"too many attempts|authentication failure"
}

# Read log file
with open(log_path, "r") as f:
    logs = f.readlines()

# Detect anomalies
anomalies = []

for line in logs:
    for anomaly_type, pattern in patterns.items():
        if re.search(pattern, line, re.IGNORECASE):
            anomalies.append({
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "log": line.strip(),
                "type": anomaly_type
            })

# Convert to DataFrame
df = pd.DataFrame(anomalies)

# Exit if no anomalies found
if df.empty:
    print("[INFO] No anomalies detected.")
    exit()

# Display detected anomalies
print("\n[INFO] Detected Anomalies:\n")
print(df.to_string(index=False))

# Save anomalies to Excel
try:
    output_file = "detected_anomalies.xlsx"

    df.to_excel(output_file, index=False)

    print(f"\n[INFO] {len(df)} anomalies saved to {output_file}")

except Exception as e:
    print(f"[ERROR] Excel Export: {e}")

# Generate Visualization
plt.figure(figsize=(8, 5))

df["type"].value_counts().plot(kind="bar")

plt.title("Security Anomalies Detected")
plt.xlabel("Anomaly Type")
plt.ylabel("Count")
plt.xticks(rotation=45)

plt.tight_layout()

plt.savefig("anomaly_report.png")

print("[INFO] Chart saved as anomaly_report.png")

plt.show()
