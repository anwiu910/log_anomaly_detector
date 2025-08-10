import re
import pandas as pd
import matplotlib.pyplot as plt
import mysql.connector
from datetime import datetime
from config import DB_CONFIG

# Path to your log file
log_path = "logs/access.log"

# Regex patterns for security anomalies
patterns = {
    "Failed Password": r"Failed password",
    "Invalid User": r"Invalid user",
    "SQL Injection": r"(\%27)|(\')|(\-\-)|(\%23)|(#)|(\%3D)|(=)|(\bunion\b)|(\bselect\b)",
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
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),  # detection timestamp
                "log": line.strip(),
                "type": anomaly_type
            })

# Convert to DataFrame
df = pd.DataFrame(anomalies)

# If no anomalies, exit
if df.empty:
    print("[INFO] No anomalies detected.")
    exit()

# Print detected anomalies
print("\n[INFO] Detected Anomalies:\n")
print(df.to_string(index=False))

# Visualization: Count anomalies by type
plt.figure(figsize=(8, 5))
df["type"].value_counts().plot(kind="bar", color="orange")
plt.title("Security Anomalies Detected")
plt.xlabel("Anomaly Type")
plt.ylabel("Count")
plt.xticks(rotation=45)
plt.tight_layout()
plt.show()

# Save anomalies to MySQL
try:
    conn = mysql.connector.connect(**DB_CONFIG)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS anomalies (
            id INT AUTO_INCREMENT PRIMARY KEY,
            timestamp DATETIME,
            log TEXT,
            type VARCHAR(50)
        )
    """)

    for _, row in df.iterrows():
        cursor.execute(
            "INSERT INTO anomalies (timestamp, log, type) VALUES (%s, %s, %s)",
            (row["timestamp"], row["log"], row["type"])
        )

    conn.commit()
    print(f"\n[INFO] {len(df)} anomalies saved to MySQL.")

except mysql.connector.Error as err:
    print(f"[ERROR] MySQL: {err}")
finally:
    if 'conn' in locals() and conn.is_connected():
        cursor.close()
        conn.close()
