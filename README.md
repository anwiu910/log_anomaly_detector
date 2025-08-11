## **Log Anomaly Detector for Security Threats**

A Python-based tool to detect and visualize suspicious activities from  web server logs, such as failed logins, brute force attempts, SQL injection, and XSS attacks. 
The detected anomalies are stored in a MySQL database, and a graph of the detected threats is generated for quick insights.

## **Features**
- **Log Parsing** – Reads HTTP access logs and extracts relevant information.

- **Threat Detection** – Identifies:

  - Failed password attempts

  - Invalid user logins

  - Brute force login attempts

  - SQL injection payloads

  - Cross-Site Scripting (XSS) attempts

- **Database Storage** – Saves anomalies into MySQL for further analysis.

- **Visualization** – Generates a bar chart showing counts of each attack type.

- **Extensible** – Easily add new detection rules.


## **Tech Stack**
- **Language**: Python 3

- **Database**: MySQL

- **Libraries**:

  - pandas – for data processing

  - matplotlib – for visualization

- **mysql-connector-python** – for database operations

- **re** – for regex-based detection patterns
