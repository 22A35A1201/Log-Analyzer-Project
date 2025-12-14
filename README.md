📊 Log Analyzer Project (Python)
📌 Project Overview

The Log Analyzer Project is a Python-based solution designed to analyze system and security log files and extract meaningful insights. The project processes authentication-related log data to identify failed login attempts, generate structured reports, and create visual representations that support security monitoring and analysis.

🎯 Objectives

Analyze log files to identify authentication activity

Detect and summarize failed login attempts

Generate structured security reports in CSV format

Visualize authentication failure trends using graphs

Apply practical log analysis concepts using Python

🛠️ Technologies Used

Python

File Handling

Regular Expressions

CSV Report Generation

Matplotlib for Data Visualization

📂 Project Structure
Log-Analyzer-Project/
├── log_analyzer.py
├── sample_logs.txt
├── security_report.csv
├── failed_login_graph.png
└── README.md

📄 Input Data

sample_logs.txt
Contains raw log entries with details such as timestamps, user identifiers, and authentication status. These logs are used as the input data for analysis.

⚙️ Working of the Project

The Python script reads the log file and processes each entry line by line.

Log patterns are analyzed to extract authentication-related information.

Failed login attempts are identified and aggregated.

The analyzed data is exported into a structured CSV report.

A graphical representation of failed login activity is generated for better visualization.

✨ Key Features

Security-focused log analysis

Detection and aggregation of failed login attempts

Automated CSV report generation

Visual insights through graphs

Simple and efficient execution workflow

▶️ How to Run the Project

Clone the repository:

git clone <your-github-repository-link>


Navigate to the project directory:

cd Log-Analyzer-Project


Run the Python script:

python log_analyzer.py

📊 Output Files

security_report.csv – Structured summary of failed login attempts

failed_login_graph.png – Graphical visualization of authentication failure trends

🧠 Learning Outcomes

Practical understanding of log and security data analysis

Experience in parsing real-world log files

Report generation using CSV format

Data visualization using Python

Analytical thinking and problem-solving skills

🚀 Scope for Enhancement

Support for additional log formats

Time-based trend analysis

Advanced alerting mechanisms

Enhanced reporting capabilities
