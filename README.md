# Mini SIEM: Security Log Monitoring & Threat Detection Dashboard

This project is a lightweight Security Information and Event Management (SIEM) platform built using Python, SQL, and HTML.

The system ingests system logs, detects suspicious behaviour, and generates security alerts through a monitoring dashboard.

It simulates core features of enterprise SIEM tools such as Splunk and Microsoft Sentinel.

---

## Features

- Log ingestion and parsing
- Security event storage
- Threat detection engine
- Alert generation
- Monitoring dashboard

---

## Implemented Security Detections

- Brute force login attempts
- Password spraying attacks
- Suspicious IP behaviour
- Impossible travel login detection
- High request rate detection (DoS pattern)

---

## Tech Stack

Python – detection engine and log parser  
Flask – web server for dashboard  
SQLite – event and alert database  
HTML – dashboard interface  

---

## How to Run the Project

1. Download the project from GitHub

You can either clone the repository using Git:

git clone https://github.com/Advaith-Ganesh/mini-siem-security-monitor

Or download the ZIP file from GitHub and extract it.

2. Navigate into the project folder

cd mini-siem-security-monitor

3. Install the required Python packages

pip install -r requirements.txt

4. Start the SIEM server

python app.py

5. Open the dashboard

Open your browser and go to:



You can now upload log files and observe how the system detects suspicious activity and generates alerts.
