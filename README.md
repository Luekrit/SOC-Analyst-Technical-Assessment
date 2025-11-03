# 🧩 SOC Analyst Technical Assessment (Learning Template)

## 📘 Overview
This project demonstrates my ability to perform end-to-end SOC analysis — from SIEM alert triage and log correlation to MITRE ATT&CK mapping and incident response reporting.  
The assessment simulates a **ransomware attack** delivered through a phishing campaign, requiring log analysis, threat hunting, and response planning.

---

## 🧠 Step 1 – SIEM Alert Analysis
Analyzed 5 alerts to identify true vs false positives:
- **Brute Force Attack (Critical)** – multiple failed DB logins from 203.0.113.42  
- **Phishing Email Malware Detection (High)** – malicious emails from `supplierxyz-invoices.com`  
- Applied prioritization to focus on high-impact events.

---

## 🕵️ Step 2 – Log Analysis & Threat Hunting
- Detected **RDP connection from external IP (198.51.100.73)** using compromised credentials.  
- Observed **Mimikatz execution** for privilege escalation (`SeDebugPrivilege`).  
- Correlated events across **Firewall, Windows, and EDR logs** to trace lateral movement and data exfiltration.

---

## ⚙️ MITRE ATT&CK Mapping

| Stage | Technique | Description |
|--------|------------|-------------|
| Initial Access | T1078 | Valid Accounts (RDP login) |
| Execution | T1059 | Command-Line Execution |
| Privilege Escalation | T1068 | Exploitation of Privilege Escalation |
| Credential Access | T1003 | Credential Dumping (Mimikatz) |
| Lateral Movement | T1021 | Remote Services (SMB) |
| Exfiltration | T1048 | Exfiltration Over Alternative Protocol |

---

## 🚨 Step 3 – Incident Response
- Contained the spread by **disabling SMB traffic** and isolating infected hosts.  
- Identified **IOCs:** `.locked` file extension, `invoice_payment.pdf.exe` payload, `.onion` URLs.  
- Recommended **account disablement, password resets, and MFA enforcement.**

---

## 🧾 Step 4 – Executive Summary
At 04:30 AM, multiple employees reported file access issues.  
Investigation confirmed a **ransomware attack via phishing email** leading to SMB propagation and encryption.  
Immediate containment actions were taken, and long-term improvements such as **EDR deployment, phishing awareness, and network segmentation** were proposed.

---

## 🧩 Tools & Skills Demonstrated
- **SIEM Log Analysis**
- **Threat Hunting & Correlation**
- **Incident Response Reporting**
- **MITRE ATT&CK Mapping**
- **Ransomware Analysis**
- **Technical Documentation**

---

## 👤 Author
**Luekrit Kongkamon**  
Aspiring Cloud & Cybersecurity Analyst | SOC | IAM | Cloud Security  
[LinkedIn](https://linkedin.com/in/luekritkongkamon) | [GitHub](https://github.com/luekrit)

 *This template is used for learning and documentation purposes to simulate SOC workflows and professional reporting style.*
