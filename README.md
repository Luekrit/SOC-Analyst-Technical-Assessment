# SOC Analyst Technical Assessment: SIEM Alert Investigation & Incident Report

## Overview
This project demonstrates an end-to-end SOC analyst investigation workflow, covering alert triage, log analysis, threat hunting, MITRE ATT&CK mapping, incident response, business impact assessment, and executive reporting.

## Scenario
A simulated SIEM alert was investigated for suspicious authentication activity, possible credential compromise, and lateral movement indicators.

## Completed Case Studies

This repository includes completed SOC-style case studies that demonstrate alert triage, log analysis, MITRE ATT&CK mapping, incident response thinking, and analyst reporting.

### Case Study 01: Suspicious RDP Login Investigation

A simulated SOC investigation involving multiple failed RDP logins followed by a successful login from the same external IP address. The case study demonstrates authentication analysis, true positive classification, MITRE ATT&CK mapping, and containment recommendations.

**Case Study:** [Suspicious RDP Login Investigation](case-studies/case-study-01-suspicious-rdp-login.md)

### Case Study 02: Azure SOC Failed Logon Investigation

A lab-based SOC investigation using telemetry from my Azure Security Operations & Threat Detection lab. This case study focuses on Windows Security Event ID 4625, failed logon analysis, Microsoft Sentinel / Log Analytics investigation workflow, KQL queries, source IP review, MITRE ATT&CK mapping, and defensive recommendations.

**Case Study:** [Azure SOC Failed Logon Investigation](case-studies/case-study-02-azure-soc-failed-logon-investigation.md)

> Note: These case studies use simulated or lab-generated security telemetry for portfolio demonstration purposes. No real company logs, customer data, or sensitive information are included.

## Tools & Skills Demonstrated
- SIEM alert triage
- Windows Event Log analysis
- MITRE ATT&CK mapping
- IOC documentation
- Incident timeline creation
- Containment and remediation planning
- Executive incident reporting

## Investigation Workflow
1. Alert triage
2. Log correlation
3. Threat hunting
4. MITRE ATT&CK mapping
5. Incident response actions
6. Business impact assessment
7. Executive summary
8. Evidence documentation

## Key Deliverables
- SIEM alert analysis template
- Incident response report structure
- MITRE ATT&CK mapping table
- IOC tracking table
- Evidence and screenshot reference section
- Executive summary format

## Why This Project Matters
This project shows my ability to investigate alerts in a structured way, validate suspicious activity using logs, map attacker behaviour to MITRE ATT&CK, and communicate findings to both technical and non-technical stakeholders.

## Related Hands-On SOC Lab

This SOC assessment is supported by a related hands-on Azure security operations lab.

In that lab, I deployed a Windows VM honeypot in Microsoft Azure, collected Windows Security Events using Azure Monitor Agent, forwarded logs into Log Analytics Workspace, investigated failed logon activity using KQL, enriched source IPs with GeoIP data, and visualized attack origins using a Microsoft Sentinel Workbook.

**Related Project:** Azure Security Operations & Threat Detection Lab  
**Focus Areas:** Microsoft Sentinel, KQL, Windows Event Logs, Event ID 4625, failed login investigation, GeoIP enrichment, attack map visualization.

Repository: https://github.com/Luekrit/Azure-Security-Operations-Threat-Detection
