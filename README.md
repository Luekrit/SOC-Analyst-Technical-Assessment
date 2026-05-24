# SOC Analyst Technical Assessment: SIEM Alert Investigation & Incident Report

## Overview
This project demonstrates an end-to-end SOC analyst investigation workflow, covering alert triage, log analysis, threat hunting, MITRE ATT&CK mapping, incident response, business impact assessment, and executive reporting.

## Scenario
A simulated SIEM alert was investigated for suspicious authentication activity, possible credential compromise, and lateral movement indicators.

## Completed Case Study: Azure SOC Failed Logon Investigation

This repository includes a completed SOC case study based on my Azure Security Operations & Threat Detection lab.

The case study investigates failed authentication activity against an internet-facing Windows virtual machine in Azure. The investigation demonstrates how Windows Security Events can be collected into Log Analytics, reviewed using KQL, enriched with source IP context, mapped to MITRE ATT&CK, and documented using a structured SOC analyst workflow.

**Case Study:** [Azure SOC Failed Logon Investigation](case-studies/case-study-01-azure-soc-failed-logon-investigation.md)

### Case Study Focus Areas

- Microsoft Sentinel / Log Analytics investigation workflow
- Windows Security Event ID 4625 analysis
- Failed logon pattern review
- Source IP and geographic context analysis
- MITRE ATT&CK mapping
- SOC analyst triage and reporting
- Containment and remediation recommendations

> Note: This case study is based on lab-generated security telemetry. No real company logs, customer data, or sensitive information are included.

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
