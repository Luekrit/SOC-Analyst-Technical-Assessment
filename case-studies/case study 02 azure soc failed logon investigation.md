# Case Study 02: Azure SOC Failed Logon Investigation

## Data Notice

This case study is based on lab-generated security telemetry from an Azure SOC lab environment. No real company logs, customer data, or sensitive information are included.

## Scenario

A Windows virtual machine was deployed in Microsoft Azure and exposed to the internet as a controlled honeypot-style lab environment. Windows Security Events were collected and forwarded into Log Analytics for investigation.

The purpose of this case study is to demonstrate how a SOC analyst can investigate failed authentication activity using Microsoft Sentinel / Log Analytics, KQL queries, Windows Security Event IDs, MITRE ATT&CK mapping, and structured incident reporting.

---

## Alert Summary

| Field | Details |
|---|---|
| Alert Name | Multiple Failed Logon Attempts Against Azure VM |
| Environment | Azure SOC Lab |
| Data Source | Windows Security Events |
| SIEM / Log Platform | Microsoft Sentinel / Log Analytics |
| Primary Event ID | 4625 |
| Severity | Medium |
| Initial Classification | Suspicious Activity |
| Final Classification | True Positive - Suspicious Authentication Activity |
| Affected Asset | Azure Windows VM |
| Data Type | Lab-generated telemetry |

---

## Investigation Objective

The objective of this investigation was to determine whether repeated failed logon attempts against the Azure Windows VM represented normal background internet noise, brute-force behaviour, password spraying, or a potential credential attack requiring defensive action.

The investigation focused on:

- Identifying repeated failed logon attempts
- Reviewing source IP activity
- Understanding authentication patterns
- Validating the activity through centralized logs
- Mapping the behaviour to MITRE ATT&CK
- Recommending defensive controls

---

## Investigation Summary

The investigation identified failed logon attempts against an internet-facing Azure Windows VM. Authentication logs were collected through Windows Security Events and reviewed in Log Analytics using KQL.

Event ID 4625 showed failed authentication attempts from external source IP addresses. The pattern was consistent with opportunistic scanning or brute-force activity commonly seen against exposed internet-facing systems.

No successful unauthorized logon was confirmed in this case study. However, the repeated failed logon activity was treated as suspicious and required hardening recommendations, including reducing public exposure, enforcing MFA where applicable, and improving detection logic.

---

## Evidence Reviewed

| Evidence Source | Event / Indicator | Analyst Finding |
|---|---|---|
| Windows Security Logs | Event ID 4625 | Failed logon attempts observed against the Azure VM |
| Log Analytics | Authentication query results | Multiple failed logons were visible in centralized logs |
| Source IP Data | External IP addresses | Failed attempts originated from external internet sources |
| GeoIP / Location Context | Country or region enrichment | Source activity may indicate opportunistic scanning or brute-force attempts |
| Sentinel Workbook / Visualization | Attack map or logon visualization | Failed logon activity was visualized for investigation and reporting |

---

## Key Windows Event ID

### Event ID 4625 - Failed Logon

Windows Security Event ID 4625 indicates that an account failed to log on successfully. In a SOC investigation, repeated 4625 events can indicate:

- Brute-force attempts
- Password spraying
- Credential stuffing
- Misconfigured services
- Unauthorized access attempts
- Internet scanning against exposed services

In this lab, Event ID 4625 was used as the main detection point for suspicious authentication activity.

---

## KQL Queries Used

### Query 1: Review Failed Logon Events

```kusto
SecurityEvent
| where EventID == 4625
| project TimeGenerated, Account, Computer, IpAddress, LogonType, Activity
| order by TimeGenerated desc
```

### Query 2: Failed Logons by Source IP

```kusto
SecurityEvent
| where EventID == 4625
| summarize FailedLogonCount = count() by IpAddress
| order by FailedLogonCount desc
```

### Query 3: Failed Logons Over Time

```kusto
SecurityEvent
| where EventID == 4625
| summarize FailedLogons = count() by bin(TimeGenerated, 1h)
| order by TimeGenerated asc
```

---

## Timeline of Events

| Time UTC | Event |
|---|---|
| 00:00 | Azure Windows VM available to the internet |
| 00:15 | Failed logon attempts begin appearing in Windows Security logs |
| 00:30 | Logs forwarded into Log Analytics |
| 00:45 | KQL query used to review Event ID 4625 activity |
| 01:00 | Source IP patterns reviewed |
| 01:15 | Activity mapped to MITRE ATT&CK |
| 01:30 | Defensive recommendations documented |

> Note: Timeline values are simplified for portfolio documentation and represent the investigation flow rather than a real corporate incident timeline.

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|---|---|---|---|
| Credential Access | Brute Force | T1110 | Repeated failed logon attempts observed through Event ID 4625 |
| Initial Access | Valid Accounts | T1078 | Attempted use of credentials against exposed system |
| Discovery | Network Service Discovery | T1046 | External sources interacting with exposed remote access service |
| Reconnaissance | Active Scanning | T1595 | Internet-based probing against public-facing infrastructure |

---

## Determination

**Classification:** True Positive - Suspicious Authentication Activity

The activity was classified as a true positive because failed logon attempts were confirmed in Windows Security Events and were visible in centralized logging. Although no confirmed successful compromise was identified, the activity represented suspicious authentication behaviour against an internet-facing cloud asset.

This type of activity should be investigated because repeated failed logons can indicate brute-force attempts, password spraying, credential stuffing, or automated scanning.

---

## Recommended Response Actions

- Review whether the VM requires direct internet exposure
- Restrict remote access to trusted IP ranges or VPN
- Disable public RDP exposure where possible
- Enforce MFA for remote access paths
- Apply strong password and account lockout policies
- Monitor Event ID 4625 trends over time
- Create SIEM alerts for repeated failed logons from the same source IP
- Review successful logons after repeated failures
- Investigate high-volume source IPs for threat intelligence context

---

## Detection Improvement Opportunities

Recommended detection logic:

- Alert when one source IP generates excessive failed logons
- Alert when one account receives failed logons from multiple IPs
- Alert when failed logons are followed by a successful logon
- Alert when administrative accounts receive failed logon attempts
- Alert when failed logons occur outside expected access patterns

### Example Detection Logic

```kusto
SecurityEvent
| where EventID == 4625
| summarize FailedAttempts = count() by IpAddress, bin(TimeGenerated, 15m)
| where FailedAttempts > 10
| order by FailedAttempts desc
```

---

## Business Impact Assessment

| Area | Assessment |
|---|---|
| Confidentiality | No confirmed data exposure |
| Integrity | No confirmed unauthorized changes |
| Availability | No service disruption confirmed |
| Risk Level | Medium |
| Main Concern | Exposed remote access may attract brute-force attempts |

Although this was a lab environment, the same pattern in a production environment could indicate increased risk of credential compromise, unauthorized access, and lateral movement if remote access is not properly secured.

---

## Executive Summary

A SOC-style investigation was performed against failed authentication activity in an Azure lab environment. Windows Security Event ID 4625 logs showed failed logon attempts against an internet-facing Windows VM. The activity was reviewed using Log Analytics and KQL to identify suspicious authentication patterns.

The investigation determined that the activity represented suspicious authentication behaviour consistent with opportunistic brute-force or scanning attempts. No confirmed successful compromise was identified, but the findings highlight the importance of restricting public remote access, monitoring failed logons, enforcing MFA, and improving SIEM alerting for authentication anomalies.

---

## Lessons Learned

This case study reinforced the importance of:

- Centralized log collection
- KQL-based investigation
- Authentication monitoring
- Public cloud attack surface reduction
- MITRE ATT&CK mapping
- Clear SOC reporting

---

## Related Project

This case study is based on my related Azure SOC lab:

**Azure Security Operations & Threat Detection**  
Repository: [https://github.com/Luekrit/Azure-Security-Operations-Threat-Detection](https://github.com/Luekrit/Azure-Security-Operations-Threat-Detection)

---

## Analyst Reflection

This case study helped demonstrate how failed authentication activity can be investigated in a SOC workflow using cloud-based logging and SIEM tools. Even without confirmed compromise, repeated failed logons against an internet-facing asset are valuable signals for detecting brute-force attempts, exposed services, and weak access control design.

The key takeaway is that SOC analysis is not only about confirming compromise. It is also about identifying risky patterns early, validating them with evidence, and recommending practical controls that reduce future attack surface.
