
# Case Study 01: Suspicious RDP Login Investigation

## Data Notice

This case study uses simulated lab data for learning and portfolio demonstration purposes. No real company logs, customer data, or sensitive information are included.

## Alert Summary

| Field | Details |
|---|---|
| Alert Name | Multiple Failed RDP Logins Followed by Successful Login |
| Severity | High |
| Classification | True Positive |
| Affected Host | WIN10-LAB-01 |
| User Account | test.user |
| Source IP | 203.0.113.45 |
| Timeframe | 2026-05-24 09:10–09:25 UTC |

## Investigation Summary

The SIEM alert triggered after multiple failed RDP login attempts were followed by a successful login from the same external IP address. Windows authentication logs were reviewed to validate the failed and successful login events. The successful login occurred from an unusual source IP and was followed by suspicious PowerShell execution.

Based on the sequence of events, this activity was assessed as a likely credential-based intrusion attempt.

## Evidence Reviewed

| Evidence Source | Event / Indicator | Analyst Finding |
|---|---|---|
| Windows Security Logs | Event ID 4625 | Multiple failed login attempts from the same source IP |
| Windows Security Logs | Event ID 4624 | Successful RDP login after failed attempts |
| Windows Process Logs | Event ID 4688 | PowerShell execution shortly after login |
| Firewall Logs | TCP/3389 | External RDP connection from suspicious IP |

## Simulated Log Snippet

```text
2026-05-24T09:10:14Z EventID=4625 Account=test.user SourceIP=203.0.113.45 Host=WIN10-LAB-01 LogonType=10 Status=Failed Login
2026-05-24T09:11:03Z EventID=4625 Account=test.user SourceIP=203.0.113.45 Host=WIN10-LAB-01 LogonType=10 Status=Failed Login
2026-05-24T09:14:22Z EventID=4624 Account=test.user SourceIP=203.0.113.45 Host=WIN10-LAB-01 LogonType=10 Status=Successful Login
2026-05-24T09:16:40Z EventID=4688 Account=test.user Host=WIN10-LAB-01 Process=powershell.exe Parent=explorer.exe CommandLine="powershell -enc <redacted>"
```

## Timeline of Events

| Time UTC | Event |
|---|---|
| 09:10 | Failed RDP login detected |
| 09:11 | Additional failed login attempt from same IP |
| 09:14 | Successful RDP login observed |
| 09:16 | PowerShell process executed |
| 09:20 | Alert escalated for investigation |
| 09:25 | Containment actions recommended |

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|---|---|---|---|
| Initial Access | Valid Accounts | T1078 | Successful login using user credentials |
| Lateral Movement | Remote Services: RDP | T1021.001 | RDP login from external IP |
| Execution | PowerShell | T1059.001 | PowerShell process execution |
| Discovery | System Information Discovery | T1082 | Suspicious post-login activity |

## Determination

**Classification:** True Positive

The alert was classified as a true positive because the login pattern showed repeated failed authentication attempts followed by a successful RDP login from the same external IP. The activity was suspicious because the source IP was not associated with normal user behaviour and PowerShell execution occurred shortly after login.

## Containment Actions

- Disable or lock the affected user account
- Force password reset for the affected user
- Revoke active sessions
- Block the suspicious source IP at the firewall
- Review related RDP activity across other users and hosts
- Check endpoint telemetry for persistence or malware activity

## Recommendations

- Enforce MFA for remote access
- Restrict RDP exposure to trusted VPN or internal networks
- Tune SIEM detection for failed logins followed by success
- Monitor PowerShell execution after remote logins
- Review privileged account access and least privilege controls

## Executive Summary

A simulated SOC investigation was performed for suspicious RDP authentication activity. The investigation identified multiple failed login attempts followed by a successful login from the same external IP address. PowerShell execution shortly after login increased the likelihood of malicious activity.

The incident was assessed as a true positive credential-based intrusion attempt. Recommended actions include account containment, password reset, session revocation, source IP blocking, MFA enforcement, and further threat hunting across authentication logs.
