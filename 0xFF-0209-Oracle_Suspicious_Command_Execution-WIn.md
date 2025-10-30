# Oracle Suspicious Command Execution

## Metadata
**ID:** 0xFF-0209-Oracle_Suspicious_Command_Execution-WIn

**OS:** WindowsEndpoint, WindowsServer

---

## ATT&CK Tags

| Tactic | Technique | Subtechnique | Technique Name |
|---|---|---| --- |
| TA0008 - Lateral Movement | T1210 |  | Exploitation of Remote Services|
| TA0004 - Privilege Escalation | T1611 |  | Escape to Host|

## Utilized Data Sources

| Log Provider | Table Name | Event ID | Event Name | ATT&CK Data Source | ATT&CK Data Component|
|---------|---------|---------|----------|---------|---------|
|MicrosoftThreatProtection|DeviceProcessEvents|ProcessCreated||Process|Process Creation|
---

## Detection description
This query searches process creation events that are indicative of an attacker spawning OS commands from an Oracle database.



## Permission required to execute the technique
User


## Description of the attack
Attackers can use database systems such as Oracle to laterally move through the network by using command execution functionality in these databases.


## Considerations
None.


## False Positives
Some legitimate Oracle plugins will also perform command execution. Such plugins will have to be filtered.


## Suggested Response Actions
Verify whether legitimate business or operational reasons exist for the user account to execute commands from the database workspace.

In case of a suspected breach or insider threat:
* Review the latest activities performed by the account that executed the commands to validate its roles and permissions for signs of compromise.
* Investigate the relationship of the Oracle process that performed the suspicious command with its parent, including executable names, command-line arguments and execution paths, and consider isolating any compromised hosts.


## Detection Blind Spots
None expected.


## References
* https://github.com/0xdea/exploits/blob/master/oracle/raptor_oraexec.sql

---
## Detection

**Language:** Kusto

**Platform:** M365 Security

**Query:**
```C#
let timeframe = 2*1h;
DeviceProcessEvents
| where ingestion_time() >= ago(timeframe)
| where ActionType =~ "ProcessCreated"
| where InitiatingProcessFileName =~ "oracle.exe"
| where not(FileName in~ ("conhost.exe", "oradim.exe"))
| where not(FileName =~ "WerFault.exe" and ProcessCommandLine contains tostring(InitiatingProcessId))
// Begin environment-specific filter.
// End environment-specific filter.
```

---

## Version History
| Version | Date | Impact | Notes |
|---------|------|--------|------|
| 1.4  | 2025-05-20| minor | Enhanced response plan actions. |
| 1.3  | 2024-06-06| minor | Added a filter for "ProcessCreated" actiontype, as MDE is rolling out other actiontypes as well. |
| 1.2  | 2022-02-22| minor | Use ingestion_time for event selection and include de-duplication logic. |
| 1.1  | 2022-01-18| minor | Added werfault to filter. |
| 1.0  | 2021-11-09| major | Initial version. |