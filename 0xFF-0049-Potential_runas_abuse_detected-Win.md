# Potential runas abuse detected

## Metadata
**ID:** 0xFF-0049-Potential_runas_abuse_detected-Win

**OS:** WindowsEndpoint, WindowsServer

---

## ATT&CK Tags

| Tactic | Technique | Subtechnique | Technique Name |
|---|---|---| --- |
| TA0004 - Privilege Escalation | T1078 | 002 | Valid Accounts - Domain Accounts|
| TA0004 - Privilege Escalation | T1078 | 003 | Valid Accounts - Local Accounts|

## Utilized Data Sources

| Log Provider | Table Name | Event ID | Event Name | ATT&CK Data Source | ATT&CK Data Component|
|---------|---------|---------|----------|---------|---------|
|MicrosoftThreatProtection|DeviceProcessEvents|ProcessCreated||Process|Process Creation|
|MicrosoftThreatProtection|DeviceLogonEvents|LogonSuccess||Logon Session|Logon Session Creation|
---

## Detection description
This query detects the use of the runas command and checks whether the account used to elevate privileges isn't the user's own admin account. Additionally, it will match this event to the logon events to check whether it has been successful, as well as augment the event with the new SID.



## Permission required to execute the technique
User


## Description of the attack
The runas command might be abused by an attacker to elevate privileges to that of another account for which the credentials have been compromised.


## Considerations
None.


## False Positives
The might be legitimate use-cases for a user using runas to execute a command using a different user.


## Suggested Response Actions
Contact both the source and target users and verify whether they have a legitimate use for using runas. In case the user is not aware of the runas command being used this might be caused by an attacker abusing the user's credentials.


## Detection Blind Spots
Other mechanisms exist to execute a command using the privileges of another user account. This rule only detects the usage of runas.exe.


## References
* https://medium.com/falconforce/falconfriday-e4554e9e6665

---
## Detection

**Language:** Kusto

**Platform:** M365 Security

**Query:**
```C#
let timeframe = 2*1h;
let RunAsProcess=DeviceProcessEvents
    | where ingestion_time() >= ago(timeframe)
    | where ActionType =~ "ProcessCreated"
    | where FileName =~ "runas.exe"
    // De-obfuscate the commandline used.
    | extend CleanProcessCommandLine=parse_command_line(tostring(ProcessCommandLine), "windows")
    | extend ElevatedAccountName=extract("u(ser)?:([a-zA-Z0-9_\\\\]+)",2,tostring(CleanProcessCommandLine))
    // Strip the domain suffix.
    | extend CleanElevatedAccountName= trim("(.*\\\\)",ElevatedAccountName)
    // Begin environment-specific filter 1.
    // End environment-specific filter 1.
;
RunAsProcess
| join kind=leftouter (
    DeviceLogonEvents
    | project-rename CleanElevatedAccountName = AccountName
    ) on CleanElevatedAccountName,DeviceId
| where AccountName !~ CleanElevatedAccountName
| where LogonType != "Unknown"
// Begin environment-specific filter 2.
// End environment-specific filter 2.
| project-rename ElevatedActionType=ActionType1,ElevatedAccountSid=AccountSid1
| project Timestamp,DeviceId,DeviceName,FileName,FolderPath,ProcessCommandLine,SHA256,ProcessIntegrityLevel,AccountDomain,AccountName,AccountSid, LogonId, InitiatingProcessFileName,InitiatingProcessFolderPath,InitiatingProcessCommandLine,ElevatedAccountName,CleanElevatedAccountName,ElevatedActionType,LogonType,ElevatedAccountSid,IsLocalAdmin, ReportId,InitiatingProcessAccountUpn
```

---

## Version History
| Version | Date | Impact | Notes |
|---------|------|--------|------|
| 1.5  | 2024-06-06| minor | Added a filter for "ProcessCreated" actiontype, as MDE is rolling out other actiontypes as well. |
| 1.4  | 2023-02-14| minor | Updated the query to fix KQL parsing warnings. |
| 1.3  | 2022-10-19| minor | Modified regex for extracting the username when the shortend "/u:" commandline parameter is used. |
| 1.2  | 2022-09-05| minor | Use post_filter_1 for post filter. |
| 1.1  | 2022-02-22| minor | Use ingestion_time for event selection and include de-duplication logic. |
| 1.0  | 2021-02-26| major | Initial version. |