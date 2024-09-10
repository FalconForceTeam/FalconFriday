# Password spraying attack detected

## Metadata
**ID:** 0xFF-0044-Password_spraying_attack_detected-Win

**OS:** WindowsServer

**FP Rate:** Medium

---

## ATT&CK Tags

| Tactic | Technique | Subtechnique | Technique Name |
|---|---|---| --- |
| TA0006 - Credential Access | T1110 | 003 | Brute Force - Password Spraying|

## Utilized Data Sources

| Log Provider | Event ID | Event Name | ATT&CK Data Source | ATT&CK Data Component|
|---------|---------|----------|---------|---------|
|MicrosoftThreatProtection|LogonSuccess||Logon Session|Logon Session Creation|
|MicrosoftThreatProtection|LogonSuccess||Logon Session|Logon Session Creation|
|MicrosoftThreatProtection|||||
---

## Technical description of the attack
This query searches for failed logins from a single source towards multiple different accounts.


## Permission required to execute the technique
User

## Detection description
A password spraying attack is detected, where a single machine has performed a large number of failed login attempts, with a large number of different accounts. For each account, the attacker uses just a few attempts to prevent account lockout.


## Considerations
None.


## False Positives
Some false positives can occur when users log in to many different systems and accidentally enter an incorrect password.


## Suggested Response Actions
Investigate why the machine has performed so many failed login attempts with so many different accounts. If the DeviceName field contains an IP address, the machine performing the password spray isn't DATP enrolled.


## Detection Blind Spots
None.


## References
* https://attack.mitre.org/techniques/T1110/003/

---
## Detection

**Language:** Kusto

**Platform:** M365 Security

**Query:**
```C#
let timeframe = 2*1d;
let domaincontrollers =(
  DeviceNetworkEvents
  | where ActionType == "InboundConnectionAccepted"
  | where InitiatingProcessFileName =~ "lsass.exe"
  | where LocalPort == 88
  | distinct DeviceName
);
let thresholdForUniqueFailedAccounts = 20;
let upperBoundOfFailedLogonsPerAccount = 3;
let ratioSuccessFailedLogons = 2;
IdentityLogonEvents
| where ingestion_time() >= ago(timeframe)
| summarize SuccessLogonCount = countif(ActionType =~ "LogonSuccess"), FailedLogonCount = countif(ActionType =~ "LogonFailed"),
    UniqueAccountFailedLogons=dcountif(AccountUpn, ActionType =~ "LogonFailed"), FailedAccounts=make_set_if(AccountUpn, ActionType =~ "LogonFailed"),
    SuccessAccounts=make_set_if(AccountUpn, ActionType =~ "LogonSuccess"), FirstFailed=minif(Timestamp, ActionType =~ "LogonFailed"),
    LastFailed=maxif(Timestamp, ActionType =~ "LogonFailed"), LastTimestamp=arg_max(Timestamp, tostring(ReportId)) by IPAddress, DeviceName // IPAddress is here the "remote IP", i.e., the source of the logon attempt.
| where UniqueAccountFailedLogons > thresholdForUniqueFailedAccounts and SuccessLogonCount*ratioSuccessFailedLogons < FailedLogonCount and UniqueAccountFailedLogons*upperBoundOfFailedLogonsPerAccount > FailedLogonCount //more than 3 tries per account is not a password spray anymore
| union (
    DeviceLogonEvents
    | where ingestion_time() >= ago(timeframe)
    | where LogonType != "Unlock" and ActionType in~ ("LogonSuccess", "LogonFailed")
    | where not(isempty( RemoteIP) and isempty( RemoteDeviceName))
    | extend LocalLogon=parse_json(AdditionalFields)
    | where RemoteIPType != "Loopback"
    | summarize SuccessLogonCount = countif(ActionType =~ "LogonSuccess"), FailedLogonCount = countif(ActionType =~ "LogonFailed"),
        UniqueAccountFailedLogons=dcountif(AccountName, ActionType =~ "LogonFailed"), FirstFailed=minif(Timestamp, ActionType =~ "LogonFailed"),
        LastFailed=maxif(Timestamp, ActionType =~ "LogonFailed"), LastTimestamp=arg_max(Timestamp, tostring(ReportId)) by RemoteIP, DeviceName, DeviceId // RemoteIP is here the source of the logon attempt.
    | project-rename IPAddress=RemoteIP
    | where UniqueAccountFailedLogons > thresholdForUniqueFailedAccounts and SuccessLogonCount*ratioSuccessFailedLogons < FailedLogonCount and UniqueAccountFailedLogons*upperBoundOfFailedLogonsPerAccount > FailedLogonCount //more than 3 tries per account is not a password spray anymore
)
| extend IsDC=(DeviceName in~ ((domaincontrollers | project DeviceName)))
| where IsDC == false
| extend Timestamp=LastFailed
| project-reorder Timestamp
// Begin environment-specific filter.
// End environment-specific filter.
```

---

## Version History
| Version | Date | Impact | Notes |
|---------|------|--------|------|
| 1.2  | 2023-02-14| minor | Updated the query to fix KQL parsing warnings. |
| 1.1  | 2022-02-22| minor | Use ingestion_time for event selection and include de-duplication logic. |
| 1.0  | 2021-02-25| major | Initial version. |