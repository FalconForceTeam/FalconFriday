# Persistence Via Scheduled Tasks

## Metadata
**ID:** 0xFF-0082-Persistence-Via-Scheduled-Tasks-Win

**OS:** WindowsServer, WindowsEndpoint

**FP Rate:** High

---

## ATT&CK Tags

| Tactic | Technique | Subtechnique | Technique Name |
|---|---|---| --- |
| TA0004 - Privilege Escalation | T1053 | 005 | Scheduled Task/Job - Scheduled Task|
| TA0003 - Persistence | T1053 | 005 | Scheduled Task/Job - Scheduled Task|
| TA0002 - Execution | T1053 | 005 | Scheduled Task/Job - Scheduled Task|

## Utilized Data Sources

| Log Provider | Event ID | Event Name | ATT&CK Data Source | ATT&CK Data Component|
|---------|---------|----------|---------|---------|
|MicrosoftThreatProtection|ProcessCreated||Command|Command Execution|
---

## Technical description of the attack
This query identifies binaries that run as a scheduled task, by looking at the parent process command line. Of the identified binaries running as scheduled tasks it finds suspicious binaries by looking at the file signature and global prevalence.


## Permission required to execute the technique
User

## Detection description
Attackers can use scheduled tasks as a method for persistence.


## Considerations
Since Defender for Endpoint does not log the executable of scheduled tasks when they are updated,
the scheduled tasks have to be identified when they are executed rather than when they are scheduled.


## False Positives
Some legitimate software also uses scheduled tasks, for example, for downloading periodic updates. If the software is unsigned or has a low global prevalence this might cause false positives.


## Suggested Response Actions
Investigate whether the scheduled task is part of legitimate software in use on the system.


## Detection Blind Spots
If an attacker uses a LOLBIN or another high-prevalence binary as an intermediate this can be used to bypass detection.


## References
* https://medium.com/falconforce/malicious-scheduled-tasks-debc64633f81

---
## Detection

**Language:** Kusto

**Platform:** M365 Security

**Query:**
```C#
let timeframe = 2*1d;
let default_global_prevalence = 0;
// Time to look back for same scheduled binary.
let lookback= 7d;
let ScheduledBinaries = (
    DeviceProcessEvents
    | where Timestamp >= ago(lookback)
    | where ActionType =~ "ProcessCreated"
    | where InitiatingProcessCommandLine startswith "svchost.exe -k netsvcs -p" and InitiatingProcessCommandLine contains "Schedule" // First argument after -p is censored with ** so can't look for the actual command line
);
let NewScheduledBinaries=(
    ScheduledBinaries
    | where Timestamp >= ago(lookback)
    | summarize FirstSeen=min(Timestamp),LastSeen=max(Timestamp) by DeviceId, SHA1
    | where LastSeen >= ago(timeframe)
    | where FirstSeen >= ago(timeframe)
);
let NewScheduledBinaryExecution=(
    ScheduledBinaries
    | where ingestion_time() >= ago(timeframe)
    | lookup kind=inner NewScheduledBinaries on DeviceId, SHA1
);
NewScheduledBinaryExecution
| summarize MachineCount=dcount(DeviceId) by SHA1
// Find the max 1000 least used binaries.
| top 1000 by MachineCount asc
// FileProfile is case-sensitive and works on lower-case hashes.
| extend SHA1=tolower(SHA1)
| invoke FileProfile(SHA1,1000)
| where not(ProfileAvailability =~ "Error")
| where coalesce(GlobalPrevalence,default_global_prevalence) < 100
| join NewScheduledBinaryExecution on SHA1
| summarize arg_max(Timestamp, *), Devices=make_set(DeviceName), MachineCount=dcount(DeviceName) by SHA1 // Gives the last execution with all details per SHA1.
// Begin environment-specific filter.
// End environment-specific filter.
```

---

## Version History
| Version | Date | Impact | Notes |
|---------|------|--------|------|
| 1.8  | 2024-06-28| minor | Modified the usage of FileProfile to exclude results if the call to the FileProfile API has failed. |
| 1.7  | 2024-06-06| minor | Added a filter for "ProcessCreated" actiontype, as MDE is rolling out other actiontypes as well. |
| 1.6  | 2023-01-03| minor | Lowered the case of hashes that are fed to the FileProfile function due to case sensitivity. |
| 1.5  | 2022-11-01| minor | Use default_global_prevalence variable to allow customizing handling of empty GlobalPrevalence |
| 1.4  | 2022-02-22| minor | Use ingestion_time for event selection and include de-duplication logic. |
| 1.3  | 2022-02-07| minor | Update InitiatingProcessCommandLine to work around issues with censoring passwords. |
| 1.2  | 2021-04-23| minor | Added lookback to only alert on new scheduled tasks. |
| 1.1  | 2021-03-22| minor | Avoid using DeviceFileCertificateInfo to speed up the query. |
| 1.0  | 2021-03-22| major | Initial version. |