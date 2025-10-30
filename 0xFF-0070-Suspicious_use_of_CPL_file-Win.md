# Suspicious use of CPL file

## Metadata
**ID:** 0xFF-0070-Suspicious_use_of_CPL_file-Win

**OS:** WindowsServer, WindowsEndpoint

---

## ATT&CK Tags

| Tactic | Technique | Subtechnique | Technique Name |
|---|---|---| --- |
| TA0005 - Defense Evasion | T1218 | 002 | System Binary Proxy Execution - Control Panel|

## Utilized Data Sources

| Log Provider | Table Name | Event ID | Event Name | ATT&CK Data Source | ATT&CK Data Component|
|---------|---------|---------|----------|---------|---------|
|MicrosoftThreatProtection|DeviceImageLoadEvents|ImageLoaded||Module|Module Load|
---

## Detection description
This query identifies .cpl files being loaded and verifies if the corresponding file is suspicious by looking at the signature and global prevalence.



## Permission required to execute the technique
User


## Description of the attack
Adversaries may abuse control.exe to proxy execution of malicious payloads. .cpl files loaded by control.exe are actually .dll files renamed to .cpl and can execute arbitrary code.


## Considerations
This detection doesn't necessarily look at executions of a .cpl file from control.exe triggered by "double clicking". Any .cpl file loaded is checked for prevalence.


## False Positives
Legitimate custom software might create a control panel item that is unsigned or has a low global prevalence.


## Suggested Response Actions
Verify whether legitimate business or operational reasons require the load of the suspicious .cpl file.

In case of a suspected breach or insider threat:
* Verify the legitimacy of the .cpl file using static/dynamic analysis to determine its origin, intent and payload.
* Review the latest activities performed by the account that initiated the load of the .cpl file and validate the permissions of the compromised account.
* Investigate further execution of the process loading the .cpl file for signs of compromise on the affected machine or the network and consider isolating the compromised hosts.


## Detection Blind Spots
DeviceImageLoad events performs heavy sampling of the telemetry. If MDE doesn't log the image load event, this detection won't trigger.


## References
* https://attack.mitre.org/techniques/T1218/002/
* https://medium.com/falconforce/falconfriday-process-injection-and-malicious-cpl-files-0xff03-8ba1ee5da64

---
## Detection

**Language:** Kusto

**Platform:** M365 Security

**Query:**
```C#
let timeframe = 2*1h;
let default_global_prevalence = 0;
let suspiciousCPLs = DeviceImageLoadEvents
    | where ingestion_time() >= ago(timeframe)
    // Begin environment-specific filter.
    // End environment-specific filter.
    | where FileName endswith ".cpl"
    | summarize by SHA1
    // FileProfile is case-sensitive and works on lower-case hashes.
    | extend SHA1=tolower(SHA1)
    | invoke FileProfile(SHA1, 1000)
    | where not(ProfileAvailability =~ "Error")
    // Begin environment-specific filter.
    // End environment-specific filter.
    | where ((isempty(Signer) or not(IsCertificateValid==1)) and coalesce(GlobalPrevalence,default_global_prevalence) < 100) or coalesce(GlobalPrevalence,default_global_prevalence) < 50;
let loadedDlls=DeviceImageLoadEvents
    | where ingestion_time() >= ago(timeframe)
    // FileProfile is case-sensitive and works on lower-case hashes.
    | extend SHA1=tolower(SHA1)
    | where SHA1 in~ ((suspiciousCPLs|project SHA1)) and ActionType =~ "ImageLoaded"
    // Begin environment-specific filter.
    // End environment-specific filter.
    ;
loadedDlls
    | join kind=leftouter suspiciousCPLs on SHA1
    // Begin environment-specific filter.
    // End environment-specific filter.
```

---

## Version History
| Version | Date | Impact | Notes |
|---------|------|--------|------|
| 1.7  | 2025-05-19| minor | Enhanced response plan actions. |
| 1.6  | 2024-06-28| minor | Modified the usage of FileProfile to exclude results if the call to the FileProfile API has failed. |
| 1.5  | 2023-01-03| minor | Lowered the case of hashes that are fed to the FileProfile function due to case sensitivity. |
| 1.4  | 2022-11-01| minor | Use default_global_prevalence variable to allow customizing handling of empty GlobalPrevalence |
| 1.3  | 2022-07-25| minor | Added more filtering options. |
| 1.2  | 2022-05-20| minor | Updated the considerations and blindspots information. |
| 1.1  | 2022-02-22| minor | Use ingestion_time for event selection and include de-duplication logic. |
| 1.0  | 2021-02-16| major | Initial version. |