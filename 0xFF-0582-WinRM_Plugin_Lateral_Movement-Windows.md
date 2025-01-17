# WinRM Plugin Lateral Movement

## Metadata
**ID:** 0xFF-0582-WinRM_Plugin_Lateral_Movement-Windows

**OS:** WindowsEndpoint, WindowsServer

---

## ATT&CK Tags

| Tactic | Technique | Subtechnique | Technique Name |
|---|---|---| --- |
| TA0008 - Lateral Movement | T1021 | 006 | Remote Services - Windows Remote Management|

## Utilized Data Sources

| Log Provider | Event ID | Event Name | ATT&CK Data Source | ATT&CK Data Component|
|---------|---------|----------|---------|---------|
|MicrosoftThreatProtection|ImageLoaded||Module|Module Load|
|MicrosoftThreatProtection|FileCreated||Module|Module Load|
|MicrosoftThreatProtection|FileRenamed||Module|Module Load|
|MicrosoftThreatProtection|FileModified||Module|Module Load|
---

## Detection description
This query detects loading of malicious WinRM plugins. These plugins can be used for lateral movement. This tradecraft has been researched and published by Arnau Ortega at FalconForce. Refer to the references for the blog post describing the full attack chain. This detection looks at low-prevalence DLLs being loaded into the WinRM host process. To minimize false-positives, the detection looks for files that are written to disk in the last 30 days, prior to being loaded into the WinRM host process as DLL. Such DLLs are likely WinRM plugins that are being loaded. Since the use of WinRM plugins is extremely scarce in real environments, we assume that any such DLL is malicious and warrants an investigation.




## Description of the attack
The Windows Remote Management (WinRM) service is a Windows service that allows administrators to remotely manage Windows machines. WinRM supports plugins that can
be loaded into the WinRM host process to extend its functionality. These plugins can be used for lateral movement. This detection looks for DLLs which are uncommon
and have been written to disk in the last 30 days, prior to being loaded as plugin in WinRM. This detection is based on research by Arnau Ortega at FalconForce.


## Considerations
Consider modifying this detection and excluding the requirement of DLLs being written to disk in the last 30 days, in case the threat model indicates highly sophisticated
attackers that may take sufficient time to prepare this attack. In such cases, the detection can be modified to look for any low-prevalence DLLs being loaded into the
WinRM host process. This will potentially increase the number of false positives at the expense of slightly increasing the chance of a false-negative.


## False Positives
None expected.


## Suggested Response Actions
Immediately obtain a copy of the offending DLL file. Reverse engineer and investigate all exported DLL functions starting with "WSMan". Investigate if other systems
showcase similar behavior or if the DLL has been seen on other systems. Especially investigate machines where there is no Defender for Endpoint coverage or where
coverage was recently enabled.


## Detection Blind Spots
Attackers can bypass this detection by finding and using a WinRM plugin DLL with a high prevalence. No such DLL exists to our knowledge.


## References

---
## Detection

**Language:** Kusto

**Platform:** M365 Security

**Query:**
```C#
let timeframe = 2*1d;
let default_global_prevalence = 0;
let lookback = 30d;
let PotentialPlugins = materialize(
  DeviceImageLoadEvents
  | where ingestion_time() >= ago(timeframe)
  | where InitiatingProcessFileName =~ "wsmprovhost.exe"
  | where FolderPath !startswith @"C:\windows\assembly\nativeimages_" // Excluding .NET GAC as these are irrelevant for WinRM plugins and generate false positives.
  | invoke FileProfile(SHA1, 1000)
  | where ProfileAvailability !~ "Error"
  | where coalesce(GlobalPrevalence, default_global_prevalence) < 100
  | extend FolderPath=tolower(FolderPath)
);
let PotentialWrites = (
  DeviceFileEvents
  | where Timestamp >= ago(lookback)
  | where ActionType in~ ("FileCreated", "FileRenamed", "FileModified")
  | where SHA1 in~ ((PotentialPlugins | project SHA1))
  | extend FolderPath=tolower(FolderPath)
);
PotentialPlugins
| join kind=inner PotentialWrites on SHA1, DeviceId, FolderPath
// Begin environment-specific filter.
// End environment-specific filter.
```

---

## Version History
| Version | Date | Impact | Notes |
|---------|------|--------|------|
| 1.0  | 2025-01-17| major | Initial version. |