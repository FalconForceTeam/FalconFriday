# Unsigned Windows System Binary

## Metadata
**ID:** 0xFF-0006-Usigned-Windows-System-Binary-Win

**OS:** WindowsEndpoint, WindowsServer

**FP Rate:** Low

---

## ATT&CK Tags

| Tactic | Technique | Subtechnique | Technique Name |
|---|---|---| --- |
| TA0005 - Defense Evasion | T1036 | 005 | Masquerading - Match Legitimate Name or Location|
| TA0005 - Defense Evasion | T1036 | 001 | Masquerading - Invalid Code Signature|

## Utilized Data Sources

| Log Provider | Event ID | Event Name | ATT&CK Data Source | ATT&CK Data Component|
|---------|---------|----------|---------|---------|
|MicrosoftThreatProtection|ProcessCreated||Process|Process Creation|
---

## Technical description of the attack
This query searches for invocations of a number of commonly used and signed Windows binaries. It then finds invocations of these binaries where they are not properly signed.


## Permission required to execute the technique
Administrator

## Detection description
Attackers might alter system binaries to modify the binaries' behavior.


## Considerations
None.


## False Positives
In case a legitimate software package uses a file name that is the same as that of a known system binary, this rule may trigger.


## Suggested Response Actions
Investigate why the device contains an altered version of a system binary.


## Detection Blind Spots
None expected.


## References
* https://medium.com/falconforce/falconfriday-dll-hijacking-suspicious-unsigned-files-0xff06-7b2c2a9dcae6?source=friends_link&sk=5807977fd38f01b5fa8e06e5c4d5b059

---
## Detection

**Language:** Kusto

**Platform:** M365 Security

**Query:**
```C#
let timeframe = 2*1h;
let default_global_prevalence = 0;
let signedSystemFiles = dynamic(["aitstatic.exe", "ApplicationFrameHost.exe", "ApplyTrustOffline.exe", "AppVClient.exe", "AppVDllSurrogate.exe", "AppVNice.exe", "AppVShNotify.exe", "audiodg.exe", "AuthHost.exe", "backgroundTaskHost.exe", "bcdedit.exe", "bdeunlock.exe", "BioIso.exe", "bootsect.exe", "browser_broker.exe", "CameraSettingsUIHost.exe", "CastSrv.exe", "CExecSvc.exe", "changepk.exe", "ClipRenew.exe", "ClipUp.exe", "CloudExperienceHostBroker.exe", "CloudNotifications.exe", "cmdiag.exe", "CompatTelRunner.exe", "consent.exe", "convertvhd.exe", "CredentialEnrollmentManager.exe", "CredentialUIBroker.exe", "csrss.exe", "DataExchangeHost.exe", "DeviceCensus.exe", "Dism.exe", "DisplaySwitch.exe", "dllhost.exe", "DTUHandler.exe", "easinvoker.exe", "ErgonomicKBNotificationService.exe", "fontdrvhost.exe", "FsIso.exe", "fsutil.exe", "GenValObj.exe", "hcsdiag.exe", "hvax64.exe", "hvc.exe", "hvix64.exe", "hvsievaluator.exe", "hvsimgr.exe", "hvsirdpclient.exe", "hvsirpcd.exe", "HvsiSettingsWorker.exe", "iotstartup.exe", "LicensingUI.exe", "LockAppHost.exe", "LockScreenContentServer.exe", "LsaIso.exe", "lsass.exe", "mavinject.exe", "mfpmp.exe", "MRT.exe", "MusNotifyIcon.exe", "NDKPing.exe", "NgcIso.exe", "nmbind.exe", "nmscrub.exe", "ntoskrnl.exe", "nvspinfo.exe", "OpenWith.exe", "PasswordOnWakeSettingFlyout.exe", "phoneactivate.exe", "PickerHost.exe", "PktMon.exe", "ProximityUxHost.exe", "prproc.exe", "ResetEngine.exe", "RuntimeBroker.exe", "ScriptRunner.exe", "securekernel.exe", "SecurityHealthHost.exe", "SecurityHealthService.exe", "services.exe", "sessionmsg.exe", "SettingSyncHost.exe", "SgrmBroker.exe", "SgrmLpac.exe", "SIHClient.exe", "SlideToShutDown.exe", "smss.exe", "SndVol.exe", "spaceman.exe", "sppsvc.exe", "svchost.exe", "SyncAppvPublishingServer.exe", "SysResetErr.exe", "systemreset.exe", "SystemSettingsAdminFlows.exe", "SystemSettingsBroker.exe", "SystemSettingsRemoveDevice.exe", "taskhostw.exe", "Taskmgr.exe", "tcblaunch.exe", "ttdinject.exe", "tttracer.exe", "ucsvc.exe", "upfc.exe", "UserAccountBroker.exe", "verifier.exe", "vmcompute.exe", "VmComputeAgent.exe", "vmms.exe", "vmplatformca.exe", "vmsp.exe", "vmwp.exe", "wcsetupagent.exe", "WerFault.exe", "WerFaultSecure.exe", "wermgr.exe", "wifitask.exe", "wimserv.exe", "wininit.exe", "winload.exe", "winresume.exe", "wkspbroker.exe", "wlrmdr.exe", "WpcMon.exe", "wuauclt.exe", "WUDFCompanionHost.exe", "WWAHost.exe", "AdtAgent.exe", "appverif.exe", "iaStorAfsNative.exe", "iaStorAfsService.exe", "MCU.exe", "microsoft.windows.softwarelogo.showdesktop.exe", "MpSigStub.exe", "RtkAudUService64.exe", "TsWpfWrp.exe"]);
let uniqueHashes = materialize(
    DeviceProcessEvents
    | where ingestion_time() >= ago(timeframe)
    | where ActionType =~ "ProcessCreated"
    | where FileName in~ (signedSystemFiles) and not(isempty(SHA1))
    // Begin environment-specific filter.
    // End environment-specific filter.
    // FileProfile is case sensistive and works on lower-case hashes
    | extend SHA1=tolower(SHA1)
    | summarize  MachineCount=dcount(DeviceId) by SHA1
);
let unsignedHashes = materialize(
    uniqueHashes
    // Take 1000 of the most unique hashes as files with high prevelance are very likely to be signed in a legit manner.
    | top 1000 by MachineCount asc
    // FileProfile is case-sensitive and works on lower-case hashes.
    | extend SHA1=tolower(SHA1)
    | invoke FileProfile(SHA1, 1000)
    | where not(ProfileAvailability =~ "Error")
    | where IsCertificateValid != 1 or (IsRootSignerMicrosoft != 1 and coalesce(GlobalPrevalence,default_global_prevalence) < 200)
    | where not(SignatureState =~ "Unknown" and coalesce(GlobalPrevalence,default_global_prevalence) > 30000) // Workaround for a bug in MDE that reports some valid MS signed files as 'Unknown'.
);
DeviceProcessEvents
| where ingestion_time() >= ago(timeframe)
| where ActionType =~ "ProcessCreated"
| where SHA1 in~ ((unsignedHashes | project SHA1)) // This is for performance improvement.
| join kind=inner unsignedHashes on SHA1
| summarize arg_min(Timestamp, *) by DeviceId, FolderPath // Show only the first invocation per device.
```

---

## Version History
| Version | Date | Impact | Notes |
|---------|------|--------|------|
| 1.6  | 2024-06-28| minor | Modified the usage of FileProfile to exclude results if the call to the FileProfile API has failed. |
| 1.5  | 2024-06-06| minor | Added a filter for "ProcessCreated" actiontype, as MDE is rolling out other actiontypes as well. |
| 1.4  | 2023-01-03| minor | Lowered the case of hashes that are fed to the FileProfile function due to case sensitivity. |
| 1.3  | 2022-11-01| minor | Use default_global_prevalence variable to allow customizing handling of empty GlobalPrevalence |
| 1.2  | 2022-02-22| minor | Use ingestion_time for event selection and include de-duplication logic. |
| 1.1  | 2021-10-28| minor | Add workaround for false positive in MDE. |
| 1.0  | 2021-03-19| major | Initial version. |