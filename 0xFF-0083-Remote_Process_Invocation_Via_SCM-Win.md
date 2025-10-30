# Remote Process Invocation Via SCM

## Metadata
**ID:** 0xFF-0083-Remote_Process_Invocation_Via_SCM-Win

**OS:** WindowsServer, WindowsEndpoint

---

## ATT&CK Tags

| Tactic | Technique | Subtechnique | Technique Name |
|---|---|---| --- |
| TA0008 - Lateral Movement | T1021 | 002 | Remote Services - SMB/Windows Admin Shares|
| TA0008 - Lateral Movement | T1021 | 003 | Remote Services - Distributed Component Object Model|
| TA0002 - Execution | T1569 | 002 | System Services - Service Execution|
| TA0003 - Persistence | T1543 | 003 | Create or Modify System Process - Windows Service|

## Utilized Data Sources

| Log Provider | Table Name | Event ID | Event Name | ATT&CK Data Source | ATT&CK Data Component|
|---------|---------|---------|----------|---------|---------|
|MicrosoftThreatProtection|DeviceProcessEvents|ProcessCreated||Process|Process Creation|
|MicrosoftThreatProtection|DeviceNetworkEvents|ConnectionSuccess||Network Traffic|Network Connection Creation|
---

## Detection description
This query matches incoming connections to services.exe with child processes spawned by services.exe, when a new child process is spawned directly after an incoming connection. This indicates a potential lateral movement where an incoming connection to services.exe triggered a child process being spawned.



## Permission required to execute the technique
Administrator


## Description of the attack
Attackers might use Windows APIs to communicate with the Windows Service Control Manager (SCM) remotely
and use it for lateral movement by spawning processes from SCM.


## Considerations
Defender for Endpoint also detects some lateral movement via SCM via standardized tools. However, this
rule can provide additional visibility in case custom methods are used to run tasks via SCM.


## False Positives
There might be legitimate usage of SCM to remotely manage machines. In addition, there is a possibility of this rule triggering by chance if an unrelated incoming network connection to services.exe is close to a process execution of services.exe. This should be rare.


## Suggested Response Actions
Investigate whether the usage of SCM is part of legitimate maintenance.


## Detection Blind Spots
If an attacker builds in a delay between the network connection and service execution it might not be detected. In addition Defender for Endpoint throttles network connection logging. Therefore, not all network connections might be logged.


## References
* https://medium.com/falconforce/falconfriday-dcom-scm-lateral-movement-0xff05-e74b69f91a7a

---
## Detection

**Language:** Kusto

**Platform:** M365 Security

**Query:**
```C#
let timeframe = 2*1h;
// This rule is fairly complex, hence this documentation.
// The rule tries to detect network activity from services.exe followed by the start of a new child process of services.exe (i.e., a service start).
// The rule tries to filter false positives as much as possible.
// The following list of LOLBINs is used to include all results which have a high reputation, but are LOLBINs.
let lolbins = dynamic(["At.exe", "Atbroker.exe", "Bash.exe", "Bitsadmin.exe", "CertReq.exe", "Certutil.exe", "Cmd.exe", "Cmdkey.exe", "Cmstp.exe", "Control.exe", "Csc.exe", "Cscript.exe", "Desktopimgdownldr.exe", "Dfsvc.exe", "Diantz.exe", "Diskshadow.exe", "Dnscmd.exe", "Esentutl.exe", "Eventvwr.exe", "Expand.exe", "Extexport.exe", "Extrac32.exe", "Findstr.exe", "Forfiles.exe", "Ftp.exe", "GfxDownloadWrapper.exe", "Gpscript.exe", "Hh.exe", "Ie4uinit.exe", "Ieexec.exe", "Ilasm.exe", "Infdefaultinstall.exe", "Installutil.exe", "Jsc.exe", "Makecab.exe", "Mavinject.exe", "Microsoft.Workflow.Compiler.exe", "Mmc.exe", "MpCmdRun.exe", "Msbuild.exe", "Msconfig.exe", "Msdt.exe", "Mshta.exe", "Msiexec.exe", "Netsh.exe", "Odbcconf.exe", "Pcalua.exe", "Pcwrun.exe", "Pktmon.exe", "Presentationhost.exe", "Print.exe", "Psr.exe", "Rasautou.exe", "Reg.exe", "Regasm.exe", "Regedit.exe", "Regini.exe", "Register-cimprovider.exe", "Regsvcs.exe", "Regsvr32.exe", "Replace.exe", "Rpcping.exe", "Rundll32.exe", "Runonce.exe", "Runscripthelper.exe", "Sc.exe", "Schtasks.exe", "Scriptrunner.exe", "SyncAppvPublishingServer.exe", "Ttdinject.exe", "Tttracer.exe", "vbc.exe", "Verclsid.exe", "Wab.exe", "Wmic.exe", "Wscript.exe", "Wsreset.exe", "Xwizard.exe", "AgentExecutor.exe", "Appvlp.exe", "Bginfo.exe", "Cdb.exe", "csi.exe", "Devtoolslauncher.exe", "dnx.exe", "Dotnet.exe", "Dxcap.exe", "Excel.exe", "Mftrace.exe", "Msdeploy.exe", "msxsl.exe", "ntdsutil.exe", "Powerpnt.exe", "rcsi.exe", "Sqldumper.exe", "Sqlps.exe", "SQLToolsPS.exe", "Squirrel.exe", "te.exe", "Tracker.exe", "Update.exe", "vsjitdebugger.exe", "Winword.exe", "Wsl.exe"]);
// First, we want to get all the network events triggered by services.exe.
let networkEvents = materialize(DeviceNetworkEvents
| where ingestion_time() >= ago(timeframe)
| where InitiatingProcessFileName in~ ("services.exe")
| where ActionType =~ "InboundConnectionAccepted"
| project-rename TimestampNetworkAct=Timestamp);
// Next, we want to get the list of child processes created by services.exe.
let allServices = materialize ((
DeviceProcessEvents
| where ingestion_time() >= ago(timeframe)
| where ActionType =~ "ProcessCreated"
// This where is for optimization purposes, as filtering is way faster than joins.
| where DeviceId in~ ((networkEvents | project DeviceId))
// Svchost and sppsvc are created very often as child processes.
| where InitiatingProcessFileName =~ "services.exe"
| project TimestampChild=Timestamp, DeviceId, DeviceName, FileName, ProcessCommandLine, SHA1,
InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessSHA1, InitiatingProcessId, TimestampServicesExe=InitiatingProcessCreationTime));
// Now we are going to join the process creations and network events and filter out all the tables _after_ the join where the child process
// of svchost is not created shortly after the network activity (0 and 10 seconds).
let serviceNetworkEvents = materialize(
(networkEvents
    | join kind=inner hint.strategy=shuffle allServices on DeviceId, InitiatingProcessId, InitiatingProcessFileName
)
| where datetime_diff("Second", TimestampChild, TimestampNetworkAct) between (0 .. 10)
// Only get the results where the network activity occurred more than 1 minute after services.exe has started (i.e., system boot).
| where datetime_diff("Second", TimestampNetworkAct, TimestampServicesExe) > 60);
// Next, we want to check the reputation of all processes.
// Since FileProfile is not properly working, we use the built-in DeviceFileCertificateInfo for the AntiJoin.
// The goal is to create a list of SHA1 hashes of the spawned processes which have a low prevelance and are not in de DeviceFileCertificateInfo.
let serviceNetworkEventsWithSHA1 = materialize(serviceNetworkEvents
| summarize count() by SHA1
| join kind=leftanti hint.strategy=broadcast DeviceFileCertificateInfo on SHA1
| where count_ < 100);
// Finally, we need to bring everything together.
// We take our subset of the child processess created by services.exe (serviceNetworkEvents).
// Everything which is on our block-list of SHA1 processess OR are LOLBINs, are filtered out.
// Also, we filter out msiexec since that appears to come very often.
serviceNetworkEvents
| where SHA1 in ((serviceNetworkEventsWithSHA1 | project SHA1)) or FileName in~ (lolbins)
| where ProcessCommandLine !~ "msiexec.exe /V"
| extend Timestamp=TimestampNetworkAct
// This summarize is optional if you want to group similar information.
//| summarize ActionType=make_set(ActionType), RemoteIPs=make_set(strcat(RemoteIP, ":", RemotePort, " (", RemoteUrl, ")")), LocalPort=make_set(LocalPort) by bin(TimestampNetworkAct, 1m), DeviceId, DeviceName, LocalIP, Protocol, AdditionalFields, bin(TimestampChild, 1m), FileName, ProcessCommandLine, SHA1, InitiatingProcessFileName, InitiatingProcessCommandLine1, bin(TimestampServicesExe, 1m)
// Begin environment-specific filter.
// End environment-specific filter.
```

---

## Version History
| Version | Date | Impact | Notes |
|---------|------|--------|------|
| 1.3  | 2024-06-06| minor | Added a filter for "ProcessCreated" actiontype, as MDE is rolling out other actiontypes as well. |
| 1.2  | 2022-09-01| minor | Filter "post_filter" added. |
| 1.1  | 2022-02-22| minor | Use ingestion_time for event selection and include de-duplication logic. |
| 1.0  | 2021-03-22| major | Initial version. |