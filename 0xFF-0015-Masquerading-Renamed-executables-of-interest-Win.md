# Masquerading Renamed executables of interest

## Metadata
**ID:** 0xFF-0015-Masquerading-Renamed-executables-of-interest-Win

**OS:** WindowsServer, WindowsEndpoint

---

## ATT&CK Tags

| Tactic | Technique | Subtechnique | Technique Name |
|---|---|---| --- |
| TA0005 - Defense Evasion | T1036 | 003 | Masquerading - Rename System Utilities|

## Utilized Data Sources

| Log Provider | Table Name | Event ID | Event Name | ATT&CK Data Source | ATT&CK Data Component|
|---------|---------|---------|----------|---------|---------|
|MicrosoftThreatProtection|DeviceProcessEvents|ProcessCreated||Process|Process Creation|
---

## Detection description
This query searches for the original file name of a set of binaries that is known to be used by attackers. The OriginalFileName field is then matched to the actual file name. Where there isn't a match the results are returned, indicating the file has been renamed. The original file name field is derived from the PE header of the executable, which is the name of the binary during compilation.



## Permission required to execute the technique
Administrator


## Description of the attack
Attackers may rename legitimate system utilities trying to evade security mechanisms concerning the usage of those utilities.


## Considerations
There might be some trusted processes in your environment, these need to be filtered.


## False Positives
There might be a legitimate use to rename the binaries. There are some cases where the shipped binary file name is already different than the embedded original file name, for example, with PSExec.exe where the original file name is PSExec.c.


## Suggested Response Actions
Investigate the subsequent processes and/or other events coming from this process launch.


## Detection Blind Spots
An attacker can choose not to rename the file or also change the PE header. Additionally, the utilized list is not exhaustive, there is a potential for other files to be utilized.


## References
* https://attack.mitre.org/techniques/T1036/003/

---
## Detection

**Language:** Kusto

**Platform:** M365 Security

**Query:**
```C#
let timeframe = 2*1h;
let lolbins = dynamic(["at.exe", "atbroker.exe", "bash.exe", "bitsadmin.exe", "certreq.exe", "certutil.exe", "cmd.exe", "cmdkey.exe", "cmstp.exe", "control.exe", "csc.exe", "cscript.exe", "desktopimgdownldr.exe", "dfsvc.exe", "diantz.exe", "diskshadow.exe", "dnscmd.exe", "esentutl.exe", "eventvwr.exe", "expand.exe", "extexport.exe", "extrac32.exe", "findstr.exe", "forfiles.exe", "ftp.exe", "gfxdownloadwrapper.exe", "gpscript.exe", "hh.exe", "ie4uinit.exe", "ieexec.exe", "ilasm.exe", "infdefaultinstall.exe", "installutil.exe", "jsc.exe", "makecab.exe", "mavinject.exe", "microsoft.workflow.compiler.exe", "mmc.exe", "mpcmdrun.exe", "msbuild.exe", "msconfig.exe", "msdt.exe", "mshta.exe", "msiexec.exe", "netsh.exe", "odbcconf.exe", "pcalua.exe", "pcwrun.exe", "pktmon.exe", "presentationhost.exe", "print.exe", "psr.exe", "rasautou.exe", "reg.exe", "regasm.exe", "regedit.exe", "regini.exe", "register-cimprovider.exe", "regsvcs.exe", "regsvr32.exe", "replace.exe", "rpcping.exe", "rundll32.exe", "runonce.exe", "runscripthelper.exe", "sc.exe", "schtasks.exe", "scriptrunner.exe", "syncappvpublishingserver.exe", "ttdinject.exe", "tttracer.exe", "vbc.exe", "verclsid.exe", "wab.exe", "wmic.exe", "wscript.exe", "wsreset.exe", "xwizard.exe", "agentexecutor.exe", "appvlp.exe", "bginfo.exe", "cdb.exe", "csi.exe", "devtoolslauncher.exe", "dnx.exe", "dotnet.exe", "dxcap.exe", "excel.exe", "mftrace.exe", "msdeploy.exe", "msxsl.exe", "ntdsutil.exe", "powerpnt.exe", "rcsi.exe", "sqldumper.exe", "sqlps.exe", "sqltoolsps.exe", "squirrel.exe", "te.exe", "tracker.exe", "vsjitdebugger.exe", "winword.exe", "wsl.exe", "powershell.exe", "pwsh.exe"]);
let binaries_of_interest = dynamic(["net.exe", "net1.exe", "whoami.exe", "ipconfig.exe", "tasklist.exe", "quser.exe", "tracert.exe", "route.exe", "runas.exe", "klist.exe", "wevtutil.exe", "wmiprvse.exe", "powershell.exe", "bash.exe", "qwinsta.exe", "rwinsta.exe", "replace.exe", "findstr.exe", "icacls.exe", "cacls.exe", "xcopy.exe", "robocopy.exe", "takeown.exe", "vssadmin.exe", "nltest.exe", "nltestk.exe", "sctasks.exe", "nbtstat.exe", "nbtinfo.exe", "mofcomp.exe", "nltestrk.exe", "dnscmd.exe", "registercimprovider.exe", "registercimprovider2.exe", "procdump", "ru.exe", "pspasswd.exe", "psexec.c", "psexec.exe", "pslist.exe", "regsize", "pskill.exe", "pkill.exe", "wsmprovhost.exe", "fltmc.exe", "sdbinst.exe"]);
// Merge both lists into one reference list.
let original_file_name_set=array_concat(lolbins,binaries_of_interest);
DeviceProcessEvents
| where ingestion_time() >= ago(timeframe)
| where ActionType =~ "ProcessCreated"
| extend process_name=tolower(FileName)
| extend original_file_name=tolower(ProcessVersionInfoOriginalFileName)
| where original_file_name in~ (original_file_name_set)
| where original_file_name != ""
// Filter some known mismatches between PE header FileName and the binary FileName.
| where not(process_name=~"schtasks.exe" and original_file_name=~"schtasks.exe" and (FolderPath=~@"C:\Windows\System32\schtasks.exe" or FolderPath=~@"C:\Windows\SysWOW64\schtasks.exe"))
| where not(process_name=~"nbtstat.exe" and original_file_name=~"nbtinfo.exe" and FolderPath=~@"C:\Windows\System32\nbtstat.exe")
| where not(process_name=~"bginfo64.exe" and original_file_name=~"bginfo.exe" and (FolderPath=~@"C:\Windows\System32\Bginfo64.exe" or FolderPath =~@"C:\Program Files\SysInternals BGInfo\Bginfo64.exe"))
// Filter MS Excel file format converter.
| where not(process_name=~"excelcnv.exe" and original_file_name=~"excel.exe" and (FolderPath startswith @"C:\Program Files\Microsoft Office Web Apps\ExcelServicesEcs\" or FolderPath  startswith @"C:\Program Files\Microsoft Office\" or FolderPath startswith @"C:\Program Files (x86)\Microsoft Office\"))
// Optionally filter this (when psexec is actually common in your environment).
| where not(process_name=~"psexec.exe" and original_file_name=~"psexec.c")
| where not(process_name=~"psexec64.exe" and original_file_name=~"psexec.c")
| where process_name != original_file_name
| project Timestamp,DeviceName,DeviceId,AccountName,process_name, original_file_name, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessVersionInfoOriginalFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, ReportId, InitiatingProcessAccountUpn
// Begin environment-specific filter.
// End environment-specific filter.
```

---

## Version History
| Version | Date | Impact | Notes |
|---------|------|--------|------|
| 1.3  | 2024-06-06| minor | Added a filter for "ProcessCreated" actiontype, as MDE is rolling out other actiontypes as well. |
| 1.2  | 2022-09-14| minor | Fix typo in the detection query. |
| 1.1  | 2022-02-22| minor | Use ingestion_time for event selection and include de-duplication logic. |
| 1.0  | 2021-02-09| major | Initial version. |