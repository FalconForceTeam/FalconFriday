# SQL Server spawning suspicious child process

## Metadata
**ID:** 0xFF-0178-SQL_Server_suspicious_childprocess-Win

**OS:** WindowsServer

**FP Rate:** Low

---

## ATT&CK Tags

| Tactic | Technique | Subtechnique | Technique Name |
|---|---|---| --- |
| TA0004 - Privilege Escalation | T1611 |  | Escape to Host|
| TA0003 - Persistence | T1505 | 001 | Server Software Component - SQL Stored Procedures|

## Utilized Data Sources

| Log Provider | Event ID | Event Name | ATT&CK Data Source | ATT&CK Data Component|
|---------|---------|----------|---------|---------|
|MicrosoftThreatProtection|ProcessCreated||Process|Process Creation|
---

## Technical description of the attack
This query looks for potential abuse of the SQL Server stored procedure `xp_cmdshell` which allows command execution on the OS. Running `xp_cmdshell` on the system triggers the follow process chain: `sqlservr.exe` => `xp_cmdshell 'whoami'` => `"cmd.exe /c" whoami` => `whoami.exe`. This rule tries to identify running of suspicious commands as a grandchild of `sqlservr.exe`. The rule is based on a block-list of executables of LOLBINs and other known recon commands or any executable executed with a low prevalence.


## Permission required to execute the technique
User

## Detection description
Attackers who obtain access to a SQL server often use this access to escape from SQL Server to the OS by abusing the `xp_cmdshell` stored procedure. This stored procedure executes commands on the OS.


## Considerations
This rule is based on a block-list of executables spawned from SQL Server. Doing it the other way around isn't feasible in most environments since it generates way too many false positives. In case your environment doesn't generate a large number of child processes from SQL Server, please reach out and we can modify the logic to suit your environment.


## False Positives
The xp_cmdshell functionality is often used by legitimate applications for interfacing with the OS and performing all kinds of maintenance tasks (i.e., back-ups, reporting, etc.).


## Suggested Response Actions
Analyze the commandline executed from SQL server and look for any malicious or recon activity. Also keep note if similar alerts trigger on the same host. If the binary is not known to you, obtain a copy of the binary for further analysis and escalate further. In case of doubt, reach out to the corresponding DBA to understand why this is triggering.


## Detection Blind Spots
Commands that aren't considered to be a LOLBIN or a recon binary but have a high prevalence, won't trigger this detection rule.


## References

---
## Detection

**Language:** Kusto

**Platform:** M365 Security

**Query:**
```C#
let timeframe = 2*1h;
let default_global_prevalence = 0;
let lolbins = dynamic(["at.exe", "atbroker.exe", "bash.exe", "bitsadmin.exe", "certreq.exe", "certutil.exe", "cmd.exe", "cmdkey.exe", "cmstp.exe", "control.exe", "csc.exe", "cscript.exe", "desktopimgdownldr.exe", "dfsvc.exe", "diantz.exe", "diskshadow.exe", "dnscmd.exe", "esentutl.exe", "eventvwr.exe", "expand.exe", "extexport.exe", "extrac32.exe", "findstr.exe", "forfiles.exe", "ftp.exe", "gfxdownloadwrapper.exe", "gpscript.exe", "hh.exe", "ie4uinit.exe", "ieexec.exe", "ilasm.exe", "infdefaultinstall.exe", "installutil.exe", "jsc.exe", "makecab.exe", "mavinject.exe", "microsoft.workflow.compiler.exe", "mmc.exe", "mpcmdrun.exe", "msbuild.exe", "msconfig.exe", "msdt.exe", "mshta.exe", "msiexec.exe", "netsh.exe", "odbcconf.exe", "pcalua.exe", "pcwrun.exe", "pktmon.exe", "presentationhost.exe", "print.exe", "psr.exe", "rasautou.exe", "reg.exe", "regasm.exe", "regedit.exe", "regini.exe", "register-cimprovider.exe", "regsvcs.exe", "regsvr32.exe", "replace.exe", "rpcping.exe", "rundll32.exe", "runonce.exe", "runscripthelper.exe", "sc.exe", "schtasks.exe", "scriptrunner.exe", "syncappvpublishingserver.exe", "ttdinject.exe", "tttracer.exe", "vbc.exe", "verclsid.exe", "wab.exe", "wmic.exe", "wscript.exe", "wsreset.exe", "xwizard.exe", "agentexecutor.exe", "appvlp.exe", "bginfo.exe", "cdb.exe", "csi.exe", "devtoolslauncher.exe", "dnx.exe", "dotnet.exe", "dxcap.exe", "excel.exe", "mftrace.exe", "msdeploy.exe", "msxsl.exe", "ntdsutil.exe", "powerpnt.exe", "rcsi.exe", "sqldumper.exe", "sqlps.exe", "sqltoolsps.exe", "squirrel.exe", "te.exe", "tracker.exe", "vsjitdebugger.exe", "winword.exe", "wsl.exe", "powershell.exe", "pwsh.exe"]);
let binaries_of_interest = dynamic(["net.exe", "net1.exe", "whoami.exe", "ipconfig.exe", "tasklist.exe", "quser.exe", "tracert.exe", "route.exe", "runas.exe", "klist.exe", "wevtutil.exe", "wmiprvse.exe", "powershell.exe", "bash.exe", "qwinsta.exe", "rwinsta.exe", "replace.exe", "findstr.exe", "icacls.exe", "cacls.exe", "xcopy.exe", "robocopy.exe", "takeown.exe", "vssadmin.exe", "nltest.exe", "nltestk.exe", "sctasks.exe", "nbtstat.exe", "nbtinfo.exe", "mofcomp.exe", "nltestrk.exe", "dnscmd.exe", "registercimprovider.exe", "registercimprovider2.exe", "procdump", "ru.exe", "pspasswd.exe", "psexec.c", "psexec.exe", "pslist.exe", "regsize", "pskill.exe", "pkill.exe", "wsmprovhost.exe", "fltmc.exe", "sdbinst.exe"]);
// Merge both lists into one reference list.
let original_file_name_set=array_concat(lolbins,binaries_of_interest);
let allGrandChilderen = DeviceProcessEvents // Based on some unscientific testing, this is faster than using materialize() in this case.
| where ingestion_time() >= ago(timeframe)
| where ActionType =~ "ProcessCreated"
| where InitiatingProcessParentFileName =~ "sqlservr.exe"
| where InitiatingProcessCommandLine startswith "\"cmd.exe\" /c";
let allSuspiciousHashes = allGrandChilderen
// FileProfile is case-sensitive and works on lower-case hashes.
| extend SHA1=tolower(SHA1)
| distinct SHA1
| invoke FileProfile(SHA1, 1000)
| where not(ProfileAvailability =~ "Error")
| where coalesce(GlobalPrevalence,default_global_prevalence) < 250 or not(isempty(ThreatName));
allGrandChilderen
| where FileName in~ (original_file_name_set) or SHA1 in ((allSuspiciousHashes))
| join kind=leftouter allSuspiciousHashes on SHA1
// Begin environment-specific filter.
// End environment-specific filter.
```

---

## Version History
| Version | Date | Impact | Notes |
|---------|------|--------|------|
| 1.6  | 2024-06-28| minor | Modified the usage of FileProfile to exclude results if the call to the FileProfile API has failed. |
| 1.5  | 2024-06-06| minor | Added a filter for "ProcessCreated" actiontype, as MDE is rolling out other actiontypes as well. |
| 1.4  | 2023-01-03| minor | Lowered the case of hashes that are fed to the FileProfile function due to case sensitivity. |
| 1.3  | 2022-11-01| minor | Use default_global_prevalence variable to allow customizing handling of empty GlobalPrevalence |
| 1.2  | 2022-05-20| minor | Updated the response plan. |
| 1.1  | 2022-02-22| minor | Use ingestion_time for event selection and include de-duplication logic. |
| 1.0  | 2021-10-05| major | Initial version. |