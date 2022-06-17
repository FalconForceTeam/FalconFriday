# FireEye red_team_tool_countermeasures KQL queries

## Disclaimer
These detections are heavily based on this [FireEye repository](https://github.com/fireeye/red_team_tool_countermeasures)

*Please note we do not want to take credit for these detections, these are heavily based on the files as kindly and professionally supplied by the FireEye team. Secondly not all rules have been converted, partially since some of our previous FalconFriday rules already covered them and also since MDE does not have the same capabilities in terms of telemetry.*

## Notes

Omissions and additions have been applied to improve the fidelity for some of the rules. In their current state most rules have a pretty acceptable volume of results. They have been tested and validated in several environments. *Additional tuning might still be required in your environment.*

Please keep in mind quite a few of these rules are heavily signature based and require additional research to be more resilient against behavior variations.

Don't forget to check out the rest of this repository.

---

- [FireEye red_team_tool_countermeasures KQL queries](#fireeye-red_team_tool_countermeasures-kql-queries)
  - [Disclaimer](#disclaimer)
  - [Notes](#notes)
  - [Tool detections](#tool-detections)
    - [ADPASSHUNT](#adpasshunt)
    - [SUSPICIOUS EXECUTION OF TSTHEME](#suspicious-execution-of-tstheme)
    - [DISM.EXE SUSPICIOUS CHILD PROCESSES](#dismexe-suspicious-child-processes)
    - [TitoSpecial Memory Dump](#titospecial-memory-dump)
    - [Possible Handler Poisoning](#possible-handler-poisoning)
    - [Service Failure Abuse](#service-failure-abuse)
    - [SharPersist](#sharpersist)
    - [SAFETYKATZ](#safetykatz)
    - [Seatbelt](#seatbelt)
    - [PAX dism WIM mount](#pax-dism-wim-mount)
    - [PXELOOT](#pxeloot)
    - [INSTALLUTIL APP WHITELISTING BYPASS](#installutil-app-whitelisting-bypass)
    - [CONTROL PANEL ITEMS](#control-panel-items)
    - [REGASM PARENT PROCESS](#regasm-parent-process)
    - [USERINIT PROCESS LAUNCH BY MSBUILD.EXE](#userinit-process-launch-by-msbuildexe)
    - [IMPACKET-OBFUSCATION SMBEXEC](#impacket-obfuscation-smbexec)
    - [IMPACKET-OBFUSCATION WMIEXEC](#impacket-obfuscation-wmiexec)
    - [SUSPICIOUS EXECUTION OF COLORCPL.EXE](#suspicious-execution-of-colorcplexe)
    - [EXCAVATOR](#excavator)
  - [DLL Hijack Section](#dll-hijack-section)
    - [api-ms-win-downlevel-shell32-l1-1-0.dll Hijack](#api-ms-win-downlevel-shell32-l1-1-0dll-hijack)
    - [ashldres.dll Hijack](#ashldresdll-hijack)
    - [ccl110u.dll Hijack](#ccl110udll-hijack)
    - [cclib.dll Hijack](#cclibdll-hijack)
    - [chrome_frame_helper.dll Hijack](#chrome_frame_helperdll-hijack)
    - [crshhndl.dll Hijack](#crshhndldll-hijack)
    - [dismcore.dll Hijack](#dismcoredll-hijack)
    - [dwmapi.dll Hijack](#dwmapidll-hijack)
    - [elogger.dll Hijack](#eloggerdll-hijack)
    - [fmtoptions.dll Hijack](#fmtoptionsdll-hijack)
    - [goopdate.dll Hijack](#goopdatedll-hijack)
    - [hpcustpartui.dll Hijack](#hpcustpartuidll-hijack)
    - [mcutil.dll Hijack](#mcutildll-hijack)
    - [mscorsvc.dll Hijack](#mscorsvcdll-hijack)
    - [msi.dll Hijack](#msidll-hijack)
    - [nflogger Hijack](#nflogger-hijack)
    - [PackageIdentification.dll Hijack](#packageidentificationdll-hijack)
    - [PotPlayer.dll Hijack](#potplayerdll-hijack)
    - [pc2msupp.dll Hijack](#pc2msuppdll-hijack)
    - [pt1.aym Hijack](#pt1aym-hijack)
    - [sidebar.dll Hijack](#sidebardll-hijack)
    - [splash_screen.dll Hijack](#splash_screendll-hijack)
    - [tmas_wlmhook.dll Hijack](#tmas_wlmhookdll-hijack)
    - [ui.dll Hijack](#uidll-hijack)
    - [ushata.dll Hijack](#ushatadll-hijack)
  
---

## Tool detections

### ADPASSHUNT

```c#
//https://github.com/fireeye/red_team_tool_countermeasures/blob/master/rules/ADPASSHUNT/production/hxioc/ADPASSHUNT (CREDENTIAL STEALER).ioc
// This IOC detects indicators associated with the ADPassHunt Tool. This tool is used to hunt for AD credentials and used via execute-assembly that looks for passwords in GPP, Autoruns and AD objects.  
// T1003.003, T1552.006
// Remove next filter when too many false positives
let StartedProcess=DeviceProcessEvents
| where FileName =~ "ADPassHunt.exe"
| extend CleanProcessCommandLine=parse_command_line(tostring(ProcessCommandLine), "windows")
| where CleanProcessCommandLine has_any ("-dc","-domain","-action","start","gpp","ad");
DeviceEvents
| where DeviceId in (( StartedProcess | project DeviceId)) and InitiatingProcessFileName in (( StartedProcess | project FileName))
```

### SUSPICIOUS EXECUTION OF TSTHEME

```c#
//https://github.com/fireeye/red_team_tool_countermeasures/blob/master/rules/WEAPONIZE/supplemental/hxioc/SUSPICIOUS EXECUTION OF TSTHEME.EXE (METHODOLOGY).ioc
//This IOC detects suspicious parent and child processes relation with TStheme.exe.
DeviceProcessEvents
| where (InitiatingProcessFolderPath contains @":\Windows\SysWOW64\TSTheme" or InitiatingProcessFolderPath contains @":\Windows\System32\TSTheme") 
or FolderPath contains @":\Windows\SysWOW64\TSTheme" or FolderPath contains @":\Windows\System32\TSTheme" and InitiatingProcessFolderPath != @"c:\windows\system32\svchost.exe"
```

### DISM.EXE SUSPICIOUS CHILD PROCESSES

```c#
//https://github.com/fireeye/red_team_tool_countermeasures/blob/master/rules/UNCATEGORIZED/production/hxioc/DISM.EXE SUSPICIOUS CHILD PROCESSES (METHODOLOGY).ioc
//This alert looks for suspicious child processes of werfault.exe, a known process used by malicious actors for process injection.
let lolbins = dynamic(["At.exe", "Atbroker.exe", "Bash.exe", "Bitsadmin.exe", "CertReq.exe", "Certutil.exe", "Cmd.exe", "Cmdkey.exe", "Cmstp.exe", "Control.exe", "Csc.exe", "Cscript.exe", "Desktopimgdownldr.exe", "Dfsvc.exe", "Diantz.exe", "Diskshadow.exe", "Dnscmd.exe", "Esentutl.exe", "Eventvwr.exe", "Expand.exe", "Extexport.exe", "Extrac32.exe", "Findstr.exe", "Forfiles.exe", "Ftp.exe", "GfxDownloadWrapper.exe", "Gpscript.exe", "Hh.exe", "Ie4uinit.exe", "Ieexec.exe", "Ilasm.exe", "Infdefaultinstall.exe", "Installutil.exe", "Jsc.exe", "Makecab.exe", "Mavinject.exe", "Microsoft.Workflow.Compiler.exe", "Mmc.exe", "MpCmdRun.exe", "Msbuild.exe", "Msconfig.exe", "Msdt.exe", "Mshta.exe", "Msiexec.exe", "Netsh.exe", "Odbcconf.exe", "Pcalua.exe", "Pcwrun.exe", "Pktmon.exe", "Presentationhost.exe", "Print.exe", "Psr.exe", "Rasautou.exe", "Reg.exe", "Regasm.exe", "Regedit.exe", "Regini.exe", "Register-cimprovider.exe", "Regsvcs.exe", "Regsvr32.exe", "Replace.exe", "Rpcping.exe", "Rundll32.exe", "Runonce.exe", "Runscripthelper.exe", "Sc.exe", "Schtasks.exe", "Scriptrunner.exe", "SyncAppvPublishingServer.exe", "Ttdinject.exe", "Tttracer.exe", "vbc.exe", "Verclsid.exe", "Wab.exe", "Wmic.exe", "Wscript.exe", "Wsreset.exe", "Xwizard.exe", "AgentExecutor.exe", "Appvlp.exe", "Bginfo.exe", "Cdb.exe", "csi.exe", "Devtoolslauncher.exe", "dnx.exe", "Dotnet.exe", "Dxcap.exe", "Mftrace.exe", "Msdeploy.exe", "msxsl.exe", "ntdsutil.exe", "rcsi.exe", "Sqldumper.exe", "Sqlps.exe", "SQLToolsPS.exe", "Squirrel.exe", "te.exe", "Tracker.exe", "Update.exe", "Wsl.exe", "ipconfig.exe", "whoami.exe", "net.exe", "net1.exe"]);
DeviceProcessEvents
| where (InitiatingProcessFileName == "WerFault.exe" or InitiatingProcessFileName == "dism.exe" or InitiatingProcessFileName == "SearchProtocolHost.exe") and FileName in~(lolbins)
| where not(ProcessCommandLine contains "\"rundll32.exe\" \"C:\\WINDOWS\\system32\\chakra.dll\",DumpDiagInfo" or ProcessCommandLine contains "WerFault.exe -u -p")
//| summarize count() by FileName, InitiatingProcessCommandLine
```

### TitoSpecial Memory Dump

```c#
//https://github.com/fireeye/red_team_tool_countermeasures/blob/master/rules/TITOSPECIAL/production/hxioc/TitoSpecial Memory Dump (Credential Stealer).ioc
//Identifies memory dump files created by the credential stealing tool TitoSpecial, which is a variant of the publicly-available tool AndrewSpecial.
//
// This is brittle, since all these variables can be changed by an attacker, this is only covering the default behavior
DeviceFileEvents
| where FolderPath contains @"Windows\Temp" and FileName endswith "dmp" and FileName contains "output"
```

### Possible Handler Poisoning

```c#
//https://github.com/fireeye/red_team_tool_countermeasures/blob/master/rules/SHARPIVOT/production/hxioc/Possible Handler Poisoning (Methodology).ioc
//
// This is a noisy one, look for anomalies in the commandline executions here
// next also consider looking at other execution methods through powershell and other lolbins
DeviceProcessEvents
| where (InitiatingProcessFileName == "wmiprvse.exe" or InitiatingProcessFileName == "svchost.exe" or InitiatingProcessFileName == "services.exe" or InitiatingProcessFileName == "taskeng.exe")
| where FileName == "cmd.exe" and ProcessCommandLine contains ""
| where not(ProcessCommandLine contains "cmd.EXE /c start hpdiags://" or ProcessCommandLine contains "start \"C:\\Program Files\\internet explorer\\iexplore.exe\"" or ProcessCommandLine contains "start iexplore http://" or ProcessCommandLine contains "start http://")
| summarize count() by ProcessCommandLine, InitiatingProcessFileName 
| where count_ < 50
```

```c#
//https://github.com/fireeye/red_team_tool_countermeasures/blob/master/rules/SHARPIVOT/production/hxioc/Possible Handler Poisoning (Methodology).ioc
DeviceProcessEvents
| where FileName == "rundll32.exe" 
| extend CleanProcessCommandLine=parse_command_line(tostring(ProcessCommandLine), "windows")
| where CleanProcessCommandLine contains "url.dll" and CleanProcessCommandLine contains "FileProtocolHandler" and CleanProcessCommandLine contains "://"
```

```c#
//https://github.com/fireeye/red_team_tool_countermeasures/blob/master/rules/SHARPIVOT/production/hxioc/Possible Handler Poisoning (Methodology).ioc
// Expect some noise from Office applications and for instance VLC
DeviceRegistryEvents
| where RegistryKey contains @"\software\classes\" and RegistryKey contains @"\shell\open\command" and ActionType contains "RegistryValueSet"
| where InitiatingProcessFileName != "msiexec.exe"
| summarize count() by RegistryKey, InitiatingProcessFileName, RegistryValueData
| where count_ < 100
```

### Service Failure Abuse

```c#
//https://github.com/fireeye/red_team_tool_countermeasures/blob/master/rules/SHARPERSIST/production/hxioc/Service Failure Abuse (Methodology).ioc
DeviceRegistryEvents
| where RegistryKey contains @"\failurecommand" and RegistryKey contains @"\services\" and ActionType contains "RegistryValueSet"
// known exploitable services, enable when you get a lot of false positives
// | where RegistryKey contains @"services\AppVClient" or RegistryKey contains @"services\UI0Detect"
```

### SharPersist

```c#
//https://github.com/fireeye/red_team_tool_countermeasures/blob/master/rules/SHARPERSIST/production/hxioc/SharPersist B (utility).ioc
//Identifies artifacts created by a variant of the SharPersist persistence creation tool.
DeviceRegistryEvents
| where RegistryKey contains @"\InprocServer32" and RegistryKey notcontains @"HKEY_LOCAL_MACHINE" and ActionType contains "RegistryValueSet"
| where (RegistryKey contains @"\{2dea658f-54c1-4227-af9b-260ab5fc3543}\" or RegistryKey contains @"\{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}\" or RegistryKey contains @"\{0358b920-0ac7-461f-98f4-58e32cd89148}\" or RegistryKey contains @"\{b1aebb5d-ead9-4476-b375-9c3ed9f32afc}\")
```

```c#
//https://github.com/fireeye/red_team_tool_countermeasures/blob/master/rules/SHARPERSIST/production/hxioc/SHARPERSIST A (UTILITY).ioc
//This IOC detects windows persistence activity performed by the Sharpersist utility. It has multiple persistence functionalities such as Keepass, hotkey, new schedule task, Startup Folder and Scheduled Task Backdoor.
//
// processname left out on perpose, since this is way to brittle, commandline parameters are slightly harder to change
DeviceProcessEvents
| where (ProcessCommandLine contains " comhijack " and ProcessCommandLine contains ".dll") 
    or (ProcessCommandLine contains " wmi " and (ProcessCommandLine contains " -n " or ProcessCommandLine contains " /n "))
    or (ProcessCommandLine contains " schtaskbackdoor " and (ProcessCommandLine contains " -n " or ProcessCommandLine contains " /n "))
    or (ProcessCommandLine contains " hotkey " and (ProcessCommandLine contains " -k " or ProcessCommandLine contains " /k ") and (ProcessCommandLine contains " -f " or ProcessCommandLine contains " /f "))
    or (ProcessCommandLine in (" add "," check "," remove "," list ") and (ProcessCommandLine contains " -t " or ProcessCommandLine contains " /t ") and (ProcessCommandLine contains " -c " or ProcessCommandLine contains " /c "))
```

### SAFETYKATZ

```c#
//https://github.com/fireeye/red_team_tool_countermeasures/blob/master/rules/SAFETYKATZ/production/hxioc/SAFETYKATZ (CREDENTIAL STEALER).ioc
//
// This is fairly brittle, since all these variables can be changed by an attacker, this is only covering the default behavior
DeviceFileEvents
| where FileName == "debug.bin" and FolderPath contains @"Windows\Temp"
```

### Seatbelt

```c#
//https://github.com/fireeye/red_team_tool_countermeasures/blob/master/rules/BELTALOWDA/supplemental/hxioc/SEATBELT (UTILITY).ioc
//Seatbelt is an open source C# project that performs a number of security oriented host-survey "safety checks" relevant from both offensive and defensive security perspectives.
let SeatBeltParameters=dynamic(["AMSIProviders","AntiVirus","AppLocker","ARPTable","AuditPolicies","AuditPolicyRegistry","AutoRuns","ChromiumBookmarks","ChromiumHistory","ChromiumPresence","IEFavorites","IETabs","IEUrls","InstalledProducts","InterestingFiles","InterestingProcesses","InternetSettings","LAPS","LastShutdown","LocalGPOs","LocalGroups","LocalUsers","LogonEvents","LogonSessions","LOLBAS","LSASettings","MappedDrives","McAfeeConfigs","McAfeeSiteList","CloudCredentials","CredEnum","CredGuard","dir","DNSCache","DotNet","DpapiMasterKeys","EnvironmentPath","EnvironmentVariables","ExplicitLogonEvents","ExplorerMRUs","ExplorerRunCommands","FileInfo","FileZilla","FirefoxHistory","FirefoxPresence","Hotfixes","IdleTime","MicrosoftUpdates","NamedPipes","NetworkProfiles","NetworkShares","NTLMSettings","OfficeMRUs","OracleSQLDeveloper","OSInfo","OutlookDownloads","PoweredOnEvents","PowerShell","PowerShellEvents","PowerShellHistory","Printers","ProcessCreationEvents","Processes","ProcessOwners","PSSessionSettings","PuttyHostKeys","PuttySessions","RDCManFiles","RDPSavedConnections","RDPSessions","RDPsettings","RecycleBin","reg","RPCMappedEndpoints","SCCM","ScheduledTasks","SearchIndex","SecPackageCreds","SecurityPackages","Services","SlackDownloads","SlackPresence","SlackWorkspaces","SuperPutty","Sysmon","SysmonEvents","TcpConnections","TokenGroups","TokenPrivileges","UAC","UdpConnections","UserRightAssignments","WindowsAutoLogon","WindowsCredentialFiles","WindowsDefender","WindowsEventForwarding","WindowsFirewall","WindowsVault","WMIEventConsumer","WMIEventFilter","WMIFilterBinding","WSUS","-group=","-outputfile=","-computername=","-full"]);
DeviceProcessEvents
| where ProcessCommandLine in(SeatBeltParameters)
| extend CleanProcessCommandLine=parse_command_line(tostring(ProcessCommandLine), "windows")
| extend ParameterCount=array_length(set_intersect(SeatBeltParameters, CleanProcessCommandLine))
| invoke FileProfile(SHA1) 
```

### PAX dism WIM mount

```c#
//https://github.com/fireeye/red_team_tool_countermeasures/blob/master/rules/PXELOOT/production/hxioc/PAX dism WIM mount (utility).ioc
//Identifies dism processes consistent with the arguments used by the tool PXE and Loot (PAX)
DeviceProcessEvents
| where FileName =~ "dism.exe"
| extend CleanProcessCommandLine=parse_command_line(tostring(ProcessCommandLine), "windows")
| where CleanProcessCommandLine in ("Mount-Wim","WimFile:","MountDir:","LogPath:NUL","index:1")
```

### PXELOOT

```c#
//https://github.com/fireeye/red_team_tool_countermeasures/blob/master/rules/PXELOOT/production/hxioc/PXELOOT (UTILITY).ioc
//PXELoot (PAL) is a C# tool designed to aid in the discovery and exploitation of misconfigurations in Windows Deployment Services (WDS)
let var1=DeviceFileEvents
| where ActionType contains "FileCreated" and InitiatingProcessFileName =~ "dism.exe"
| where FolderPath contains @"Windows\Temp\" and FolderPath matches regex "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}";
let var2=DeviceProcessEvents
| where ProcessCommandLine contains " --dhcp-recon" or ProcessCommandLine contains " --targets " or ProcessCommandLine contains " --rpc "
    or (ProcessCommandLine matches regex "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}" and (ProcessCommandLine contains " --u " or ProcessCommandLine contains " --unmount-path "));
let var3=DeviceProcessEvents
| where ((ProcessCommandLine contains " -w " or ProcessCommandLine contains " --wim ") and ProcessCommandLine contains "\\reminst\\" and ProcessCommandLine endswith ".wim")
    and ((ProcessCommandLine contains " -U " or ProcessCommandLine contains " --Username ")
    and (ProcessCommandLine contains " -P " or ProcessCommandLine contains " --Password ")
    and (ProcessCommandLine contains " -D " or ProcessCommandLine contains " --Domain "));    
union var1,var2,var3
```

### INSTALLUTIL APP WHITELISTING BYPASS

```c#
//https://github.com/fireeye/red_team_tool_countermeasures/blob/master/rules/PGF/production/hxioc/INSTALLUTIL APP WHITELISTING BYPASS (METHODOLOGY).ioc
//This alert looks for evidence of the native signed Windows binary InstallUtil.exe being used to load PE files. This technique can be used to bypass application whitelisting and has been observed used in the wild.
let var1=DeviceProcessEvents
| where ProcessCommandLine contains "InstallUtil" and ProcessCommandLine contains "LogToConsole="
| where not(InitiatingProcessFolderPath contains @":\Windows\System32\msiexec.exe" 
        or InitiatingProcessFolderPath contains @":\Windows\SysWOW64\msiexec.exe" 
        or (InitiatingProcessFolderPath contains @":\Windows\winsxs\" and InitiatingProcessFolderPath contains @"\msiexec.exe")
        or ProcessCommandLine contains @"\Microsoft.Workflow.Compiler.exe.lib"
        or ProcessCommandLine contains @"\UIAutomationClientsideProviders.dll.rsp"
        or ProcessCommandLine contains @"\AppData\sbscmp20_mscorwks.dll.rsp"
        or ProcessCommandLine contains @":\Program Files"
        or ProcessCommandLine contains "/ShowCallStack"
        );
let var2=DeviceRegistryEvents
| where ActionType == "RegistryValueSet"
| where RegistryValueData contains "InstallUtil" and RegistryValueData contains "LogToConsole" and RegistryValueData contains "logfile=";
union var1,var2
```

### CONTROL PANEL ITEMS

```c#
//https://github.com/fireeye/red_team_tool_countermeasures/blob/master/rules/PGF/supplemental/hxioc/CONTROL PANEL ITEMS (METHODOLOGY).ioc
//Windows Control Panel items are utilities that allow users to view and adjust computer settings. Control Panel items are registered executable (.exe) or Control Panel (.cpl) files, the latter are actually renamed dynamic-link library (.dll) files that export a CPlApplet function. This is associated with MITRE ATT&amp;CK (r) Tactic(s): Defense Evasion and Technique(s): T1218.002
DeviceProcessEvents
| where FileName == "control.exe" and ProcessCommandLine contains ".cpl " 
| where ProcessCommandLine contains "shell32.dll" and (ProcessCommandLine contains "Control_RunDLLAsUser " or ProcessCommandLine contains "Control_RunDLL ")
```

### REGASM PARENT PROCESS

```c#
//https://github.com/fireeye/red_team_tool_countermeasures/blob/master/rules/PGF/supplemental/hxioc/REGASM PARENT PROCESS (METHODOLOGY).ioc
//This IOC detects the spawning of a process by RegAsm.exe, a Windows command-line utility used to register .NET Component Object Model (COM) assemblies.
DeviceProcessEvents
| where InitiatingProcessFileName =~ "regasm.exe" and FileName != "conhost.exe"
```

### USERINIT PROCESS LAUNCH BY MSBUILD.EXE

```c#
//https://github.com/fireeye/red_team_tool_countermeasures/blob/master/rules/MSBUILDME/supplemental/hxioc/USERINIT PROCESS LAUNCH BY MSBUILD.EXE (METHODOLOGY).ioc
//MSBuild is the build system for Visual Studio. This IOC detects the suspicious execution of userinit process by MSBUILD.
DeviceProcessEvents
| where InitiatingProcessFileName =~ "MSBuild.exe" and FileName =~ "userinit.exe"
```

### IMPACKET-OBFUSCATION SMBEXEC

```c#
//https://github.com/fireeye/red_team_tool_countermeasures/blob/master/rules/IMPACKETOBF/production/hxioc/IMPACKET-OBFUSCATION SMBEXEC (UTILITY).ioc
//Impacket-Obfuscation is a slightly obfuscated version of the open source Impacket framework. This IOC looks for artifacts from the execution of SMBEXEC python script which is part of Impacket-Obfuscation framework.
let var1=DeviceRegistryEvents
| where RegistryValueName == "ImagePath" and RegistryValueData contains "%CoMSpEC% /q /K echo ";
let var2=DeviceProcessEvents
| where InitiatingProcessFileName =~ "services.exe" and FileName =~ "cmd.exe"
| where (ProcessCommandLine contains "/q /K echo" or ProcessCommandLine contains "-q -K echo") and ProcessCommandLine contains "2>&1";
union var1,var2
```

### IMPACKET-OBFUSCATION WMIEXEC

```c#
//https://github.com/fireeye/red_team_tool_countermeasures/blob/master/rules/IMPACKETOBF/production/hxioc/IMPACKET-OBFUSCATION WMIEXEC (UTILITY).ioc
//Impacket-Obfuscation is a slightly obfuscated version of the open source Impacket framework. This IOC looks for artifacts from the execution of WMIEXEC python script which is part of Impacket-Obfuscation framework.
let var1=DeviceFileEvents
| where FolderPath matches regex "\\Windows\\[0-9]{10}[0-9a-f]{8}\\.dat";
let var2=DeviceProcessEvents
| where InitiatingProcessFileName =~ "wmiprvse.exe" and FileName =~ "cmd.exe"
| where (ProcessCommandLine contains "/q /K" or ProcessCommandLine contains "-q -K") and ProcessCommandLine matches regex "\\[0-9]{10}[0-9a-f]{8}\\.dat";
union var1,var2
```

### SUSPICIOUS EXECUTION OF COLORCPL.EXE

```c#
//https://github.com/fireeye/red_team_tool_countermeasures/blob/master/rules/G2JS/production/hxioc/SUSPICIOUS EXECUTION OF COLORCPL.EXE (METHODOLOGY).ioc
//This IOC detects suspicious parent and child processes relation with colorcpl.exe.
let lolbins = dynamic(["At.exe", "Atbroker.exe", "Bash.exe", "Bitsadmin.exe", "CertReq.exe", "Certutil.exe", "Cmd.exe", "Cmdkey.exe", "Cmstp.exe", "Control.exe", "Csc.exe", "Cscript.exe", "Desktopimgdownldr.exe", "Dfsvc.exe", "Diantz.exe", "Diskshadow.exe", "Dnscmd.exe", "Esentutl.exe", "Eventvwr.exe", "Expand.exe", "Extexport.exe", "Extrac32.exe", "Findstr.exe", "Forfiles.exe", "Ftp.exe", "GfxDownloadWrapper.exe", "Gpscript.exe", "Hh.exe", "Ie4uinit.exe", "Ieexec.exe", "Ilasm.exe", "Infdefaultinstall.exe", "Installutil.exe", "Jsc.exe", "Makecab.exe", "Mavinject.exe", "Microsoft.Workflow.Compiler.exe", "Mmc.exe", "MpCmdRun.exe", "Msbuild.exe", "Msconfig.exe", "Msdt.exe", "Mshta.exe", "Msiexec.exe", "Netsh.exe", "Nslookup.exe", "Odbcconf.exe", "Pcalua.exe", "Pcwrun.exe", "Pktmon.exe", "Powershell.exe", "Presentationhost.exe", "Print.exe", "Psr.exe", "Pwsh.exe", "Rasautou.exe", "Reg.exe", "Regasm.exe", "Regedit.exe", "Regini.exe", "Register-cimprovider.exe", "Regsvcs.exe", "Regsvr32.exe", "Replace.exe", "Rpcping.exe", "Rundll32.exe", "Runonce.exe", "Runscripthelper.exe", "Sc.exe", "Schtasks.exe", "Scriptrunner.exe", "SyncAppvPublishingServer.exe", "Ttdinject.exe", "Tttracer.exe", "vbc.exe", "Verclsid.exe", "Wab.exe", "Wmic.exe", "Wscript.exe", "Wsreset.exe", "Xwizard.exe", "AgentExecutor.exe", "Appvlp.exe", "Bginfo.exe", "Cdb.exe", "csi.exe", "Devtoolslauncher.exe", "dnx.exe", "Dotnet.exe", "Dxcap.exe", "Mftrace.exe", "Msdeploy.exe", "msxsl.exe", "ntdsutil.exe", "rcsi.exe", "Sqldumper.exe", "Sqlps.exe", "SQLToolsPS.exe", "Squirrel.exe", "Svchost.exe", "te.exe", "Tracker.exe", "Update.exe", "Wsl.exe", "ipconfig.exe", "whoami.exe", "net.exe", "net1.exe"]);
let var1=DeviceProcessEvents
| where FileName endswith ".exe" and FolderPath has_any (@"\Windows\System32\colorcpl\",@"\Windows\SysWOW64\colorcpl\")
| where InitiatingProcessFileName in ("cscript.exe","wscript.exe","mshta.exe","winword.exe","excel.exe","outlook.exe","powerpnt.exe");
let var2=DeviceProcessEvents
| where InitiatingProcessFileName endswith ".exe" and InitiatingProcessFolderPath has_any (@"\Windows\System32\colorcpl\",@"\Windows\SysWOW64\colorcpl\") and FileName in~(lolbins);
union var1,var2
```

### EXCAVATOR

```c#
//https://github.com/fireeye/red_team_tool_countermeasures/blob/master/rules/EXCAVATOR/production/hxioc/EXCAVATOR (UTILITY).ioc
//Excavator is a tool for dumping the process via a service. It can also dump the process directly if not used as a service. 
//
// be mindful this is a very brittle detection, easy to bypass, only catches default behavior
let var1=DeviceFileEvents
| where FolderPath contains @"\windows\memory.dmp";
let var2=DeviceRegistryEvents
| where RegistryKey contains @"CurrentControlSet\services\iphlpsvc6\ImagePath";
let var3=DeviceProcessEvents
| where FileName contains "excavator.exe";
union var1,var2,var3
```

## DLL Hijack Section

Apart from looking at the results which process loaded it and triaging what happened before and after, also have a look at the signature and GlobalPrevalence information provided by the FileProfile function, this can contain very useful contextual information.

---

### api-ms-win-downlevel-shell32-l1-1-0.dll Hijack

```c#
//https://github.com/fireeye/red_team_tool_countermeasures/blob/master/rules/PGF/supplemental/hxioc/api-ms-win-downlevel-shell32-l1-1-0.dll Hijack (Methodology).ioc
//Identifies possible DLL search order hijacking of api-ms-win-downlevel-shell32-l1-1-0.dll based on image loads from unexpected locations.
DeviceImageLoadEvents
| where FileName =~ "api-ms-win-downlevel-shell32-l1-1-0.dll"
| where not(FolderPath has_any (@"\Windows\System32",
@"\Windows\SysWOW64",
@"\Windows\WinSxS",
@"\Program Files\Softing\",
@"\Device\HarddiskVolume",
@"Windows\SoftwareDistribution\"
))
| where not(FolderPath matches regex "[A-F0-9]{8}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{12}")
| invoke FileProfile(SHA1) 
```

### ashldres.dll Hijack

```c#
//https://github.com/fireeye/red_team_tool_countermeasures/blob/master/rules/PGF/supplemental/hxioc/ashldres.dll Hijack (Methodology).ioc
// Identifies possible DLL search order hijacking of ashldres.dll based on image loads from unexpected locations.
DeviceImageLoadEvents
| where FileName =~ "ashldres.dll"
| invoke FileProfile(SHA1) 
```

### ccl110u.dll Hijack

```c#
//https://github.com/fireeye/red_team_tool_countermeasures/blob/master/rules/PGF/supplemental/hxioc/ccl110u.dll Hijack (Methodology).ioc
//Identifies possible DLL search order hijacking of ccl110u.dll based on image loads from unexpected locations.
DeviceImageLoadEvents
| where FileName =~ "ccl110u.dll"
| invoke FileProfile(SHA1) 
```

### cclib.dll Hijack

```c#
//https://github.com/fireeye/red_team_tool_countermeasures/blob/master/rules/PGF/supplemental/hxioc/cclib.dll Hijack (Methodology).ioc
//Identifies possible DLL search order hijacking of cclib.dll based on image loads from unexpected locations.
DeviceImageLoadEvents
| where FileName =~ "cclib.dll"
| where not(FolderPath has_any (@"\Program Files (x86)\Symantec",
@"\Program Files\Symantec",
@"\ProgramData\Symantec",
@"\Program Files (x86)\Norton",
@"\Program Files\Norton",
@"\Symantec\Symantec Endpoint Protection",
@"\Endpoint Agent\ccLib.dll"
))
| invoke FileProfile(SHA1) 
```

### chrome_frame_helper.dll Hijack

```c#
//https://github.com/fireeye/red_team_tool_countermeasures/blob/master/rules/PGF/supplemental/hxioc/chrome_frame_helper.dll Hijack (Methodology).ioc
//Identifies possible DLL search order hijacking of chrome_frame_helper.dll based on image loads from unexpected locations.
let var1=DeviceImageLoadEvents
| where FileName =~ "chrome_frame_helper.dll"
| where not(FolderPath has_any (@"\AppData\Local\Google\Chrome\Application\",
@"\GoogleChromePortable\App\Chrome-bin\",
@"\Program Files (x86)\Google\Chrome\",
@"\Program Files (x86)\Google\Chrome\",
@"\Local Settings\Application Data\Google\Chrome\Application\"
));
let var2=DeviceFileEvents
| where FileName =~ "chrome_frame_helper.dll"
| where not(FolderPath has_any (@"\AppData\Local\Google\Chrome\Application\",
@"\GoogleChromePortable\App\Chrome-bin\",
@"\Program Files (x86)\Google\Chrome\",
@"\Program Files (x86)\Google\Chrome\",
@"\Local Settings\Application Data\Google\Chrome\Application\"
));
union var1,var2
| invoke FileProfile(SHA1) 
```

### crshhndl.dll Hijack

```c#
//https://github.com/fireeye/red_team_tool_countermeasures/blob/master/rules/PGF/supplemental/hxioc/crshhndl.dll Hijack (Methodology).ioc
//Identifies possible DLL search order hijacking of crshhndl.dll based on image loads from unexpected locations.
DeviceImageLoadEvents
| where FileName =~ "crshhndl.dll"
| where not(FolderPath has_any (@"\TortoiseSVN\bin\",
@"\TortoiseGit\bin\"
))
| invoke FileProfile(SHA1) 
```

### dismcore.dll Hijack

```c#
//https://github.com/fireeye/red_team_tool_countermeasures/blob/master/rules/PGF/supplemental/hxioc/dismcore.dll Hijack (Methodology).ioc
//Identifies possible DLL search order hijacking of DismCore.dll based on image loads from unexpected locations.
DeviceImageLoadEvents
| where FileName =~ "dismcore.dll"
| where not(FolderPath has_any (@"\Windows\System32",
@"\Windows\SysWOW64",
@"\Windows\WinSxS",
@"\ProgramData\docker\windowsfilter\",
@"\Program Files (x86)\Quest\KACE",
@"\Program Files\Quest\KACE"
))
| where not(FolderPath matches regex "[A-F0-9]{8}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{12}")
| where InitiatingProcessFolderPath != @"c:\$windows.~bt\sources\setuphost.exe"
| invoke FileProfile(SHA1) 
```

### dwmapi.dll Hijack

```c#
//https://github.com/fireeye/red_team_tool_countermeasures/blob/master/rules/PGF/supplemental/hxioc/dwmapi.dll Hijack (Methodology).ioc
//Identifies possible DLL search order hijacking of dwmapi.dll based on image loads from unexpected locations.
DeviceImageLoadEvents
| where FileName =~ "dwmapi.dll"
| where not(FolderPath has_any (@"\Windows\System32",
@"\Windows\SysWOW64",
@"\Windows\WinSxS",
@"\Program Files\Common Files\microsoft shared\ink",
@"\Windows\System32\sysprep",
@"\Program Files\Windows Sidebar",
@"\Device\HarddiskVolume"
))
| invoke FileProfile(SHA1) 
```

### elogger.dll Hijack

```c#
//https://github.com/fireeye/red_team_tool_countermeasures/blob/master/rules/PGF/supplemental/hxioc/elogger.dll Hijack (Methodology).ioc
//Identifies possible DLL search order hijacking of elogger.dll based on image loads from unexpected locations.
DeviceImageLoadEvents
| where FileName =~ "elogger.dll"
| where not(FolderPath has_any (@"\Program Files\Leica Microsystems CMS GmbH"))
| invoke FileProfile(SHA1) 
```

### fmtoptions.dll Hijack

```c#
//https://github.com/fireeye/red_team_tool_countermeasures/blob/master/rules/PGF/supplemental/hxioc/fmtoptions.dll Hijack (Methodology).ioc
//Identifies possible DLL search order hijacking of fmtoptions.dll based on image loads from unexpected locations.
DeviceImageLoadEvents
| where FileName =~ "fmtoptions.dll"
| where not(FolderPath has_any (@"\Program Files\Quest Software\",
@"\Program Files (x86)\Quest Software"
))
| invoke FileProfile(SHA1) 
```

### goopdate.dll Hijack

```c#
//https://github.com/fireeye/red_team_tool_countermeasures/blob/master/rules/PGF/supplemental/hxioc/goopdate.dll Hijack (Methodology).ioc
//Identifies possible DLL search order hijacking of goopdate.dll based on image loads from unexpected locations.
DeviceImageLoadEvents
| where FileName =~ "goopdate.dll"
| where not(FolderPath has_any (@"\Program Files (x86)\GUM\",
@"\Program Files\GUM\",
@"\Program Files (x86)\Nok Nok Labs\MFACUpdater\",
@"\Program Files\Nok Nok Labs\MFACUpdater\",
@"\Device\HarddiskVolume",
@"\Program Files (x86)\Google\Update",
@"\Program Files\Google\Update",
@"\Program Files (x86)\Common Files\HCL\AutoUpdate\",
@"\Program Files\Common Files\HCL\AutoUpdate\"
))
| where FolderPath matches regex "(Update|Installer)\\[0-9.]" and FolderPath contains @"\AppData\Local"
| invoke FileProfile(SHA1) 
```

### hpcustpartui.dll Hijack

```c#
//https://github.com/fireeye/red_team_tool_countermeasures/blob/master/rules/PGF/supplemental/hxioc/hpcustpartui.dll Hijack (Methodology).ioc
//Identifies possible DLL search order hijacking of hpcustpartui.dll based on image loads from unexpected locations.
DeviceImageLoadEvents
| where FileName =~ "hpcustpartui.dll"
| where not(FolderPath has_any (@"\Program Files\HP\HP ",
@"\Program Files (x86)\HP\HP ",
@"\Program Files (x86)\Trend Micro\",
@"\Program Files\Trend Micro\"
))
| invoke FileProfile(SHA1) 
```

### mcutil.dll Hijack

```c#
//https://github.com/fireeye/red_team_tool_countermeasures/blob/master/rules/PGF/supplemental/hxioc/mcutil.dll Hijack (Methodology).ioc
//Identifies possible DLL search order hijacking of  mcutil.dll based on image loads from unexpected locations.
DeviceImageLoadEvents
| where FileName =~ "mcutil.dll"
| where not(FolderPath has_any (@"\Program Files\Common Files\McAfee",
@"\Program Files (x86)\Common Files\McAfee\",
@"\Program Files (x86)\McAfee\",
@"\Program Files\McAfee\",
@"\Program Files\McAfee Security Scan\",
@"\Program Files (x86)\McAfee Security Scan\",
@"\AppData\Local\Temp\McAfeeSafeConnect\",
@"Program Files\MagicInfo Premium\",
@"Program Files\Media Cybernetics\"
))
| invoke FileProfile(SHA1) 
```

### mscorsvc.dll Hijack

```c#
//https://github.com/fireeye/red_team_tool_countermeasures/blob/master/rules/PGF/supplemental/hxioc/mscorsvc.dll Hijack (Methodology).ioc
//Identifies possible DLL search order hijacking of mscorsvc.dll based on image loads from unexpected locations.
DeviceImageLoadEvents
| where FileName =~ "mscorsvc.dll"
| where not(FolderPath has_any (@"\Windows\Microsoft.NET\Framework",
@"\Windows\Microsoft.NET\Framework64",
@"\Windows\WinSxS\",
@"\Device\HarddiskVolume\"
))
| invoke FileProfile(SHA1) 
```

### msi.dll Hijack

```c#
//https://github.com/fireeye/red_team_tool_countermeasures/blob/master/rules/PGF/supplemental/hxioc/msi.dll Hijack (Methodology).ioc
//Identifies possible DLL search order hijacking of msi.dll based on image loads from unexpected locations.
DeviceImageLoadEvents
| where FileName =~ "msi.dll"
| where not(FolderPath has_any (@"\Windows\System32",
    @"\Windows\SysWOW64",
    @"\Windows\WinSxS",
    @"\Device\HarddiskVolume"
))
```

### nflogger Hijack

```c#
//https://github.com/fireeye/red_team_tool_countermeasures/blob/master/rules/PGF/supplemental/hxioc/nflogger.dll Hijack (Methodology).ioc
//Identifies possible DLL search order hijacking of nflogger.dll based on image loads from unexpected locations.
DeviceImageLoadEvents
| where FileName =~ "nflogger.dll"
| invoke FileProfile(SHA1) 
```

### PackageIdentification.dll Hijack

```c#
//https://github.com/fireeye/red_team_tool_countermeasures/blob/master/rules/PGF/supplemental/hxioc/PackageIdentification.dll Hijack (Methodology).ioc
//Identifies possible DLL search order hijacking of PackageIdentification.dll based on image loads from unexpected locations.
DeviceImageLoadEvents
| where FileName =~ "PackageIdentification.dll"
| where not(FolderPath has_any (@"Program Files (x86)\Citrix\ICA Client\Receiver",
        @"Program Files\Citrix\ICA Client",
        @"AppData\Local\Citrix\ICA Client\Receiver",
        @"Program Files (x86)\Citrix\Online Plugin\Receiver",
        @"Program Files\Citrix\Online Plugin\Receiver",
        @"Program Files (x86)\Citrix\Receiver\Receiver",
        @"Program Files\Citrix\Receiver\Receiver"
        ))
| where not(FolderPath contains @"Program Files\WindowsApps\" and FolderPath endswith @"\ICA Client\Receiver\PackageIdentification.dll")
```

### PotPlayer.dll Hijack

```c#
//https://github.com/fireeye/red_team_tool_countermeasures/blob/master/rules/PGF/supplemental/hxioc/PotPlayer.dll Hijack (Methodology).ioc
//Identifies possible DLL search order hijacking of PotPlayer.dll based on image loads from unexpected locations.
DeviceImageLoadEvents
| where FileName =~ "PotPlayer.dll"
| where not(FolderPath has_any (@"Program Files (x86)\DAUM\PotPlayer",
        @"Program Files\DAUM\PotPlayer",
        @"Program Files (x86)\Final Codecs\",
        @"Program Files\Final Codecs\"
        ))
| where not(InitiatingProcessFileName =~ "PotPlayerMini.exe")
```

### pc2msupp.dll Hijack

```c#
//https://github.com/fireeye/red_team_tool_countermeasures/blob/master/rules/PGF/supplemental/hxioc/pc2msupp.dll Hijack (Methodology).ioc
//Identifies possible DLL search order hijacking of pc2msupp.dll based on image loads from unexpected locations.
DeviceImageLoadEvents
| where FileName =~ "pc2msupp.dll"
| where not(FolderPath has_any (@"\Program Files\Quick Heal\",
    @"\Program Files\Quick Heal\"
))
| invoke FileProfile(SHA1) 
```

### pt1.aym Hijack

```c#
//https://github.com/fireeye/red_team_tool_countermeasures/blob/master/rules/PGF/supplemental/hxioc/pt1.aym Hijack (Methodology).ioc
//Identifies possible DLL search order hijacking of pt1.aym based on image loads from unexpected locations.
DeviceImageLoadEvents
| where FileName =~ "pt1.aym"
| invoke FileProfile(SHA1) 
```

### sidebar.dll Hijack

```c#
//https://github.com/fireeye/red_team_tool_countermeasures/blob/master/rules/PGF/supplemental/hxioc/sidebar.dll Hijack (Methodology).ioc
//Identifies possible DLL search order hijacking of sidebar.dll based on image loads from unexpected locations.
DeviceImageLoadEvents
| where FileName =~ "sidebar.dll"
| invoke FileProfile(SHA1) 
```

### splash_screen.dll Hijack

```c#
//https://github.com/fireeye/red_team_tool_countermeasures/blob/master/rules/PGF/supplemental/hxioc/splash_screen.dll Hijack (Methodology).ioc
//Identifies possible DLL search order hijacking of splash_screen.dll based on image loads from unexpected locations.
DeviceImageLoadEvents
| where FileName =~ "splash_screen.dll"
| invoke FileProfile(SHA1) 
```

### tmas_wlmhook.dll Hijack

```c#
//https://github.com/fireeye/red_team_tool_countermeasures/blob/master/rules/PGF/supplemental/hxioc/tmas_wlmhook.dll Hijack (Methodology).ioc
//Identifies possible DLL search order hijacking of tmas_wlmhook.dll based on image loads from unexpected locations.
DeviceImageLoadEvents
| where FileName =~ "tmas_wlmhook.dll"
| invoke FileProfile(SHA1) 
```

### ui.dll Hijack

```c#
//https://github.com/fireeye/red_team_tool_countermeasures/blob/master/rules/PGF/supplemental/hxioc/ui.dll Hijack (Methodology).ioc
//Identifies possible DLL search order hijacking of ui.dll based on image loads from unexpected locations.
DeviceImageLoadEvents
| where FileName =~ "ui.dll"
| where not(FolderPath has_any (@"\Program Files\PDF Architect ",
    @"\Program Files (x86)\PDF Architect ",
    @"\ProgramData\Citrix\",
    @"Program Files (x86)\Intuit\",
    @"Program Files\Intuit\",
    @"\Program Files\Autodesk\",
    @"\Program Files (x86)\Autodesk\",
    @"\Program Files\Common Files\Autodesk Shared\",
    @"\Program Files (x86)\Common Files\Autodesk Shared\",
    @"\Program Files\MTS Systems\",
    @"\Program Files\Adobe\",
    @"\Program Files (x86)\Adobe\",
    @"\Program Files\Manufacturer\Endpoint Agent\",
    @"\Program Files (x86)\ABB\"
))
| invoke FileProfile(SHA1) 
```

### ushata.dll Hijack

```c#
//https://github.com/fireeye/red_team_tool_countermeasures/blob/master/rules/PGF/supplemental/hxioc/ushata.dll Hijack (Methodology).ioc
//Identifies possible DLL search order hijacking of ushata.dll based on image loads from unexpected locations.
DeviceImageLoadEvents
| where FileName =~ "ushata.dll"
| where not(FolderPath has_any (@"\Program Files (x86)\Kaspersky Lab\Kaspersky",
    @"\Program Files\Kaspersky Lab\Kaspersky",
    @"\Program Files (x86)\LANDesk\LDClient\antivirus\"
))
| invoke FileProfile(SHA1) 
```
