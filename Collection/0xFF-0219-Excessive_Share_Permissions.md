Note: You are viewing an old, archived version of this content. The latest version is available in the ['main' branch](https://github.com/FalconForceTeam/FalconFriday/blob/main/0xFF-0219-Excessive_Share_Permissions.md).

# Excessive Share Permissions

## Metadata
**OS:** WindowsEndpoint, WindowsServer

**FP Rate:** Medium

---

## ATT&CK Tags

| Tactic | Technique | Subtechnique | Technique Name |
|---|---|---| --- |
| TA0009 - Collection | T1039 |  | Data from Network Shared Drive|
| TA0007 - Discovery | T1135 |  | Network Share Discovery|

## Utilized Data Sources

| Log Provider | Event ID | Event Name | ATT&CK Data Source |
|---------|---------|----------|---------|
|WindowsLog_Security|5143| A network share object was modified | Network Share:Network Share Access|
---

## Technical description of the attack
The query searches for event 5143, which is triggered when a share is created or changed and includes de share permissions. First it checks to see if this is a whitelisted share for the system (e.g. domaincontroller netlogn, printserver print$ etc.) The share permissions are then checked against 'allow' rule (A) for a number of well known overly permissive groups, like all users, guests, authenticated users etc. If these are found, an alert is raised so the share creation may be audited. This rule only checks for changed permissions, to prevent repeat alerts if for example a comment is changed, but the permissions are not altered.


## Permission required to execute the technique
Administrator

## Detection description
Often times, sensitive data is found on overly permissive shares. This can lead to an easy escalation path which is hard to track down. By monitoring permissions for new and updated shares, such overly permissive shares can be detected.


## Considerations
Requires the audit policy 'Audit File Share' to be enabled. May generate a large amount of events as all share (file) interactions are logged as event 5140. Requires some configuration of whitelisted shares, for example:
      let system_roles = datatable(role:string, system:string)                  // Link roles to systems
      ["DC","dc1.corp.local",
      "DC","dc2.corp.local",
      "PRINT","printer.corp.local"
      ];
    let share_roles = datatable(role:string, share:string)                    // Link roles to shares
      ["DC", @"\\*\sysvol",
      "DC",@"\\*\netlogon",
      "PRINT",@"\\*\print$"];
Also requires configuration of monitored monitored_principals
      let monitored_principals=datatable(identifier:string, Group_Name:string)  // Define a data-table with groups to monitor
      ["AN", "Anonymous Logon",                                               // We accept the 'alias' for these well-known SIDS
      "AU", "Authenticated Users",
      "BG","Built-in guests",
      "BU","Built-in users",
      "DG","Domain guests",
      "DU","Domain users",
      "WD","Everyone",
      "IU","Interactively Logged-on users",
      "LG","Local Guest",
      "NU","Network logon users",
      "513", "Domain Users",                                                  // Support matching on the last part of a SID
      "514", "Domain Guests",
      "545", "Builtin Users",
      "546", "Builtin Guests",
      "S-1-5-7", "Anonymous Logon" // For the global SIDS, we accept them as-is
      ];


## False Positives
Services which routinely (re)create public shares for valid reasons may generate an excessive numer of events. Such systems/services may require explicit whitelisting of specific shares on specific sytems. - Domain Controller SYSVOL/NETLOGON shares - SCCM Shares - DFS Shares These can be defined through the datashares and roles.


## Suggested Response Actions
Investigate the creation of the share. Ascertain if it really should be as permissive as it is steup.


## Detection Blind Spots
This query only searches for a set of known overly-permissive groups (e.g. well-known SIDs) Domain-specific groups which are not suitable for share creation need to be added to the query manually. These can be added in the datatable / filter 'monitored_principals'.


## References
* https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-file-share
* https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5143
* https://docs.microsoft.com/en-us/windows/win32/secauthz/well-known-sids

---

## Detection

**Language:** Kusto

**Platform:** Sentinel

**Query:**
```C#
let timeframe={{ timeframe | default('1h') }};
let system_roles = datatable(role:string, system:string)                  // Link roles to systems
  [{{ role_system_mapping | default('"DC","dc1.corp.local",
  "DC","dc2.corp.local",
  "PRINT","printer.corp.local') }}
  ];
let share_roles = datatable(role:string, share:string)                    // Link roles to shares
  [{{ role_share_mapping |  default('"DC", @"\\\\*\\sysvol",
  "DC",@"\\\\*\\netlogon",
  "PRINT",@"\\\\*\\print$"') }}];
let allowed_system_shares = system_roles                                  // Link systems to shares
  | join kind=inner share_roles on role
  | extend system = tolower(system), share = tolower(share)
  | project-away role
  | summarize allowed_shares = make_set(share) by system;
let monitored_principals=datatable(identifier:string, Group_Name:string)  // Define a data-table with groups to monitor
  [{{ monitored_principals | default('"AN", "Anonymous Logon",                                               // We accept the \'alias\' for these well-known SIDS
  "AU", "Authenticated Users",
  "BG","Built-in guests",
  "BU","Built-in users",
  "DG","Domain guests",
  "DU","Domain users",
  "WD","Everyone",
  "IU","Interactively Logged-on users",
  "LG","Local Guest",
  "NU","Network logon users",
  "513", "Domain Users",                                                  // Support matching on the last part of a SID
  "514", "Domain Guests",
  "545", "Builtin Users",
  "546", "Builtin Guests",
  "S-1-5-7", "Anonymous Logon" // For the global SIDS, we accept them as-is') }}
  ];
SecurityEvent
| where TimeGenerated >= ago(timeframe)
| where EventID == 5143
{{ pre_filter_1 }}
| extend EventXML = parse_xml(EventData)
| extend OldSD = tostring(EventXML["EventData"]["Data"][13]["#text"])     // Grab the previous Security Descriptor
| extend NewSD = tostring(EventXML["EventData"]["Data"][14]["#text"])     // Grab the new Security Descriptor
| project-away EventXML
| where tostring(OldSD) !~ tostring(NewSD)                                // Don't bother with unchagned permissions
| extend system = tolower(Computer), share=tolower(ShareName)             // Normalize system & sharename for matching with whitelist
| join kind=leftouter allowed_system_shares on system                     // Retrieve the allowed shares per system
| where not(set_has_element(allowed_shares, share))                       // Check if the current share is an allowed share
| project-away system, share, allowed_shares                              // Get rid of temporary fields
| extend DACLS = extract_all(@"(D:(?:\((?:[\w\-]*;){5}(?:[\w\-]*)\))*)", tostring(NewSD)) //Grab all isntances of D:(DACL), in case there are multiple sets.
| project-away OldSD, NewSD                                               // Get rid of data we no longer need
| mv-expand DACLS to typeof(string)                                       // In case there are any duplicate/subsequent D: entrys (e.g. D:<dacls>S:<sacls>D:<dacls>) split them out to individual D: sets
| extend DACLS = substring(DACLS,2)                                       // Strip the leading D:
| extend DACLS = split(DACLS, ")")                                        // Split the sets of DACLS ()() to an array of individual DACLS (), this removes the trailing ) character
| mv-expand DACLS to typeof(string)                                       // Duplicate the records in such a way that only 1 dacl per record exist, we will aggregate them back later
| extend DACLS = substring(DACLS, 1)                                      // Also remove the leading ( character
| where not(isempty(DACLS)) and DACLS startswith "A;"                     // Remove any empty or non-allow DACLs
| extend allowed_principal = tostring(split(DACLS,";",5)[0])              // Grab the SID what is affected by this DACL
| extend allowed_principal = iff(not(allowed_principal startswith "S-" and string_size(allowed_principal) > 15), allowed_principal, split(allowed_principal,"-",countof(allowed_principal,"-"))[0]) //This line takes only the last part (e.g. 513) of a long SID, so you can refer to groups/users without needing to supply the full SID above.
| join kind=inner monitored_principals on $left.allowed_principal == $right.identifier //Join the found groups to the table of groups to be monitored above, adds the more readable 'group_name)
| project-away allowed_principal, identifier, DACLS
| summarize Authorized_Public_Principals = make_set(Group_Name), take_any(*) by TimeGenerated, SourceComputerId, EventData //Summarize the fields back, making a set of the various group_name values for this record
| project-away Group_Name
{{ post_filter_1 }}

```


---

## Version History
| Version | Date | Impact | Notes |
|---------|------|--------|------|
| 1.0  | 2021-12-16| major | Initial version |
