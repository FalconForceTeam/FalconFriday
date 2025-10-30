# Excessive Share Permissions

## Metadata
**ID:** 0xFF-0219-Excessive_Share_Permissions

**OS:** WindowsEndpoint, WindowsServer

---

## ATT&CK Tags

| Tactic | Technique | Subtechnique | Technique Name |
|---|---|---| --- |
| TA0009 - Collection | T1039 |  | Data from Network Shared Drive|
| TA0007 - Discovery | T1135 |  | Network Share Discovery|

## Utilized Data Sources

| Log Provider | Table Name | Event ID | Event Name | ATT&CK Data Source | ATT&CK Data Component|
|---------|---------|---------|----------|---------|---------|
|SecurityEvents|SecurityEvent|5143||Network Share|Network Share Access|
---

## Detection description
This query searches for event 5143, which is triggered when a share is created or changed and includes the share permissions. First it checks to see if this is an allow-listed share for the system (e.g., domain controller netlogon, print server print$, etc.) The share permissions are then checked against 'allow' rule (A) for a number of well-known overly permissive groups, like All Users, Guests, Authenticated Users, etc. If these are found, an alert is raised so the share creation may be audited. This rule only checks for changed permissions. This is to prevent repeated alerts if, for example, a comment is changed, but the permissions have not been altered.



## Permission required to execute the technique
Administrator


## Description of the attack
Sensitive data is often found on overly permissive shares. This can lead to an easy escalation path which is hard to track down. By monitoring permissions for new and updated shares, such overly permissive shares can be detected.


## Considerations
Requires the audit policy 'Audit File Share' to be enabled. May generate a large number of events as all share (file) interactions are logged as event 5140. Requires some configuration of allow-listed shares and monitored monitored_principals.


## False Positives
Services which routinely (re)create public shares for valid reasons may generate an excessive number of events. Such systems/services may require explicit allow-listing of specific shares on specific systems. - Domain Controller SYSVOL/NETLOGON shares. - SCCM shares. - DFS shares. These can be defined through the data-shares and roles.


## Suggested Response Actions
Investigate the creation of the share. Ascertain if it really should be as permissive as it is set up.


## Detection Blind Spots
This query only searches for a set of known overly-permissive groups (e.g., well-known SIDs). Domain-specific groups which are not suitable for share creation need to be added to the query manually. These can be added in the data-table / filter 'monitored_principals'.


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
let timeframe = 2*1h;
let RuleId = "0219";
let DedupFields = dynamic(["TimeGenerated"]);
let system_roles = datatable(role:string, system:string)                  // Link roles to systems.
  ["DC","dc1.corp.local",
  "DC","dc2.corp.local",
  "PRINT","printer.corp.local"
  ];
let share_roles = datatable(role:string, share:string)                    // Link roles to shares.
  ["DC", @"\\*\sysvol",
  "DC",@"\\*\netlogon",
  "PRINT",@"\\*\print$"];
let allowed_system_shares = system_roles                                  // Link systems to shares.
  | join kind=inner share_roles on role
  | extend system = tolower(system), share = tolower(share)
  | project-away role
  | summarize allowed_shares = make_set(share) by system;
let monitored_principals=datatable(identifier:string, Group_Name:string)  // Define a data-table with groups to monitor.
  ["AN", "Anonymous Logon",            // We accept the 'alias' for these well-known SIDS.
  "AU", "Authenticated Users",
  "BG","Built-in guests",
  "BU","Built-in users",
  "DG","Domain guests",
  "DU","Domain users",
  "WD","Everyone",
  "IU","Interactively Logged-on users",
  "LG","Local Guest",
  "NU","Network logon users",
  "513", "Domain Users",                                                  // Support matching on the last part of a SID.
  "514", "Domain Guests",
  "545", "Builtin Users",
  "546", "Builtin Guests",
  "S-1-5-7", "Anonymous Logon"                                            // For the global SIDS, we accept them as-is.
  ];
SecurityEvent
| where ingestion_time() >= ago(timeframe)
| where EventID == 5143
| extend EventXML = parse_xml(EventData)
| extend OldSD = tostring(EventXML["EventData"]["Data"][13]["#text"])     // Grab the previous Security Descriptor.
| extend NewSD = tostring(EventXML["EventData"]["Data"][14]["#text"])     // Grab the new Security Descriptor.
| project-away EventXML
| where tostring(OldSD) !~ tostring(NewSD)                                // Don't bother with unchanged permissions.
| extend system = tolower(Computer), share=tolower(ShareName)             // Normalize system and share name for matching with allow-list.
| join kind=leftouter allowed_system_shares on system                     // Retrieve the allowed shares per system.
| where not(set_has_element(allowed_shares, share))                       // Check if the current share is an allowed share.
| project-away system, share, allowed_shares                              // Get rid of temporary fields.
| extend DACLS = extract_all(@"(D:(?:\((?:[\w\-]*;){5}(?:[\w\-]*)\))*)", tostring(NewSD)) // Grab all instances of D:(DACL), in case there are multiple sets.
| project-away OldSD, NewSD                                               // Get rid of data we no longer need.
| mv-expand DACLS to typeof(string)                                       // In case there are any duplicate/subsequent D: entries (e.g., D:<dacls>S:<sacls>D:<dacls>) split them out to individual D: sets.
| extend DACLS = substring(DACLS,2)                                       // Strip the leading D:.
| extend DACLS = split(DACLS, ")")                                        // Split the sets of DACLS ()() to an array of individual DACLS (). This removes the trailing ) character.
| mv-expand DACLS to typeof(string)                                       // Duplicate the records in such a way that only 1 DACL per record exist. We will aggregate them back later.
| extend DACLS = substring(DACLS, 1)                                      // Also remove the leading ( character.
| where not(isempty(DACLS)) and DACLS startswith "A;"                     // Remove any empty or non-allow DACLs.
| extend allowed_principal = tostring(split(DACLS,";",5)[0])              // Grab the SID what is affected by this DACL.
| extend allowed_principal = iff(not(allowed_principal startswith "S-" and string_size(allowed_principal) > 15), allowed_principal, split(allowed_principal,"-",countof(allowed_principal,"-"))[0]) // This line takes only the last part (e.g., 513) of a long SID, so you can refer to groups/users without needing to supply the full SID above.
| join kind=inner monitored_principals on $left.allowed_principal == $right.identifier // Join the found groups to the table of groups to be monitored above. Adds the more readable 'group_name).
| project-away allowed_principal, identifier, DACLS
| summarize Authorized_Public_Principals = make_set(Group_Name), take_any(*) by TimeGenerated, SourceComputerId, EventData // Summarize the fields back, making a set of the various group_name values for this record.
| project-away Group_Name
// Begin environment-specific filter.
// End environment-specific filter.
// Begin de-duplication logic.
| extend DedupFieldValues=pack_all()
| mv-apply e=DedupFields to typeof(string) on (
    extend DedupValue=DedupFieldValues[tostring(e)]
    | order by e // Sorting is required to ensure make_list is deterministic.
    | summarize DedupValues=make_list(DedupValue)
)
| extend DedupEntity=strcat_array(DedupValues, "|")
| project-away DedupFieldValues, DedupValues
| join kind=leftanti (
    SecurityAlert
    | where AlertName has RuleId and ProviderName has "ASI"
    | where TimeGenerated >= ago(timeframe)
    | extend DedupEntity = tostring(parse_json(tostring(parse_json(ExtendedProperties)["Custom Details"])).DedupEntity[0])
    | project DedupEntity
) on DedupEntity
// End de-duplication logic.
```

---

## Version History
| Version | Date | Impact | Notes |
|---------|------|--------|------|
| 1.2  | 2022-08-25| minor | Entity mapping added. |
| 1.1  | 2022-02-22| minor | Use ingestion_time for event selection and include de-duplication logic. |
| 1.0  | 2021-12-16| major | Initial version. |