# Shadow Credentials Added to Account

## Metadata
**ID:** 0xFF-0275-Shadow_Credentials_Added_to_Account-Win

**OS:** WindowsEndpoint, WindowsServer

---

## ATT&CK Tags

| Tactic | Technique | Subtechnique | Technique Name |
|---|---|---| --- |
| TA0004 - Privilege Escalation | T1484 |  | Domain or Tenant Policy Modification|
| TA0003 - Persistence | T1098 |  | Account Manipulation|

## Utilized Data Sources

| Log Provider | Table Name | Event ID | Event Name | ATT&CK Data Source | ATT&CK Data Component|
|---------|---------|---------|----------|---------|---------|
|SecurityEvents|SecurityEvent|5136||Active Directory|Active Directory Object Modification|
---

## Detection description
This query searches for modifications to the 'msDS-KeyCredentialLink' property in Active Directory, introduced in Windows Server 2016. There are two different events which contain information to detect such changes 5136 and 4662. This detection uses the 5136, which is the preferred event to use.



## Permission required to execute the technique
Administrator


## Description of the attack
Windows Hello for Business (WHfB) supports multi-factor passwordless authentication. When the user or computer enrolls, the TPM generates a public-private key pair for the relevant account. The public key is stored in a new Key Credential object in the msDS-KeyCredentialLink attribute of the account. When a client logs in, Windows attempts to perform PKINIT authentication using their private key. Under the Key Trust model, the Domain Controller can decrypt their pre-authentication data using the raw public key in the corresponding NGC object stored in the client's msDS-KeyCredentialLink attribute. Attackers can abuse this property to gain local administrator access to a computer. Various attack tools such as Whisker, DSInternals and ntlmrelayx include functionality to modify this property.


## Considerations
This query requires event 5136 to be enabled to audit Active Directory object modifications. This attack can also be detected with
event 4662, which is an alternative option. Detecting this attack with event 4662 is a backup strategy in case 5136 is not available
in your environment.

To enable this event two steps are required:
* Enable 'Active Directory Service changes' under the 'Advanced Audit Policy configuration' in the 'DS Access' section.
* Enable a SACL for 'Write all properties' under the 'Advanced, Auditing' section of the domain in the 'Active Directory Users and Computers' tool.
A full explanation of these steps is available at https://morgantechspace.com/2013/11/event-id-5136-ad-object-change-audit-event.html


## False Positives
The property can also be used for legitimate purposes. However, the legitimate use of the property is limited in most environments.


## Suggested Response Actions
Investigate the source of the update to the 'msDS-KeyCredentialLink' property. The SubjectUserName indicates which user has changed this field. Use this together with the SubjectLogonId to identify from which machine this potential attack has been performed. Once the machine is found, investigate the process which triggered this behavior and try to find a reason why this has happend.
Also, consider the OperationType. This column provides a mapping of all operation types: https://gist.github.com/brianreitz/d5b9397a2e8b3d52ceb9359897e07c3f.


## Detection Blind Spots
Accounts changing their own 'msDS-KeyCredentialLink' property are excluded from this detection rule, since this behavior periodically happens for legitimate purposes, e.g., when updating Windows Hello for Business [WHfB] certificates. As a result, abusing this issue with an NTLM relay attack would not trigger this rule.


## References
* https://morgantechspace.com/2013/11/event-id-5136-ad-object-change-audit-event.html
* https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab
* https://github.com/ShutdownRepo/pywhisker
* https://github.com/MichaelGrafnetter/DSInternals

---
## Detection

**Language:** Kusto

**Platform:** Sentinel

**Query:**
```C#
let timeframe = 2*1h;
let RuleId = "0275";
let DedupFields = dynamic(["TimeGenerated", "SubjectUserName", "Computer"]);
SecurityEvent
| where ingestion_time() >= ago(timeframe)
| where EventID == 5136
| extend AttributeName = extract("<Data Name=\"AttributeLDAPDisplayName\">(.*?)</Data>", 1, EventData)
| extend ObjectDN = extract("<Data Name=\"ObjectDN\">(.*?)</Data>", 1, EventData)
| extend SubjectUserName = extract("<Data Name=\"SubjectUserName\">(.*?)</Data>", 1, EventData)
| where AttributeName has "msDS-KeyCredentialLink"
| where not(SubjectUserName endswith "$" and ObjectDN startswith strcat("CN=", replace_string(SubjectUserName, "$", ""), ",")) // Machine account changing its own msDS-KeyCredentialLink.
| extend HostName=tostring(split(Computer,".")[0]),DnsDomain=iif(Computer contains ".", substring(Computer, indexof(Computer, ".") + 1, strlen(Computer)),"")
| extend AccountName=iif(Account contains @"\",tostring(split(Account,@"\")[1]),Account),AccountDomain=iif(Account contains @"\",tostring(split(Account,@"\")[0]),"")
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
| 1.5  | 2025-05-19| minor | Updated entity mapping to remove deprecated FullName field. |
| 1.4  | 2023-04-20| minor | Fixed blindspot introduced due to performance update. |
| 1.3  | 2023-03-27| minor | Performance update. |
| 1.2  | 2023-01-30| minor | Added more details to the response plan. |
| 1.1  | 2022-06-17| minor | Improved rule logic to not rely on fixed indexes in the EventData. |
| 1.0  | 2022-04-20| major | Initial version. |