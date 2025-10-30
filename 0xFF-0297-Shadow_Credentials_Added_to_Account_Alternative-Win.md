# Shadow Credentials Added to Account (Alternative)

## Metadata
**ID:** 0xFF-0297-Shadow_Credentials_Added_to_Account_Alternative-Win

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
|SecurityEvents|SecurityEvent|4662||Active Directory|Active Directory Object Modification|
---

## Detection description
This query searches for modifications to the 'msDS-KeyCredentialLink' property in Active Directory. There are two different events which contain information to detect such changes: 5136 and 4662. This detection uses the 4662, which is an alternative if 5136 is not available.



## Permission required to execute the technique
Administrator


## Description of the attack
Windows Hello for Business (WHfB) supports multi-factor passwordless authentication. When the user or computer enrolls, the TPM generates a public-private key pair for the relevant account. The public key is stored in a new Key Credential object in the msDS-KeyCredentialLink attribute of the account. When a client logs in, Windows attempts to perform PKINIT authentication using their private key. Under the Key Trust model, the Domain Controller can decrypt their pre-authentication data using the raw public key in the corresponding NGC object stored in the client's msDS-KeyCredentialLink attribute. Attackers can abuse this property to gain local administrator access to a computer. Various attack tools such as Whisker, DSInternals and ntlmrelayx include functionality to modify this property.


## Considerations
This query requires event 4662 (Active Directory object operations) to be logged. This attack can also be detected with event 5136, which
is the preferred option. Detecting this attack with event 4662 is a backup strategy in case 5136 is not available in your environment.


## False Positives
The property can also be used for legitimate purposes. However, the legitimate use of the property is limited in most environments.


## Suggested Response Actions
Investigate the source of the update to the 'msDS-KeyCredentialLink' property.


## Detection Blind Spots
Accounts changing their own 'msDS-KeyCredentialLink' property are excluded from this detection rule, since this behavior periodically happens for legitimate purposes, e.g., when updating Windows Hello for Business [WHfB] certificates. As a result, abusing this issue with an NTLM relay attack would not trigger this rule.


## References
* https://docs.microsoft.com/en-us/defender-for-identity/configure-windows-event-collection
* https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4662
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
let RuleId = "0297";
let DedupFields = dynamic(["TimeGenerated"]);
SecurityEvent
| where ingestion_time() >= ago(timeframe)
| where EventID == 4662
| where Properties has "5b47d60f-6090-40b2-9f37-2a4de88f3063" // msDS-KeyCredentialLink.
| where Properties has "%%7685" or (binary_and(toint(AccessMask), 0x10) == 0x10) // "Write Property" or "Write Extended Attributes": https://gist.github.com/brianreitz/d5b9397a2e8b3d52ceb9359897e07c3f
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
| 1.2  | 2025-05-19| minor | Updated entity mapping to remove deprecated FullName field. |
| 1.1  | 2024-02-02| minor | Added logic to include attempts to write extended attributes. This can be used to detect failed attempts to update the shadow credential link. |
| 1.0  | 2022-06-17| major | Initial version. |