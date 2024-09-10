# TGT requested with suspicious certificate

## Metadata
**ID:** 0xFF-0298-TGT_requested_with_suspicious_certificate-Win

**OS:** WindowsEndpoint, WindowsServer

**FP Rate:** Low

---

## ATT&CK Tags

| Tactic | Technique | Subtechnique | Technique Name |
|---|---|---| --- |
| TA0005 - Defense Evasion | T1550 | 003 | Use Alternate Authentication Material - Pass the Ticket|
| TA0006 - Credential Access | T1558 | 002 | Steal or Forge Kerberos Tickets - Silver Ticket|

## Utilized Data Sources

| Log Provider | Event ID | Event Name | ATT&CK Data Source | ATT&CK Data Component|
|---------|---------|----------|---------|---------|
|SecurityEvents|4768||Active Directory|Active Directory Credential Request|
---

## Technical description of the attack
This query looks for TGT requests where the user authenticated with a client certificate which is unexpected for the environment.
In most environments there are a number of use-cases for using client certificates.

1) 802.1X "Network Access Control" (NAC) - It's usually a machine account authenticating with a machine certificate.
2) AzureAD SSO - The signer is "login.windows.net"
3) Smartcard authentication for users - This can be distinguished by a specific issuer and certificate format.

## Permission required to execute the technique
User

## Detection description
Attackers abusing vulnerabilities in ADCS at some point need to authenticate against AD to obtain a valid Kerberos TGT ticket. This detection will trigger whenever an attacker requests a TGT with a certificate which has properties which are suspicious.


## Considerations
This detection doesn't work in all environments. Depending on the environment, it might be unfeasible to detect suspicious TGT requests based
on the certificates.


## False Positives
This detection requires careful tuning to make sure all common TGT requests based on certificate authentication are filtered out. If tuned properly, this detection will result in limited false positives.


## Suggested Response Actions
If the rule has been tuned properly and doesn't produce false positives, consider blocking accounts automatically (or manually) whenever a TGT is requested with a suspicious certificate. Investigate in the logs when the certificate has been requested, how it has been used before and why the user is authenticating with a certificate all of a sudden.


## Detection Blind Spots
Attackers can use certificates which have the same format as the "commonly-used" certificates. However, commonly-used is very dependant on the environment and attackers usually don't have visibility in which certificates are used and how they're formatted.


## References
* https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4768
* https://github.com/ly4k/Certipy#authenticate
* https://github.com/GhostPack/Certify#using-requested-certificates

---
## Detection

**Language:** Kusto

**Platform:** Sentinel

**Query:**
```C#
let timeframe = 2*1h;
let RuleId = "0298";
let DedupFields = dynamic(["TimeGenerated"]);
SecurityEvent
| where ingestion_time() >= ago(timeframe)
| where EventID == 4768
| extend CertIssuerName = extract("<Data Name=\"CertIssuerName\">(.*?)</Data>", 1, EventData)
| extend CertSerialNumber = extract("<Data Name=\"CertSerialNumber\">(.*?)</Data>", 1, EventData)
| where not(isempty(CertIssuerName)) // No certificate used for authentication.
| where not(CertIssuerName has "/login.windows.net/") // Attackers abusing existing certificate templates can't fake the issuer, so this check is sufficient.
| where not(CertIssuerName matches regex @"(?i)^MS-Organization-P2P-Access \[\d\d\d\d\]$")
| extend HostCustomEntity=tostring(split(Computer,".")[0])
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
| 1.0  | 2022-07-05| major | Initial version. |