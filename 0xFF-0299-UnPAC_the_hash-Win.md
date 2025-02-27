# UnPAC the hash

## Metadata
**ID:** 0xFF-0299-UnPAC_the_hash-Win

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
|SecurityEvents|4769||Active Directory|Active Directory Credential Request|
---

## Technical description of the attack
This query looks for an attack that allows an attacker with a valid TGT token for a certain account, to obtain the NTLM hash for that account. Such an account may either be a user account or a machine account. The TGT can, for example, be obtained by authenticating with a certificate instead of with username and password.


## Permission required to execute the technique
User

## Detection description
This query works by identifying TGS requests with KDC options that don't occur in normal AD environments. This detection looks for TGS requests where the KDC options `Renewable`, `Forwardable`, `Renewable_ok` and `Enc_tkt_in_skey` are set. This combination of options is unique for Certipy, Rubeus and Kekeo. More tools inspired by the implementation of these tools likely use the same options. The detection checks the presense of these 4 options, regardless which other options are set.


## Considerations
Rubeus and Certipy also set the `Canonicalize` options, besides the earlier mentioned options. Since we want our coverage to be
as broad as possible, we don't check for this KDC option. However, if this detection gives too many false positives in
an environment, you can consider to check for the presence of `Canonicalize` as well.


## False Positives
No false positives observed.


## Suggested Response Actions
Consider the account for which this rule triggered compromised. An attacker has access to the NTLM hash. For compromised machine accounts, it's unlikely that an attacker would be able to crack it. However, an attacker can use this hash to create local admin passwords for that machine at will.
For a normal user account which triggers this rule, consider the account compromised and stop using the account. Consider the ups and downs of keeping the account active vs blocking the account. The latter is usually a sufficient sign to an attacker that he/she has been caught. Choose strategically whether you want to share this insight with an attacker.


## Detection Blind Spots
Other tools with similar behavior, but less KDC options set, might slip through this rule. We haven't researched what the minimum set of KDC options is required to receive the correct information to unPAC-the-hash.


## References
* https://www.ietf.org/rfc/rfc4120.txt
* https://www.thehacker.recipes/ad/movement/kerberos/unpac-the-hash
* https://www.dsinternals.com/wp-content/uploads/eu-19-Grafnetter-Exploiting-Windows-Hello-for-Business.pdf
* https://dirkjanm.io/ntlm-relaying-to-ad-certificate-services/

---
## Detection

**Language:** Kusto

**Platform:** Sentinel

**Query:**
```C#
let timeframe = 2*1h;
let RuleId = "0299";
let DedupFields = dynamic(["TimeGenerated"]);
let forwardable = binary_shift_left(1, 30);
let renewable = binary_shift_left(1, 23);
let renewable_ok = binary_shift_left(1, 4);
let enctik = binary_shift_left(1, 3);
let krbflags = binary_or(forwardable, binary_or(renewable, binary_or(renewable_ok, binary_or(enctik, 0))));
SecurityEvent
| where ingestion_time() >= ago(timeframe)
| where EventID == 4769
| extend ticketOptions = toint(extract("<Data Name=\"TicketOptions\">(.*?)</Data>", 1, EventData))
| extend TargetUserName = extract("<Data Name=\"TargetUserName\">(.*?)@.*?</Data>", 1, EventData)
| extend ServiceName = extract("<Data Name=\"ServiceName\">(.*?)</Data>", 1, EventData)
| where ServiceName =~ TargetUserName // Requirement for getting the NT hash with U2U. This makes the KDC encrypt the NT hash with the key in the TGT.
| where binary_and(ticketOptions, krbflags) == krbflags
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
| 1.0  | 2022-06-17| major | Initial version. |