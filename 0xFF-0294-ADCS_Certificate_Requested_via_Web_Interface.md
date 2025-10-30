# ADCS Certificate Requested via Web Interface

## Metadata
**ID:** 0xFF-0294-ADCS_Certificate_Requested_via_Web_Interface

**OS:** WindowsServer

---

## ATT&CK Tags

| Tactic | Technique | Subtechnique | Technique Name |
|---|---|---| --- |
| TA0006 - Credential Access | T1556 |  | Modify Authentication Process|

## Utilized Data Sources

| Log Provider | Table Name | Event ID | Event Name | ATT&CK Data Source | ATT&CK Data Component|
|---------|---------|---------|----------|---------|---------|
|AzureMonitor(IIS)|W3CIISLog|W3CIISLog||Application Log|Application Log Content|
---

## Detection description
This query uses IIS logs to identify certificates requested via the web interface. In the first step, ADCS servers are listed by looking for an ADCS specific Uri Stem in the IIS logs events. A hard-coded ADCS server list can also be provided as environment variable instead (adcs_server_list). In a second step, requests to these servers done via the web interface are identified by looking for POST to a '/certsrv/certfnsh.asp' Uri.



## Permission required to execute the technique
User


## Description of the attack
This query looks for ADCS certificates being requested via the web interface. This technique can be used by an attacker to modify authentication processes, in order to evade detection or elevate privileges.


## Considerations
This action is not malicious on its own, but should be quite rare. This event must be correlated with other events.


## False Positives
This rule will create noise if the web interface is a common way to request certificates in a given environment.


## Suggested Response Actions
Investigate whether the affected user requested the certificate for a valid business purpose.


## Detection Blind Spots
None expected.


## References
* https://thesecmaster.com/how-to-request-a-certificate-from-windows-adcs/

---
## Detection

**Language:** Kusto

**Platform:** Sentinel

**Query:**
```C#
let timeframe = 2*1h;
let RuleId = "0294";
let DedupFields = dynamic(["TimeGenerated"]);
// List ADCS servers.
let ADCSsrv = dynamic(["ADCS01.test.lab", "ADCS02.test.lab"]);
// Cert request via web interface.
W3CIISLog
| where ingestion_time() >= ago(timeframe)
| where Computer in~ (ADCSsrv)
| where not(csMethod in~ ("GET","HEAD"))
| where csUriStem =~ "/certsrv/certfnsh.asp"
| extend HostName=tostring(split(Computer,".")[0]),DnsDomain=iif(Computer contains ".", substring(Computer, indexof(Computer, ".") + 1, strlen(Computer)),"")
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
| 1.1  | 2022-07-06| minor | Modified query to use ingestion_time() instead of TimeGenerated. |
| 1.0  | 2022-06-08| major | Initial version. |