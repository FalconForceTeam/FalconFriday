# Large number of AD objects accessed by user

## Metadata
**ID:** 0xFF-0108-Large_number_of_AD_objects_accessed_by_user-Win

**OS:** WindowsServer

**FP Rate:** Medium

---

## ATT&CK Tags

| Tactic | Technique | Subtechnique | Technique Name |
|---|---|---| --- |
| TA0009 - Collection | T1119 |  | Automated Collection|
| TA0007 - Discovery | T1087 | 002 | Account Discovery - Domain Account|

## Utilized Data Sources

| Log Provider | Event ID | Event Name | ATT&CK Data Source | ATT&CK Data Component|
|---------|---------|----------|---------|---------|
|SecurityEvents|4662||Active Directory|Active Directory Object Access|
---

## Technical description of the attack
This query detects a user accessing a large number of Group and User objects from Active Directory which is outside the baseline of normal behavior for that particular user.


## Permission required to execute the technique
User

## Detection description
Attackers often abuse information from Active Directory, such as lists of domain users and groups, in order to determine attack paths. When large numbers of objects are accessed, this
could indicate usage of an AD collection tool such as Bloodhound.


## Considerations
If multiple attacks are performed with the same user account, this might lead to the baseline for that user being adjusted and only the first attack being detected.


## False Positives
There are legitimate use-cases for downloading large number of AD objects. For example, an administrator might run a script to extract all users as part of certain migration activities.


## Suggested Response Actions
Investigate if the user has a legitimate business purpose for accessing large numbers of Active Directory objects.


## Detection Blind Spots
If the attack is performed slowly, for example, with 5000 objects per day it can remain undetected.


## References
* http://www.stuffithoughtiknew.com/2019/02/detecting-bloodhound.html

---
## Detection

**Language:** Kusto

**Platform:** Sentinel

**Query:**
```C#
let timeframe = 2*1d;
let RuleId = "0108";
let DedupFields = dynamic(["TimeGenerated"]);
let lookback_days=14d; // Look back this many days to calculate baseline for maximum number of objects accessed per day.
let min_suspicious_count = 20000; // Only consider users looking up at least this many objects during the timeframe.
let suspicious_factor = 50; // Consider as suspicious if requesting more than suspicious_factor*daily maximum in lookback period.
let ADObjectAccess=(
    SecurityEvent
    | where EventID == 4662
    | where not(Account endswith "$")
    | where ObjectType in~ (
        "%{bf967aba-0de6-11d0-a285-00aa003049e2}", // User.
        "%{bf967a9c-0de6-11d0-a285-00aa003049e2}" //  Group.
    )
);
let AccessBaseline=(
    ADObjectAccess
    | where TimeGenerated <= ago(timeframe)
    | where TimeGenerated >= ago(timeframe + lookback_days)
    | summarize BaselineObjectCount=count() by Account, bin(TimeGenerated,1d)
    | summarize PreviousMaxObjectPerDay=max(BaselineObjectCount) by Account
);
ADObjectAccess
| where ingestion_time() >= ago(timeframe)
| summarize ObjectCount=count(),TimeGenerated=min(TimeGenerated) by Account
| where ObjectCount > min_suspicious_count
| join kind=leftouter AccessBaseline on Account
| extend PreviousMaxObjectPerDay=coalesce(PreviousMaxObjectPerDay,0)
// Calculate what is considered a suspicious number for the given user.
| extend SuspiciousThreshold=max_of(PreviousMaxObjectPerDay*suspicious_factor,min_suspicious_count)
| where ObjectCount > SuspiciousThreshold
| project TimeGenerated, Account, ObjectCount, PreviousMaxObjectPerDay, SuspiciousThreshold
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
| 1.3  | 2024-01-18| minor | Added query_prefix variable. |
| 1.2  | 2022-08-26| minor | Entity mapping added. |
| 1.1  | 2022-02-22| minor | Use ingestion_time for event selection and include de-duplication logic. |
| 1.0  | 2021-06-01| major | Initial version. |