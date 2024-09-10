Note: You are viewing an old, archived version of this content. The latest version is available in the ['main' branch](https://github.com/FalconForceTeam/FalconFriday/blob/main/0xFF-0108-Large_number_of_AD_objects_accessed_by_user-Win.md).

# Large number of AD objects accessed by user

## Metadata
**ID:** AD_Data_Collection_Number_of_Objects_Accessed

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
​This query detects a user accessing a large number of Group, Computer and User objects from Active Directory which is outside the baseline of normal behavior for that particular user.


## Permission required to execute the technique
User

## Detection description
Attackers often abuse information from Active Directory, such as lists of domain users, computers and groups, in order to determine attack paths. When large numbers of objects are accessed, this
could indicate usage of an AD collection tool such as Bloodhound.


## Considerations
If multiple attacks are performed with the same user account, this might lead to the baseline for that user being adjusted and only the first attack being detected.


## False Positives
There are legitimate use cases for downloading large number of AD objects. For example, an administrator might run a script to extract all users as part of certain migration activities.


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
let timeframe = 1d;
let lookback_days=14d; // Look back this many days to calculate baseline for maximum number of objects accessed per day.
let min_suspicious_count = 20000; // Only consider users looking up at least this many objects during the timeframe.
let suspicious_factor = 50; // Consider as suspicious if requesting more than suspicious_factor*daily maximum in lookback period.
let ADObjectAccess=(
    SecurityEvent
    | where EventID == 4662
    | where ObjectType in~ (
        "%{bf967aba-0de6-11d0-a285-00aa003049e2}", // User.
        "%{bf967a9c-0de6-11d0-a285-00aa003049e2}" //  Group.
        "%{bf967a86-0de6-11d0-a285-00aa003049e2}" //  Computer.
    )
);
let AccessBaseline=(
    ADObjectAccess
    | where TimeGenerated between (ago(timeframe + lookback_days)..ago(timeframe))
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
```


---

## Version History
| Version | Date | Impact | Notes |
|---------|------|--------|------|
| 1.1  | 2022-11-11| major | FalconFriday release. |
