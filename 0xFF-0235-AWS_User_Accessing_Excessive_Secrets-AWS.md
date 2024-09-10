# AWS User Accessing Excessive Secrets

## Metadata
**ID:** 0xFF-0235-AWS_User_Accessing_Excessive_Secrets-AWS

**OS:** N/A

**FP Rate:** Low

---

## ATT&CK Tags

| Tactic | Technique | Subtechnique | Technique Name |
|---|---|---| --- |
| TA0009 - Collection | T1530 |  | Data from Cloud Storage|

## Utilized Data Sources

| Log Provider | Event ID | Event Name | ATT&CK Data Source | ATT&CK Data Component|
|---------|---------|----------|---------|---------|
|AWS|GetPasswordData||Application Log|Application Log Content|
---

## Technical description of the attack
This query searches for an account which accesses a large number of secrets from various sources in AWS, including SSM secrets and instance passwords.


## Permission required to execute the technique
User

## Detection description
When an attacker gains access to an account with access to AWS,they might abuse that account to view secrets stored in the AWS cloud.


## Considerations
None.


## False Positives
There might be user accounts that access large numbers of secrets for business purposes. For example, an account associated with a remote management tool. These accounts have be filtered.


## Suggested Response Actions
Confirm if the user responsible for the account that triggered this alert is aware of the attempts to access secrets.


## Detection Blind Spots
None known.


## References
* https://github.com/DataDog/stratus-red-team

---
## Detection

**Language:** Kusto

**Platform:** Sentinel

**Query:**
```C#
let timeframe = 2*1h;
let RuleId = "0235";
let DedupFields = dynamic(["TimeGenerated"]);
let time_period = 10m;
let access_threshold = 10;
// The rule will trigger when more than access_threshold secrets are requested in time_period.
AWSCloudTrail
| where ingestion_time() >= ago(timeframe)
| where EventName in ("GetPasswordData","GetSecretValue","Decrypt")
| extend SecretId=case(
    EventName == "GetPasswordData", parse_json(RequestParameters).instanceId,
    EventName == "GetSecretValue", parse_json(RequestParameters).secretId,
    EventName == "Decrypt", coalesce(parse_json(parse_json(RequestParameters).encryptionContext).SecretARN, parse_json(parse_json(RequestParameters).encryptionContext).PARAMETER_ARN)
    , ""
)
// For Decrypt only look at decryption of SSM secrets.
| where EventName != "Decrypt" or SecretId startswith "arn:aws:ssm"
| summarize arg_min(TimeGenerated, *), SecretCount=count(), Secrets=make_set(SecretId) by UserIdentityArn, TimeBin=bin(TimeGenerated, time_period)
| where SecretCount > access_threshold
// Begin environment-specific filter.
// End environment-specific filter.
| extend UserAccount=tostring(split(UserIdentityArn, "/")[-1])
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
| 1.0  | 2022-02-01| major | Initial version. |