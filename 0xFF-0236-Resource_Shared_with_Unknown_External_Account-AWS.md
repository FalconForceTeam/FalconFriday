# AWS Resource Shared with Unknown External Account

## Metadata
**ID:** 0xFF-0236-Resource_Shared_with_Unknown_External_Account-AWS

**OS:** N/A

**FP Rate:** Low

---

## ATT&CK Tags

| Tactic | Technique | Subtechnique | Technique Name |
|---|---|---| --- |
| TA0003 - Persistence | T1098 | 001 | Account Manipulation - Additional Cloud Credentials|
| TA0009 - Collection | T1530 |  | Data from Cloud Storage|

## Utilized Data Sources

| Log Provider | Event ID | Event Name | ATT&CK Data Source | ATT&CK Data Component|
|---------|---------|----------|---------|---------|
|AWS|ModifyImageAttribute||Application Log|Application Log Content|
|AWS|ModifySnapshotAttribute||Application Log|Application Log Content|
|AWS|ModifyDBSnapshotAttribute||Application Log|Application Log Content|
|AWS|PutBucketPolicy||Application Log|Application Log Content|
---

## Technical description of the attack
This query searches for resources being shared with an external AWS account that is not on a list of known trusted accounts.


## Permission required to execute the technique
User

## Detection description
When an attacker gains access to an account with access to AWS, they might abuse that account to share resources with an external account to extract data or to leave a backdoor that can be used at a later stage to re-gain access to the environment.


## Considerations
None.


## False Positives
There might be sharing of resources with external accounts for business reasons. Such sharing will have to be filtered.


## Suggested Response Actions
Confirm if the user responsible for the sharing has shared the resource for a valid business reason.


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
let RuleId = "0236";
let DedupFields = dynamic(["TimeGenerated", "AccountId"]);
let TrustedAccounts= dynamic([]);
let SharingEvents=(
    AWSCloudTrail
    | where ingestion_time() >= ago(timeframe)
    | where EventName in ("ModifyImageAttribute","ModifySnapshotAttribute","ModifyDBSnapshotAttribute","PutBucketPolicy")
        or (EventSource == "lambda.amazonaws.com" and EventName startswith "AddPermission")
);
let ImageSharing=(
    SharingEvents
    | where EventName == "ModifyImageAttribute"
    | mv-expand LaunchPermission=parse_json(RequestParameters).launchPermission
    | mv-expand AddItem=LaunchPermission.add.items
    | extend AddedAccount = AddItem.userId
    | extend SharedGroup = AddItem.group
    | extend SharedResourceId = parse_json(RequestParameters).imageId
);
let SnapshotSharing=(
    SharingEvents
    | where EventName == "ModifySnapshotAttribute"
    | mv-expand CreateVolumePermission=parse_json(RequestParameters).createVolumePermission
    | mv-expand AddItem=CreateVolumePermission.add.items
    | extend AddedAccount=AddItem.userId
    | extend SharedResourceId = parse_json(RequestParameters).snapshotId
);
 let DBSnapshotSharing=(
    SharingEvents
    | where EventName == "ModifyDBSnapshotAttribute"
    | where parse_json(RequestParameters).attributeName =~ "restore"
    | mv-expand AddedAccount=parse_json(RequestParameters).valuesToAdd
    | extend SharedResourceId = parse_json(RequestParameters).dBSnapshotIdentifier
);
let BucketSharing=(
    SharingEvents
    | where EventName == "PutBucketPolicy"
    | extend BucketPolicy=parse_json(RequestParameters).bucketPolicy
    | mv-expand  Statement=BucketPolicy.Statement
    | where Statement.Effect =~ "Allow"
    | mv-expand AddedAccount=Statement.Principal.AWS
);
let LambdaSharing=(
    SharingEvents
    | where EventName startswith "AddPermission"
    | extend RequestParameters=parse_json(RequestParameters)
    | where RequestParameters.action == "lambda:InvokeFunction"
    | extend AddedAccount=RequestParameters.principal
);
union ImageSharing, SnapshotSharing, DBSnapshotSharing, BucketSharing, LambdaSharing
| extend AddedAccount=iif(AddedAccount contains "*", "*", AddedAccount)
| extend AddedAccount=iif(AddedAccount startswith "arn:", split(AddedAccount, ":")[4], AddedAccount)
| where not(isempty(AddedAccount))
| where not(AddedAccount == UserIdentityAccountId)
| where not(AddedAccount in (TrustedAccounts))
// Excluding AWS services as external accounts, anything in the pattern of ".amazonaws.com"
| where not(AddedAccount endswith ".amazonaws.com")
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
| 1.4  | 2023-11-13| minor | Additional context added. |
| 1.3  | 2023-07-26| minor | Added a filter-out in the detection logic. |
| 1.2  | 2022-08-31| minor | Entity mapping added. |
| 1.1  | 2022-02-22| minor | Use ingestion_time for event selection and include de-duplication logic. |
| 1.0  | 2022-02-01| major | Initial version. |