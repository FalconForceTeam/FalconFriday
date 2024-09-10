Note: You are viewing an old, archived version of this content. The latest version is available in the ['main' branch](https://github.com/FalconForceTeam/FalconFriday/blob/main/0xFF-0236-Resource_Shared_with_Unknown_External_Account-AWS.md).

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
| TA0009 - Collection | T1530 |  | Data from Cloud Storage Object|

## Utilized Data Sources

| Log Provider | Event ID | Event Name | ATT&CK Data Source |
|---------|---------|----------|---------|
|AWSCloudTrail||||
---

## Technical description of the attack
​This query searches for resources being shared with an external AWS account that is not on a list of known trusted accounts.


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
let timeframe = 1h;
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
    | extend AddedAccount=AddItem.userId
);
let SnapshotSharing=(
    SharingEvents
    | where EventName == "ModifySnapshotAttribute"
    | mv-expand CreateVolumePermission=parse_json(RequestParameters).createVolumePermission
    | mv-expand AddItem=CreateVolumePermission.add.items
    | extend AddedAccount=AddItem.userId
);
let DBSnapshotSharing=(
    SharingEvents
    | where EventName == "ModifyDBSnapshotAttribute"
    | where parse_json(RequestParameters).attributeName =~ "restore"
    | mv-expand AddedAccount=parse_json(RequestParameters).valuesToAdd
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
| order by TimeGenerated asc
// Begin client-specific filter.
// End client-specific filter.
```


---

## Version History
| Version | Date | Impact | Notes |
|---------|------|--------|------|
| 1.0  | 2022-02-01| major | Initial version. |