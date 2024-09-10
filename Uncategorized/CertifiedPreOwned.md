Note: You are viewing an old, archived version of this content. The latest version is available in the ['main' branch](https://github.com/FalconForceTeam/FalconFriday/blob/main/0xFF-0298-TGT_requested_with_suspicious_certificate-Win.md).

# Certified Pre-Owned

## Background info
The [excellent research](https://posts.specterops.io/certified-pre-owned-d95910965cd2) by [@harmj0y](https://twitter.com/harmj0y) and [@tifkin_](https://twitter.com/tifkin_) has resulted in some serious attacks possible against AD. The queries here are detection rules which are meant to work in a realistic production environment. 

The full background of the queries are detailed [in this blog post](https://medium.com/falconforce/falconfriday-certified-pre-owned-0xff12-40f00a35e51a?source=friends_link&sk=9928aa6271bf59027687b850959ac265).


## TGTs requested with certificate authentication
```C#
let timeframe=14d;
SecurityEvent
| where TimeGenerated >= ago(timeframe)
| where EventID == 4768
| project TimeGenerated, Computer, TargetAccount, EventData=parse_xml(EventData)
| mv-apply d=EventData.EventData.Data on 
(
    where d["@Name"]=="CertIssuerName"
    | project CIN=tostring(d["#text"])
)
| where not(isempty(CIN))
// <DECISION - 1>
//In my prod, I'm seeing a lot of certs starting with a sid and containing live.com. Comment out the next line if you have that as well. 
//| where not(CIN startswith "S-1-")
// <DECISION - 2>
//If you're seeing significant amount of machine accounts, might be due to 802.1X or SCCM. https://twitter.com/MagnusMOD/status/1407800853088591872?s=20. The following line allows you to filter out all endpoints. This does introduce a blindspot. + you need a custom function which provides data about (on-prem) ad machined. Alternatively, you can use DeviceInfo, if you're ingesting that data from MDE.
| parse CIN with "CN=" MachineName
//| join kind=leftouter  MyCustomLookupFunction on $left.MachineName == $right.CN
//| where not(OperatingSystem startswith "Windows 10")
```

## Backup of CA private key - Rule 1
```C#
SecurityEvent
// Fill in the machine name of your CA
| where EventID == 5058 and Computer contains "<YOUR CA MACHINE NAME>"
| where EventData contains "%%2499" //Machine key
| extend EventData=parse_xml(EventData)
| mv-apply d=EventData.EventData.Data on 
(
    where d["@Name"]=="KeyName"
    | project KeyName=tostring(d["#text"])
)
| mv-apply d=EventData.EventData.Data on 
(
    where d["@Name"]=="SubjectUserName"
    | project SubjectUserName=tostring(d["#text"])
)
| mv-apply d=EventData.EventData.Data on 
(
    where d["@Name"]=="Operation"
    | project Operation=tostring(d["#text"])
)
| extend Operation=iff(Operation == "%%2458", "Read persisted key from file", Operation)
//this one is a guess and very poorly documented :(
| extend Operation=iff(Operation == "%%2459", "Write persisted key to file", Operation)
// Fill in the keyname of the CA key. 
| where KeyName == "<INSERT ISSUING CA KEY HERE>" //or any other key you want to monitor
```

## Backup of CA private key - Rule 2
```C#
SecurityEvent
// Fill in the machine name of your CA
| where EventID == 5059 and Computer contains "<YOUR CA MACHINE NAME>"
| where EventData contains "%%2499" and EventData contains "%%2464"
| extend EventData=parse_xml(EventData)
| mv-apply d=EventData.EventData.Data on 
(
    where d["@Name"]=="KeyName"
    | project KeyName=tostring(d["#text"])
)
| mv-apply d=EventData.EventData.Data on 
(
    where d["@Name"]=="SubjectUserName"
    | project SubjectUserName=tostring(d["#text"])
)
| parse Account with "<YOUR DOMAIN NAME>\\" CleanAccount "$"
| where not(Computer startswith CleanAccount)
```