Here are 4 hunts for the PHP CVE's and the revoked Issuer Certificates that are in the news now.  
The PHP ones require more filtering based on normal activities in your environment.

```sql
// Only shows connections to domains with a certificate that was issued by one of the compromised certificates. Which can mean the communications could have been intercepted.
DeviceNetworkEvents
| where Timestamp >= ago(30d)
| where ActionType =~ "SslConnectionInspected"
| where AdditionalFields has "O=eMudhra"
| where AdditionalFields has_any("EM EV TLS CA - G3B", 
                                 "EM OV TLS CA - G3B", 
                                 "EM DV TLS CA - G3B", 
                                 "EM EV TLS CA - G3C",
                                 "EM OV TLS CA - G3C", 
                                 "EM DV TLS CA - G3C", 
                                 "EM OV CS CA - G3B", 
                                 "EM OV CS CA - G3C")
| extend
    Issuer = tostring(parse_json(AdditionalFields).issuer),
    Subject = tostring(parse_json(AdditionalFields).subject),
    Cipher = tostring(parse_json(AdditionalFields).cipher)
| summarize make_set(DeviceId), make_set(Subject), count() by Issuer
```

```sql
// Find programs that were executed and signed by any of the known compromised Issuer certificates.
let signedSoftware=DeviceFileCertificateInfo
| where Timestamp >= ago(30d)
| where Issuer has "O=eMudhra"
| where Issuer has_any("EM EV TLS CA - G3B",
                                 "EM OV TLS CA - G3B",
                                 "EM DV TLS CA - G3B",
                                 "EM EV TLS CA - G3C",
                                 "EM OV TLS CA - G3C",
                                 "EM DV TLS CA - G3C",
                                 "EM OV CS CA - G3B",
                                 "EM OV CS CA - G3C")
| summarize by DeviceId,SHA1;
DeviceProcessEvents
| where Timestamp >= ago(30d)
| where DeviceId in~ ((signedSoftware | project DeviceId)) and SHA1 in~ ((signedSoftware | project SHA1))
```

```sql
// All subprocesses from PHP as a start for a hunt, needs filtering based on what is known normal behavior by environment
// Option is to to anti join with behavior from more than a week ago to remove most noise. This can cause blind spots
DeviceProcessEvents
| where Timestamp >= ago(3d)
| where ActionType contains "ProcessCreated"
| where InitiatingProcessFileName has "php"
| where not(ProcessCommandLine in~ ("cmd.exe /c \"chcp\"", "conhost.exe 0xffffffff -ForceV1"))
| extend Executions=bag_pack_columns(FileName, ProcessCommandLine)
// add filters for trusted ProcessCommandLines below
// end filter
| summarize count() by DeviceId, DeviceName, tostring(Executions), InitiatingProcessFileName
```

```sql
/// This looks for machines with Defender on it that have PHP on them and adds InternetAccessible if it has inbound connections from PublicIPs or has been scanned by MS from the internet
DeviceTvmSoftwareInventory
| where SoftwareName contains "php"
| extend DeviceNameShort=tolower(extract("^[\\w-]+",0,DeviceName))
| summarize make_set(SoftwareName, 20) by NodeName=DeviceNameShort, DeviceId
| join kind=leftouter (ExposureGraphNodes
    | where Categories has "device"
    | where NodeProperties has "exposedToInternet"
    | extend NodeName=tolower(extract("^[\\w-]+",0,NodeName))
    )
    on NodeName
| join kind=leftouter ( DeviceNetworkEvents
    | where ActionType == "InboundInternetScanInspected"
    | extend DeviceNameShort=tolower(extract("^[\\w-]+",0,DeviceName))
    | summarize by NodeName=DeviceNameShort
    | extend InternetAccessible="yes"
    )
    on NodeName
| join kind=leftouter ( DeviceNetworkEvents
| where ActionType =~ "InboundConnectionAccepted"
| where RemoteIPType !in ("Private","Loopback","LinkLocal")
| where not(RemoteIP has_any ("::ffff:127","::ffff:10","::ffff:192.168","::ffff:172.24"))
| where RemotePort > 10000
| extend DeviceNameShort=tolower(extract("^[\\w-]+",0,DeviceName))
| summarize by NodeName=DeviceNameShort
| extend InternetAccessible="yes" ) on NodeName
| project-away NodeName2, NodeName3(edited)
```
