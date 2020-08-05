# FalconFriday
TL;DR: Every two weeks on “Falcon Friday”, we’ll release (DTAP) hunting queries to detect offensive techniques.

As FalconForce, we are active in the “purple arena” — we want to practice as much defensive security as offensive security. Moreover, we want to share back to the community. Combining these two, we came up with the idea to develop hunting queries based on our offensive & defensive experience and share our “latest and greatest” hunting/alerting queries for everyone to use. We’ll start off with queries for Microsoft Defender ATP (DATP), but might expand to other tools in the future.
Our plan

We will publish the KQL queries on this GitHub page. Each query will be aimed at detecting some specific technique as precisely as possible and linked to MITRE ATT&CK. We anticipate that some queries will have more than 1 variant, aimed at detecting the same attack in different ways with varying trade-offs. Similarly, we will document trade-offs for various options in a single query to give you the flexibility to gear towards more false positives or more false negatives.

Having said that, don’t expect to copy-paste the queries in your environment and be done with it. We will provide a foundation query which can detect a certain technique. However, you will still need to fine-tune/extend the query to your organization’s specifics to make it work in your environment and integrate into your monitoring solution.

The queries will be free to use in any way you like, although we appreciate a reference back to @falconforceteam Twitter / FalconForce GitHub.
