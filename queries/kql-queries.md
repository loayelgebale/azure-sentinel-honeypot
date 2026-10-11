# KQL queries used in the lab

## Failed logons (Event ID 4625) per source IP
```kql
SecurityEvent
| where EventID == 4625
| summarize FailedAttempts = count() by IpAddress
| order by FailedAttempts desc
```

## Failed logons per hour (attack timeline)
```kql
SecurityEvent
| where EventID == 4625
| summarize count() by bin(TimeGenerated, 1h)
| render timechart
```

## Check for remaining failed logons after hardening
```kql
SecurityEvent
| where EventID == 4625
| where TimeGenerated > ago(30h)
| summarize count()
```

## First and last attempt per source IP
```kql
SecurityEvent
| where EventID == 4625
| summarize attempts = count(), first_seen = min(TimeGenerated), last_seen = max(TimeGenerated) by IpAddress
| order by last_seen desc
```

## GeoIP enrichment (Sentinel watchlist "geoip")
```kql
let GeoIPDB_FULL = _GetWatchlist("geoip");
SecurityEvent
| where EventID == 4625
| evaluate ipv4_lookup(GeoIPDB_FULL, IpAddress, network)
| summarize FailureCount = count() by IpAddress, latitude, longitude, cityname, countryname
```
