# Incident Report: RDP Brute-Force Attack on an Internet-Exposed Azure VM

**Analyst:** (loay elgebale)  **Environment:** Azure lab (Microsoft Sentinel)  **Severity:** Low (no compromise found)

## 1. Executive Summary
Between 6 and 8 October 2026, an internet-exposed Windows VM in Azure was targeted by automated RDP brute-force attacks. Sentinel recorded failed logon attempts (Event ID 4625) from approximately 51 distinct IP addresses. The most active source alone generated 228,779 failed attempts, and activity peaked at approximately 35,000 attempts per hour on 7 October. No successful logon by an attacker was observed. After RDP access was restricted to a single trusted IP address and the old permissive rule was deleted, the attacks stopped.

## 2. Timeline (times approximate; chart times in UTC)
- **6 Oct (evening):** The VM was deployed with all inbound ports open. Failed logons appeared in Sentinel within hours, starting at around 10,000 per hour.
- **6-7 Oct:** The attack rate rose steadily as more sources found the host.
- **7 Oct (early morning):** Peak of approximately 35,000 failed attempts per hour.
- **7 Oct (~04:00-09:00):** The rate fell sharply after RDP access was first restricted to a single trusted IP.
- **7-8 Oct:** A low level of attempts (hundreds per hour) continued because the default RDP rule (priority 300, source Any) still allowed external traffic.
- **8 Oct (~06:47):** Last failed attempt logged, after the permissive rule was deleted.
- **After 8 Oct:** No failed logons recorded for the rest of the monitoring period.

## 3. Technical Analysis
**Data source:** Windows Security Events from the VM, collected through the Azure Monitor Agent into a Log Analytics workspace used by Microsoft Sentinel.

**Detection logic:** Event ID 4625 records a failed Windows logon. Many 4625 events from one source IP in a short period indicate brute-force activity.

```kql
SecurityEvent
| where EventID == 4625
| summarize FailedAttempts = count() by IpAddress
| order by FailedAttempts desc
```

**Findings:** About 51 distinct source IPs. Top sources: 144.76.103.122 (228,779), 62.238.86.212 (55,406), 80.94.95.83 (30,349). GeoIP enrichment through a Sentinel watchlist showed sources across Europe, Asia and North America. Most appear to be hosting-provider addresses, so an IP's location does not necessarily show where the attacker is.

**Compromise check:** The only successful logons (Event ID 4624) belonged to `NT AUTHORITY\SYSTEM`, which is normal system activity. No successful external logon was observed.

## 4. Threat Intelligence
The three most active source IPs were checked against public reputation services on 11 October 2026.

| Source IP | Failed attempts | AbuseIPDB score | Reports | Provider (as listed) |
|---|---|---|---|---|
| 144.76.103.122 | 228,779 | 2% | 6 | Hetzner Online GmbH |
| 62.238.86.212 | 55,406 | 33% | 7 | Hetzner Online GmbH |
| 80.94.95.83 | 30,349 | 100% | 8,580 | UNMANAGED LTD |

VirusTotal flagged 80.94.95.83 as malicious by 15 of 92 security vendors (ASN 204428, country listed as RO).

**Observations:**
- Reputation did not match observed behaviour. The most active attacker had only a 2% abuse score, so a low reputation score alone cannot be treated as evidence that an IP is safe. Observed behaviour in our own logs (hundreds of thousands of failed logons) is stronger evidence.
- All three sources belong to hosting providers, consistent with rented servers rather than personal devices.
- Sources disagree on location: VirusTotal lists 80.94.95.83 in Romania while the Sentinel GeoIP watchlist placed it in the Netherlands. Geolocation is approximate and should not be used to attribute an attacker.
- AlienVault OTX lists 80.94.95.83 in 50 pulses with 37 related tags. Many tags are names of honeypot software (for example cowrie, dionaea, honeytrap, tpot), which suggests the IP was reported by many other honeypot operators. Behaviour tags (rdp, ssh, ftp, smtp, vnc, telnet, snmp, scanner, bruteforce, automated) indicate opportunistic, multi-protocol scanning rather than a targeted attack on this VM.
- OTX tags also include malware-family names (mirai, mozi, wannacry, botnet). These come from aggregated community pulses and do not show that this IP is infected or that any malware reached our VM; no malware activity was observed in our logs.
- 80.94.95.9, also seen in our logs, sits in the same /24 range as 80.94.95.83 and may belong to the same operator (not verified).

**Indicators of Compromise (IOCs):** 144.76.103.122, 62.238.86.212, 80.94.95.83 (RDP brute-force sources).

## 5. Impact
No evidence of compromise was found. No successful external logon was recorded, so there is no indication that an attacker accessed the VM or any data on it. The VM was a lab system containing no production or personal data. The main effect was resource consumption and log volume (hundreds of thousands of failed logon events), not data loss or service disruption. This assessment is based on Windows logon events only; process and network telemetry were not reviewed.

## 6. Containment & Remediation
An inbound NSG rule named `MyIP-Only` (priority 200) was created, allowing RDP (TCP 3389) only from a single trusted IP address. The first attempt did not fully work: the trusted IP was entered in the wrong field (Destination instead of Source), and the default RDP rule (priority 300, source Any) was still allowing external traffic. After that rule was deleted, remaining traffic matched only `DenyAllInBound`, and no further failed logons were recorded. The control was confirmed effective only after verification with log data.

## 7. Recommendations
1. **Do not expose RDP to the internet.** Require a VPN (or Azure Bastion / just-in-time VM access) so RDP is reachable only after authenticating to a trusted network.
2. **Alert on brute force.** Create a Sentinel analytics rule that fires when a single source IP produces more than a set number of 4625 events within a short window (for example, 10 in 5 minutes), so the activity is seen in minutes rather than found later.
3. **Verify every network change.** After any NSG edit, review all inbound rules (including defaults) and confirm with log data that unwanted traffic has stopped.

## Evidence
Screenshots: attack map, top source IPs, failed attempts per hour, NSG inbound rules (see project README).
