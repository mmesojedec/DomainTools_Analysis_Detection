"""Detection reference: what each rule detects, and how severity, confidence, category, and ATT&CK are assigned."""
import pandas as pd

from config import SEVERITY_WEIGHTS
from core.intel_data import CONFIDENCE_ORDER, MITRE_TACTICS, RULE_METADATA

SEVERITY_LEVELS = [
    ("Critical", "Infrastructure that is almost certainly malicious or actively weaponized (e.g. CAA breach, rogue CA, "
                 "parked domain suddenly armed). Investigate or block first."),
    ("High", "Strong attacker tradecraft or a high-risk configuration (fast-flux, self-signed or weak certificates, "
             "permissive SPF, shared trackers). Prioritize after Critical."),
    ("Medium-High", "Suspicious setup that is common in abuse but has benign explanations (offshore DNS, DGA-like names, "
                    "CN mismatch, shared clusters). Review with context."),
    ("Medium", "Notable change or weak-to-moderate indicator (new registration, redirects, sinkholes, CAA mismatch). "
               "Use to corroborate other findings."),
    ("Low", "Context only: hygiene or informational observations (parking, wildcard or short-lived certificate, "
            "malformed SPF)."),
]

CONFIDENCE_LEVELS = [
    ("High", "The rule matches a specific artifact with few false positives (exact certificate, tracker, or CAA facts). "
             "Treat the finding as true unless an allow-list explains it."),
    ("Medium", "A strong behavioral signal that also occurs in legitimate infrastructure (CDNs, hosting migrations, "
               "registrar defaults). Confirm with a second finding or the evidence table."),
    ("Low", "A weak or heuristic signal (entropy, volume, naming). On its own it is not a verdict; use it to rank or pivot."),
]

COLUMN_GUIDE = [
    ("Threat Type", "The detection rule that fired. Each rule is listed in the table below."),
    ("Severity", "Impact if the finding is true, fixed per rule (a few rules raise or lower it; see the Severity column below). "
                 f"Weights {', '.join(f'{k} {v}' for k, v in SEVERITY_WEIGHTS.items())} feed the Unified Risk vectors, "
                 "except for informational rules (Short-Lived Certificate)."),
    ("Confidence", "How likely the finding is a true positive. Defaults per rule; some rules adjust it at runtime "
                   "(e.g. fast-flux on CDN IPs is Low, a strong infrastructure cluster is High, a public short-lived IP "
                   "certificate is Low)."),
    ("Category", "The kind of evidence the rule looks at (DNS Behavior, Certificates, Email, Correlation, ...)."),
    ("MITRE ATT&CK", "The adversary technique the behavior maps to; the tactic is derived from the technique ID."),
    ("Risk / Risk Evidence", "DomainTools risk score for the domain and its evidence tags (from Iris Investigate). Domains with a known score below "
                             "Min Risk Score are not evaluated."),
    ("Occurrences", "How many matching certificates or records were merged into one detection for the domain."),
    ("First Detected / Runs Seen", "When this detection first appeared in a saved run (any target list), and in how many runs."),
]

# threat type -> (severity as assigned, ATT&CK technique, what triggers it, why it matters)
RULE_CATALOG = {
    # DNS / pDNS / Domain History
    "DGA / High Entropy Domain": ("Medium-High", "T1568.002 (Dynamic Resolution: DGA)",
                                  "Domain label of 13+ characters with Shannon entropy above the DGA Entropy Score threshold, or of 8+ "
                                  "characters that looks generated (letter/digit mix, long consonant run).",
                                  "Algorithmically generated names are used by malware to find C2 servers."),
    "Parked-to-Weaponized": ("High", "T1583.001 (Acquire Infrastructure)",
                             "Dormant longer than Parked Dormancy (Days), then 3+ DNS changes within 48 hours that "
                             "include a new address (A / AAAA).",
                             "Aged domains are bought or reactivated to evade new-domain reputation checks."),
    "Rapid IP Rotation (Fast-Flux)": ("High", "T1568.001 (Fast Flux DNS)",
                                      "At least Rapid IP Rotation Event Count distinct IPs on one hostname within 7 days (each "
                                      "subdomain counted apart). Confidence drops to Low when every IP belongs to a CDN.",
                                      "Rotating IPs hide the real hosting and resist takedowns."),
    "Multi-Network Fast-Flux (ASN-Diverse)": ("High", "T1568.001 (Fast Flux DNS)",
                                              "Non-CDN IPs of one hostname across at least Fast-Flux Min Distinct Networks ASNs or prefixes "
                                              "within 7 days.",
                                              "Spreading across networks is typical of botnet-hosted flux, not CDNs."),
    "Sinkhole / Loopback Resolution": ("Medium", "T1568 (Dynamic Resolution)",
                                       "A or NS record points to 127.0.0.1, 0.0.0.0, or a known sinkhole.",
                                       "Usually means the domain was taken over by researchers or law enforcement after abuse."),
    "Suspicious / Offshore Name Server": ("Medium-High", "T1583.001 (Acquire Infrastructure)",
                                          "Name server at a dynamic, free, or bulletproof DNS provider.",
                                          "These providers ignore abuse reports and are favored for malicious domains."),
    "High-Risk Mail Provider": ("Medium", "T1585.002 (Acquire Email Accounts)",
                                "MX records (passive DNS, or the current MX in Iris Investigate) point to an anonymous, "
                                "throwaway mail provider (cock.li, guerrillamail, mailinator, ...; not large consumer providers).",
                                "Disposable mail backends are common in phishing and fraud operations."),
    "Phishing/Spam Prep": ("Medium-High", "T1583.001 (Acquire Infrastructure)",
                           "MX / TXT / SPF records added after longer than Phishing Prep Dormancy (Days).",
                           "Mail setup on a quiet domain often precedes a phishing or spam campaign."),
    "Invalid/Malformed SPF": ("Low", "T1583.001 (Acquire Infrastructure)",
                              "SPF record without the required 'v=' prefix.",
                              "Hygiene issue; mostly useful as a sign of hastily configured infrastructure."),
    "Highly Permissive SPF (+all)": ("High", "T1583.001 (Acquire Infrastructure)",
                                     "SPF record (passive DNS, or the current SPF in Iris Investigate) ends in +all, "
                                     "authorizing any server to send mail.",
                                     "Lets anyone spoof the domain; rarely legitimate."),
    "Anomalous TXT Payload": ("High", "T1071.004 (DNS C2)",
                              "TXT record longer than Anomalous TXT Length with almost no spaces, that is neither a known "
                              "SaaS / mail record (DKIM, verification tokens) nor a key=value setting.",
                              "Long encoded TXT data is a classic DNS tunneling / C2 channel."),
    "Flash/Burst Campaign": ("High", "T1583.001 (Acquire Infrastructure: Domains)",
                             "Over 1,000 queries on a record alive 7 days or less and no longer seen, above pDNS "
                             "Burst Density (a record that is merely new does not count).",
                             "Short, intense query bursts match spam blasts and botnet check-ins."),
    "Query Volume Anomaly": ("Medium", "T1071.004 (App Layer Protocol: DNS)",
                             "Daily pDNS volume with a robust z-score above Query Volume Anomaly (100+ queries).",
                             "Sudden traffic spikes point to campaign activity; counts are approximate."),
    "IPTV / Stream Distribution Endpoint": ("Medium", "T1584.001 (Compromise Infrastructure)",
                                            "Subdomains such as m3u., xtream., stalker. in passive DNS, or two or more "
                                            "generic ones (stream., live., panel., ...).",
                                            "Typical of illegal IPTV / restreaming infrastructure."),
    "ACME Certificate Sprawl": ("Low", "T1588.004 (Obtain Digital Certificates)",
                                "More than 10 distinct _acme-challenge hostnames in passive DNS (renewals of one name "
                                "count once).",
                                "Mass automated certificate issuance supports fast setup of many hostnames."),
    "Deeply Nested Subdomains": ("Medium", "T1584.001 (Compromise Infrastructure)",
                                 "Hostnames 3 or more labels deeper than the domain, not counting service labels "
                                 "(_domainkey, _acme-challenge, ...).",
                                 "Deep nesting is used for domain shadowing on compromised DNS accounts."),
    "Parked Domain (Parking Name Servers)": ("Low", "T1583.001 (Acquire Infrastructure: Domains)",
                                             "Domain is or was delegated to parking name servers.",
                                             "Context: parked domains can be sold and weaponized later."),
    "Parking Exit / Reactivation": ("High", "T1583.001 (Acquire Infrastructure: Domains)",
                                    "Domain left parking name servers and gained live A/AAAA/MX records within 7 days.",
                                    "Reactivation of a parked domain often marks the start of malicious use."),
    # CNAME chains
    "Dangling CNAME (Subdomain Takeover Risk)": (
        "Critical (High when no target is on a takeover-prone service)", "T1584.001 (Compromise Infrastructure: Domains)",
        "A current CNAME whose chain (collected passive DNS, then the DNSDB chase) ends at a name with no A, AAAA or "
        "CNAME record. Critical and High confidence when the target is on a takeover-prone service (S3, Azure, Heroku, "
        "GitHub Pages, Shopify, ...).",
        "A dangling CNAME lets anyone who claims the target resource serve content, phishing pages or cookies-stealing "
        "scripts on the organization's own subdomain."),
    "Unverified CNAME to Takeover-Prone Service": (
        "Medium", "T1584.001 (Compromise Infrastructure: Domains)",
        "A current CNAME to a takeover-prone service whose chain was not chased (chasing off, over the per-domain chase budget, or the "
        "lookup failed).",
        "Same takeover exposure as a dangling CNAME, but unconfirmed: chase it in the CNAME Chains lens."),
    "CNAME to Dynamic DNS / Tunnel Service": (
        "High", "T1568 (Dynamic Resolution)",
        "Any CNAME in the analysis window to a dynamic DNS or tunnel service (Duck DNS, No-IP, ngrok, Cloudflare quick "
        "tunnels, localtunnel, ...).",
        "These names follow a home or attacker machine or expose a local service; legitimate organizations rarely "
        "point their subdomains there, attackers use them for C2 and short-lived phishing."),
    "CNAME to Free Hosting Platform": (
        "Medium (High when the hostname has a phishing word, brand or embedded domain)",
        "T1583.006 (Acquire Infrastructure: Web Services)",
        "A current CNAME from the domain to a free hosting platform it does not belong to (pages.dev, workers.dev, "
        "Vercel, Netlify, Firebase, ...). High when the hostname also shows a Subdomain Triage name signal.",
        "Free platforms give attackers disposable, reputable-looking hosting behind a trusted name."),
    "CNAME Retargeted to Another Provider": (
        "Medium", "T1584.001 (Compromise Infrastructure: Domains)",
        "A hostname's current CNAME points to a different registrable domain than its earlier one, and the new target "
        "is external and not a CDN.",
        "Repointed subdomains are how takeovers and compromised DNS accounts show up; also normal during migrations, "
        "so check the new provider."),
    "Long CNAME Chain / Loop": (
        "Medium (Medium-High for a loop)", "T1090 (Proxy)",
        "A current CNAME chain of at least Long CNAME Chain Min Hops CNAMEs, a chain stopped at the step limit, or a "
        "loop.",
        "Layered redirects hide the final hosting and let operators swap it without touching the visible name."),
    "CNAME Link Between Analyzed Domains": (
        "Medium-High", "T1583.001 (Acquire Infrastructure: Domains)",
        "CNAME chains connect two or more analyzed domains: a name of one analyzed domain reached from another, or a "
        "name outside them all that several reach (CDNs and shared final addresses left out). Confidence is High for "
        "a CNAME into another analyzed domain, Low when every shared name is a known service (hosting, "
        "takeover-prone, tunnel).",
        "A dedicated proxy or host, or one domain aliasing into another, is a strong operator link."),
    # Iris enrichment and intel
    "Live Pirate Streaming Panel Detected": ("Critical", "T1584.001 (Compromise Infrastructure)",
                                            "Website returns HTTP 200 with an IPTV panel title (Xtream, Stalker, ...).",
                                            "Confirms an active illegal streaming management panel."),
    "Shared Web Tracker Fingerprint": ("High", "T1583.001 (Acquire Infrastructure)",
                                       "The same analytics / tag manager ID appears on other analyzed domains.",
                                       "Shared tracker IDs tie domains to the same operator."),
    "Newly Registered Domain": ("Medium", "T1583.001 (Acquire Infrastructure: Domains)",
                                "Created within Newly Registered Domain Age (Days).",
                                "Most malicious domains are used within days of registration."),
    "Newly Registered & Weaponized Domain": ("High", "T1583.001 (Acquire Infrastructure: Domains)",
                                             "Newly registered and already resolving, mailing, or serving certificates (resolving does not "
                                             "count while it is on parking name servers).",
                                             "A brand-new domain that is already operational is a strong abuse signal."),
    "High-Abuse / Offshore Hosting Provider": ("Medium-High", "T1583.003 (Acquire Infrastructure: Virtual Private Server)",
                                               "Currently resolves to a provider on the high-abuse / offshore watchlist.",
                                               "Bulletproof and offshore hosts are preferred for malicious services."),
    "Cross-Domain Redirect": ("Medium", "T1608.005 (Stage Capabilities: Link Target)",
                              "Website redirects to a different registrable domain.",
                              "Redirect chains are used for cloaking and traffic distribution."),
    "Potential Origin IP Exposure (Behind CDN)": ("Medium-High", "T1090.002 (Proxy: External Proxy)",
                                                  "Non-CDN IPs observed for a domain that sits behind a CDN.",
                                                  "May reveal the real origin server hidden behind the proxy."),
    # BGPDB (a BGPDB host and the BGP routing lookup)
    "BGP Origin Conflict (Possible Hijack)": (
        "High (unauthorized origin seen in the last 7 days) / Medium", "T1557 (Adversary-in-the-Middle)",
        "A prefix covering one of the domain's hosting IPs has its authorized origin (RPKI or IRR valid) and also "
        "another origin that RPKI or IRR names as invalid (BGPDB, last ~30 days).",
        "Two networks claiming the same addresses, one of them without authorization, is how BGP hijacks and route "
        "leaks look: traffic to the domain may have gone to the wrong network while it lasted."),
    "Unauthorized BGP Origin": (
        "Medium-High", "T1583 (Acquire Infrastructure)",
        "The network that usually announces the prefix of a hosting IP is RPKI- or IRR-invalid for it, and no "
        "authorized origin is seen (BGPDB).",
        "Hosting on space the registries do not tie to its announcer: squatted, informally leased or hijacked "
        "prefixes are favoured by bulletproof hosters."),
    "Newly Announced Prefix": (
        "Medium", "T1583 (Acquire Infrastructure)",
        "The prefix of a hosting IP was first announced by its origin in the last 14 days, and after the first "
        "days of BGPDB's ~30-day window (an older announcement can't be told apart there).",
        "Fresh address space comes and goes with short-lived campaign infrastructure."),
    "Recently Registered Origin Network": (
        "Medium-High (under 90 days) / Medium (under a year)", "T1583 (Acquire Infrastructure)",
        "The origin AS of a hosting IP was registered at its RIR within the last year (BGPDB's RIR record).",
        "Young networks host a large share of malicious infrastructure; established hosters rarely are."),
    "Low-Visibility or Single-Upstream Route": (
        "Low", "T1583 (Acquire Infrastructure)",
        "The prefix of a hosting IP is seen by fewer than 10 route collectors, or its origin network has a single "
        "upstream and no downstream networks (BGPDB).",
        "Context: small and bulletproof hosters often look like this, so do many legitimate small networks."),
    "Anonymizer Exit on Unstable Routing": (
        "High", "T1090 (Proxy)",
        "A hosting IP VPNDB names as a VPN, proxy or Tor exit sits on a prefix with an origin conflict, an "
        "unauthorized origin or a new announcement (BGPDB).",
        "An anonymizer on unstable or unregistered space is rarely a mainstream service: likely the actor's own or "
        "a fly-by-night provider."),
    "Unauthorized Origin Is a Tor Exit Network": (
        "Medium-High", "T1557 (Adversary-in-the-Middle)",
        "A network that announced a hosting prefix without authorization (origin conflict or unauthorized origin, "
        "BGPDB) also carries Tor exit traffic: at least 0.5 % of it or 10+ exit addresses (VPNDB Tor overview).",
        "The hijacking or squatting network welcomes Tor exits: privacy or bulletproof-style hosting, where traffic "
        "drawn by the announcement is hard to trace."),
    # VPNDB (VPNDB key and the VPN / proxy / Tor check)
    "Domain on Tor Relay / Exit Node": ("High (exit) / Medium-High (relay)", "T1090.003 (Proxy: Multi-hop Proxy)",
                                        "An IP the domain resolves to (in the window, or now in Iris) exits Tor "
                                        "traffic (High) or runs a guard / middle relay (Medium-High), by the Tor "
                                        "Project's data in VPNDB, while the domain used it (exit dates checked when "
                                        "known). New exits (last 30 days) are called out.",
                                        "The host also carries anonymized Tor traffic; services on it are often run "
                                        "by operators who want to stay unattributed."),
    "Domain on Residential Proxy Exit": ("High", "T1090.002 (Proxy: External Proxy)",
                                         "An IP the domain resolves to is a residential or mobile proxy exit (VPNDB). "
                                         "Confidence is VPNDB's for the IP (Low below its medium level).",
                                         "Rented home connections hide the real server and evade IP reputation; "
                                         "legitimate sites rarely point DNS at one."),
    "Domain on VPN / Proxy Exit": ("Medium-High", "T1090.002 (Proxy: External Proxy)",
                                   "An IP the domain resolves to is an exit of a commercial VPN or datacenter proxy "
                                   "service (VPNDB). Confidence is VPNDB's for the IP.",
                                   "Unusual for a website: can mark infrastructure meant to be hard to attribute. A "
                                   "shared exit identifies the service, not the actor."),
    "Domain on Dedicated Anonymizer Exit": ("High", "T1090.002 (Proxy: External Proxy)",
                                            "An IP the domain resolves to is a VPN or proxy exit few customers share "
                                            "(VPNDB sharing LOW or IOC value HIGH), e.g. a dedicated VPN IP.",
                                            "The address points to one customer, so it is a usable actor indicator: "
                                            "pivot on it and block it."),
    "Hosting Moved onto Anonymizer Exit": ("Medium-High", "T1090.002 (Proxy: External Proxy)",
                                           "The domain resolved to ordinary hosting first and its newest addresses "
                                           "in the window are VPN, proxy or Tor exits (passive DNS and VPNDB).",
                                           "Moving a domain behind an anonymizer often follows a report or a block "
                                           "and hides the real server."),
    "Domain Rotates Across Anonymizer Exits": ("Medium-High", "T1090.002 (Proxy: External Proxy)",
                                               "The domain resolves to three or more anonymizer exits, or to exits "
                                               "of two or more providers (VPNDB).",
                                               "Rotating exits keeps hosting ahead of IP blocks and reputation lists."),
    "Newly Registered Domain on Anonymizer Exit": ("High", "T1583.001 (Acquire Infrastructure: Domains)",
                                                   "A Newly Registered Domain that already resolves to a VPN, proxy "
                                                   "or Tor exit (Iris Investigate and VPNDB).",
                                                   "A fresh domain hidden behind an anonymizer from the start is a "
                                                   "common phishing and C2 set-up."),
    "Anonymizer Exit Shared by Analyzed Domains": ("Medium-High",
                                                   "T1583.003 (Acquire Infrastructure: Virtual Private Server)",
                                                   "Two or more analyzed domains resolve to the same anonymizer exit, "
                                                   "one that few customers share (shared exits are left out).",
                                                   "Domains behind one non-shared exit are probably run by the same "
                                                   "operator."),
    "Hosted Among Tor Exits": ("Medium", "T1090.003 (Proxy: Multi-hop Proxy)",
                               "The domain's IPs are not Tor relays, but sit in a Tor exit prefix, or on a network "
                               "carrying 0.5 % or more of Tor exit traffic or 10+ exit addresses (VPNDB /tor).",
                               "A hoster that welcomes Tor exits, often privacy or bulletproof-style, or a server "
                               "next to the operator's own exits."),
    "Hosted Among Anonymizer Exits": ("Medium", "T1090.002 (Proxy: External Proxy)",
                                      "The domain's IPs are not exits, but their /24 holds known VPN / proxy exits, or "
                                      "the network (Iris ASN) is one VPN provider's (VPNDB).",
                                      "The domain is probably hosted on an anonymizer operator's servers or next to "
                                      "them."),
    # Lookalikes (need brand watchlist entries)
    "Homoglyph / IDN Brand Impersonation": ("Critical", "T1583.001 (Acquire Infrastructure: Domains)",
                                            "Domain renders like a protected brand using look-alike characters.",
                                            "Built to deceive users visually; strongly associated with phishing."),
    "Typosquatting Lookalike": ("High", "T1583.001 (Acquire Infrastructure: Domains)",
                                "Small edit distance from a protected brand domain.",
                                "Catches mistyped traffic and lends credibility to phishing."),
    "Combosquatting (Brand + Keyword)": ("High (Medium without a risky keyword)", "T1583.001 (Acquire Infrastructure: Domains)",
                                         "Brand as a whole word of the name, or joined only to words such as login, secure, support or digits "
                                         "(`paypallogin`; `purchase` does not match `chase`).",
                                         "Brand + keyword names are the most common phishing domain pattern."),
    "Brand in Subdomain": ("Medium-High", "T1566.002 (Phishing: Spearphishing Link)",
                           "Protected brand appears as a subdomain of an unrelated domain.",
                           "Makes phishing links look legitimate at a glance."),
    "Brand Name on Alternate TLD": ("Low", "T1583.001 (Acquire Infrastructure: Domains)",
                                    "Exact brand name registered on another TLD.",
                                    "May be defensive or third-party; watch for activation."),
    "IDN / Punycode Domain": ("Low", "T1583.001 (Acquire Infrastructure: Domains)",
                              "Domain uses internationalized (punycode) characters.",
                              "Context for homoglyph abuse; common and benign in many languages."),
    # Correlation
    "Shared Infrastructure Cluster": ("High (strong link) / Medium-High", "T1583.001 (Acquire Infrastructure: Domains)",
                                      "Linked to other analyzed domains by a shared certificate, key, or tracker (strong), or by "
                                      "IP plus name server. Confidence High for strong links, otherwise Medium.",
                                      "Shared infrastructure reveals campaigns run by one operator."),
    "Domain Hopping on Shared IP": ("Medium-High", "T1583.001 (Acquire Infrastructure: Domains)",
                                    "A new domain appears on an IP within Domain Hopping Gap (Days) after the previous one went dark. "
                                    "Confidence High with 2+ hops.",
                                    "Typical takedown evasion: the operator moves to a fresh domain on the same server."),
    # Certificates
    "Rapid Weaponization (Cert-to-DNS Gap)": ("High", "T1588.004 (Obtain Digital Certificates)",
                                              "Certificate issued within Cert-to-DNS Gap (Hours) of the first DNS record.",
                                              "Certificate and DNS set up together point to scripted, disposable deployment."),
    "Self-Signed Certificate Detected": ("Critical to Low (graded: High, Medium)", "T1573.002 (Encrypted Channel)",
                                         "Certificate subject equals its issuer. Graded like the Certificates page: "
                                         "a C2 framework's default certificate or one served on the domain now is "
                                         "Critical, an expired one a step lower.",
                                         "Common on C2 servers and malware panels; untrusted by browsers."),
    "Known C2 Certificate Fingerprint (JA4X)": ("High", "T1588.002 (Obtain Capabilities: Tool)",
                                                "The certificate's JA4X is on the built-in list of C2 framework and "
                                                "malware fingerprints (Cobalt Strike, Sliver / Havoc, Metasploit, "
                                                "Qakbot, ...).",
                                                "The certificate was generated the way that tool generates its own. "
                                                "Other certificates built with the same fields match too, so confirm "
                                                "with the certificate (self-signed, default names, the IP's ports)."),
    "Dual-Use Tool Certificate Fingerprint (JA4X)": ("Medium", "T1572 (Protocol Tunneling)",
                                                     "The certificate's JA4X is on the built-in list of dual-use tools "
                                                     "(e.g. SoftEther VPN).",
                                                     "Legitimate software that attackers also run for tunnels and "
                                                     "remote access; unexpected on a phishing or brand domain."),
    "Network Device Default Certificate (JA4X)": ("Medium", "T1584.008 (Compromise Infrastructure: Network Devices)",
                                                  "The certificate's JA4X is on the built-in list of network devices' "
                                                  "default certificates (e.g. Cisco RV32x routers).",
                                                  "The host serves a router's own management certificate; small-office "
                                                  "routers are often compromised and used as relays."),
    "Code-Generated Certificate Layout (JA4X)": ("Medium", "T1587.003 (Develop Capabilities: Digital Certificates)",
                                                 "The certificate's JA4X has an empty issuer part (no issuer "
                                                 "attributes) and is not on a built-in list.",
                                                 "No CA issues a certificate without issuer attributes; C2 frameworks "
                                                 "that generate their own do (Sliver, Havoc). Search CertsQL for the "
                                                 "JA4X to find the set."),
    "Short-Lived Certificate": ("Low (informational, not scored)", "T1588.004 (Obtain Digital Certificates)",
                                "Certificate valid at most Short-Lived Certificate Max Validity (Days), e.g. Let's Encrypt's "
                                "6-day profile.",
                                "Context only: short lifetimes reflect good automation, so this is excluded from risk scores and DIF."),
    "Mega-SAN Cluster (Bulk Infrastructure)": ("High", "T1583.001 (Acquire Infrastructure)",
                                               "One certificate covers at least Mega-SAN Min Root Domains registrable domains. Low confidence "
                                               "on CDN / shared-hosting certificates (Cloudflare, cPanel, ...).",
                                               "Bundling unrelated domains in one certificate links bulk-registered infrastructure."),
    "Multi-IP Certificate (Shared C2 / Proxy Cluster)": ("High", "T1008 (Fallback Channels)",
                                                         "Certificate for an IP target also lists other raw IPs.",
                                                         "Points to a cluster of C2 or proxy nodes sharing one certificate."),
    "Bare-IP Certificate (C2 / Proxy Node)": ("Critical / Medium-High (public short-lived IP certificate)", "T1008 (Fallback Channels)",
                                              "Certificate common name or SAN contains a raw IP address. A publicly trusted, short-lived "
                                              "IP certificate (e.g. Let's Encrypt) is Medium-High with Low confidence.",
                                              "Legitimate sites rarely certify bare IPs; C2 frameworks often do."),
    "SSL Common Name (CN) Mismatch": ("Medium-High", "T1071.001 (Web Protocols / Shared C2)",
                                      "Served certificate is issued to a different name.",
                                      "Shared or reused certificates can expose hidden relationships or shared C2."),
    "Pre-Certificate Staging (CT Log Only)": ("Low", "T1588.004 (Obtain Digital Certificates)",
                                              "Certificate seen only as a CT log precertificate.",
                                              "Shows infrastructure being prepared before it goes live."),
    "CT Log Evasion / Missing SCTs": ("Medium-High", "T1588.004 (Obtain Capabilities: Digital Certificates)",
                                      "Final (not pre-) certificate from a public CA without embedded Signed Certificate Timestamps.",
                                      "Missing SCTs suggest an interception proxy or attempts to avoid CT monitoring."),
    "Rogue Certificate Authority": ("Critical", "T1553.004 (Subvert Trust Controls: Install Root Certificate)",
                                    "Endpoint serves a certificate with CA signing capability (CA=True).",
                                    "A host that can mint certificates enables traffic interception."),
    "Non-Compliant Validity Window": ("Medium", "T1588.004 (Obtain Digital Certificates)",
                                      "Publicly trusted certificate valid longer than the CA/B Forum limit on its issue date: "
                                      "398 days from 2020-09-01, 200 from 2026-03-15, 100 from 2027-03-15, 47 from 2029-03-15.",
                                      "Browsers reject such certificates; typical of private or misconfigured CAs."),
    "Deprecated Signature Algorithm": ("High (Medium before 2017)", "T1588 (Obtain Capabilities)",
                                       "Certificate signed with MD5 or SHA-1. Issued before 2017 (when public CAs "
                                       "stopped SHA-1) it is Medium with Low confidence: history, not a new forgery.",
                                       "Weak signatures can be forged and indicate outdated or attacker-made certificates."),
    "Non-Public / Private CA Certificate": ("Medium", "T1588.004 (Obtain Digital Certificates)",
                                            "Issuer shows no sign of public trust (no SCTs, no CA/B policy, unknown CA).",
                                            "Typical of internal CAs, interception proxies, or attacker-run infrastructure."),
    "CAA Mismatch (CA Trust Unverified)": ("Medium", "T1588.004 (Obtain Digital Certificates)",
                                           "Issuer not allowed by the domain's CAA policy, but public trust of the CA is unknown.",
                                           "Possible CAA breach that needs confirmation."),
    "Wildcard Issuance Forbidden by CAA Policy": ("Critical", "T1588.004 (Obtain Digital Certificates)",
                                                  "Publicly trusted wildcard certificate although CAA forbids wildcards.",
                                                  "Issuance against the owner's policy points to mis-issuance or account compromise."),
    "Unauthorized CA Certificate Issuance (CAA Breach)": ("Critical", "T1588.004 (Obtain Digital Certificates)",
                                                          "Publicly trusted certificate from a CA the CAA policy does not authorize.",
                                                          "Strong sign of mis-issuance or a hijacked domain."),
    "Suspicious CAA Stripping / Evasion": ("High", "T1562.001 (Disable or Modify Tools)",
                                           "Unauthorized certificate issued within 90 days after CAA records disappeared.",
                                           "Removing CAA before issuing is a way to bypass the owner's CA restrictions."),
    "Wildcard Infrastructure Sprawl": ("Medium", "T1584.001 (Compromise Infrastructure: Domains)",
                                       "Wildcard certificate bundling 5 or more names.",
                                       "Supports rotating subdomains for phishing or C2 without new certificates."),
    "Wildcard Certificate Observed": ("Low", "T1588.004 (Obtain Digital Certificates)",
                                      "Wildcard certificate with fewer than 5 names.",
                                      "Common for legitimate hosting; new hostnames under it never appear in CT logs."),
    "Suspicious Domain Validation (DV)": ("Medium", "T1588.004 (Obtain Digital Certificates)",
                                          "DV certificate on a domain with risk score above Suspicious DV Min Risk Score.",
                                          "DV certificates are free and instant, so they are the default for abusive sites."),
    "Weak Cryptographic Key Material": ("High", "T1588 (Obtain Capabilities)",
                                        "RSA key below 2048 bits or EC key below 224 bits.",
                                        "Weak keys are breakable and rare on maintained infrastructure."),
    "Certificate Churn (Ephemeral SSL)": ("High", "T1588.004 (Obtain Digital Certificates)",
                                          "At least Cert Churn Min Early Replacements within Cert Churn Window (Days): certificates "
                                          "reissued for the same names while the previous one still had over half its validity left. "
                                          "Scheduled renewals of short-lived certificates do not count.",
                                          "Replacing valid certificates early accompanies disposable or evasive infrastructure."),
    # Lifecycle, certificate timing, compound and cross-domain rules
    "Certificate Staged Before DNS": ("Medium", "T1608.003 (Stage Capabilities: Install Digital Certificate)",
        "A certificate issued 1 to 30 days before a hostname it names first resolved (each hostname apart).",
        "Infrastructure prepared ahead of going live is typical of phishing and C2 staging."),
    'Backdated Certificate': ('Medium', 'T1588.004 (Obtain Digital Certificates)',
        "Not Before more than 48 hours earlier than the certificate's first embedded CT log timestamp (SCT).",
        'Backdating hides when a certificate was really made; CAs backdate by an hour at most.'),
    "Unusual Certificate Fields": ("Medium", "T1587.003 (Develop Capabilities: Digital Certificates)",
        "CA-issued certificate with a serial of 2 bytes or less, extended key usage without server authentication, or a default subject (Internet Widgits, Some-State, ...).",
        "Fields that tools set and public CAs never do point to a hand-made or tool-made certificate."),
    "Re-Registered Domain": ("Medium", "T1583.001 (Acquire Infrastructure: Domains)",
        "Iris first saw the domain over a year before its current registration, or it has certificates issued more than 30 days before the registration.",
        "Lapsed domains are drop-caught and reused for their history and reputation."),
    'Disposable Registrant Email': ('Medium', 'T1585.002 (Establish Accounts: Email Accounts)',
        "The registration's email domains include a throwaway mail service (mailinator, guerrillamail, cock.li, ...).",
        'Nobody can be reached there for abuse reports; legitimate owners rarely register with one.'),
    "Name Server Churn": ("Medium", "T1584.002 (Compromise Infrastructure: DNS Server)",
        "Three or more name server providers within 30 days (parking name servers not counted).",
        "Abusive domains move DNS repeatedly to stay ahead of takedowns."),
    "Registrar Transfer then New Name Servers": ("Medium-High", "T1584.001 (Compromise Infrastructure: Domains)",
        "A registrar change in Domain History followed within 14 days by name servers of a provider that is neither a large DNS provider nor parking.",
        "The pattern of a hijacked or drop-caught domain being put to new use."),
    "Phishing Kit Staging": ("Critical", "T1583.001 (Acquire Infrastructure: Domains)",
        "Compound: a brand lookalike, newly registered (or re-registered), with a certificate issued as a hostname went live (Rapid Weaponization or Certificate Staged Before DNS).",
        "Three independent signals together describe the setup of a phishing site."),
    "Weaponized Reactivation": ("High", "T1583.001 (Acquire Infrastructure: Domains)",
        "Compound: parked, dormant, re-registered or transferred domain (Parking Exit, Parked-to-Weaponized, Re-Registered, Registrar Transfer) that got a fresh, staged or backdated certificate.",
        "Aged domains are bought or hijacked to borrow their reputation."),
    "Subdomain Takeover in Progress": ("Critical", "T1584.001 (Compromise Infrastructure: Domains)",
        "Compound: a dangling CNAME and a subdomain repointed to another provider on the same domain.",
        "A takeover may already have happened, not only be possible."),
    "Generated Fast-Flux Domain": ("Critical", "T1568.001 (Fast Flux DNS)",
        "Compound: a generated-looking (DGA) name with fast-flux or ASN-diverse flux.",
        "The pattern of botnet C2 domains."),
    "Bulletproof-Hosted New Domain": ("High", "T1583.003 (Acquire Infrastructure: Virtual Private Server)",
        "Compound: newly registered and on a suspicious name server, watchlisted hosting, an anonymizer exit, or with name server churn.",
        "Set up to resist takedown from day one."),
    "Mail-Capable Lookalike": ("High", "T1566.002 (Phishing: Spearphishing Link)",
        "A brand lookalike with MX records and no DMARC record, no SPF, or SPF without -all.",
        "It can send mail that passes as the brand."),
    "Lure Subdomain": ("Medium", "T1566.002 (Phishing: Spearphishing Link)",
        "Subdomains whose names alone score Medium or more in Subdomain Triage with a phishing word, brand, embedded domain or punycode.",
        "Lure names hide the real domain in links sent to victims."),
    "Bulk Registration Cohort": ("Medium", "T1583.001 (Acquire Infrastructure: Domains)",
        "Analyzed domains registered within 48 hours at the same registrar that also share an own name server, a registrant mail domain or a hosting ASN.",
        "Registered together by one operator, often for one campaign."),
    "Campaign Wave (Same-Day Setup)": ("Medium", "T1583.001 (Acquire Infrastructure: Domains)",
        "Three or more analyzed domains registered within 48 hours, each given a certificate by the same CA within 72 hours of registering.",
        "One campaign set up in one go."),
    "Linked to Confirmed-Malicious Domain": ("High", "T1583.001 (Acquire Infrastructure: Domains)",
        "In a Strong infrastructure cluster with a domain you marked Malicious (domain verdict on Alerts or the Domain profile).",
        "Domains sharing certificates, keys, trackers or rare hosting with a confirmed-bad one are usually the same operator."),
}

CATALOG_COLUMNS = ["Threat Type", "In This Run", "Severity", "Confidence", "Your Verdicts", "Category", "MITRE ATT&CK",
                   "Tactic", "Fires When", "Why It Matters"]


def rule_catalog_frame(alerts=None, feedback=None):
    """One row per rule, rules that fired in `alerts` first (by count), then by severity. `feedback`
    (core.triage.rule_feedback) fills Your Verdicts."""
    feedback = feedback or {}
    counts = alerts["Threat Type"].value_counts() if alerts is not None and not alerts.empty else pd.Series(dtype=int)
    rows = []
    for threat_type, (severity, mitre, trigger, why) in RULE_CATALOG.items():
        category, confidence = RULE_METADATA.get(threat_type, ("Other", "Medium"))
        technique = mitre.split(" ")[0]
        rows.append({
            "Threat Type": threat_type, "In This Run": int(counts.get(threat_type, 0)), "Severity": severity,
            "Confidence": confidence, "Category": category,
            "Your Verdicts": (f"{feedback[threat_type]['Malicious']} malicious / {feedback[threat_type]['Benign']} benign"
                              if threat_type in feedback else ""), "MITRE ATT&CK": mitre,
            "Tactic": MITRE_TACTICS.get(technique.split(".")[0], "Other"), "Fires When": trigger, "Why It Matters": why,
        })
    frame = pd.DataFrame(rows, columns=CATALOG_COLUMNS)
    base_severity = frame["Severity"].str.extract(r"^(Critical|High|Medium-High|Medium|Low)")[0]
    frame["_weight"] = base_severity.map(SEVERITY_WEIGHTS).fillna(0)
    frame["_confidence"] = frame["Confidence"].map({c: i for i, c in enumerate(CONFIDENCE_ORDER)})
    frame = frame.sort_values(["In This Run", "_weight", "_confidence", "Threat Type"], ascending=[False, False, True, True])
    return frame.drop(columns=["_weight", "_confidence"]).reset_index(drop=True)
