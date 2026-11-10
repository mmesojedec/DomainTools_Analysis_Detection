# Use Cases

The investigations the tool supports, what to enter in the target box, where to look in the results, and what each one
surfaces. The use cases are grouped by goal; each row is a starting point, not the only way to use the app.

Eight of them are ready-made on the app's **Start** page (*Triage a suspicious domain*, *Map related infrastructure*,
*Hunt C2 infrastructure*, *Subdomain takeover check*, *Phishing & lookalikes*, *Monitor changes*, *Check IP addresses
(VPN, proxy, Tor)*, *Report & export evidence*). Each card lists the
lookups a run makes and their limits; **Use this** sets those collection options and the analysis window, and the
Summary then shows its plan as links. You can change what a use case looks up, or save profiles of your own for other
investigations, on *Settings → Use cases & profiles*: see [Use cases and profiles](USAGE.md#use-cases-and-profiles),
and the [Reference](REFERENCE.md#use-cases-and-profiles) for what each one sets.

Every use case checks the hosting IPs in VPNDB (with a VPNDB key), each with a budget that suits it: the infrastructure,
C2 and reporting use cases send up to 500 IPs, give 50 exits the full verdict and history, and look at the
neighbourhood (neighbouring /24s, hosting networks, other domains on dedicated exits); triage sends 100 and gives 20
with the neighbourhood; takeover, phishing and monitoring send 100–200 and give 10–20 without it. *Check IP addresses*
is the only one that turns on *Only the VPNDB IP check*: there VPNDB is the only source. *Monitor changes* also keeps
re-runs cheap: it fetches 90 days of Domain History, and turns on *Incremental passive DNS*, so with an offline copy of
the last run DNSDB returns only the records seen since then.

For what a run collects and in which order see [Workflows](WORKFLOWS.md), for every option see
[Usage](USAGE.md), and for reading alerts and scores see the [User Guide](USER_GUIDE.md).

## Contents

- [Triage and threat hunting](#triage-and-threat-hunting)
- [Certificates and attack surface](#certificates-and-attack-surface)
- [Infrastructure and hosting](#infrastructure-and-hosting)
- [Monitoring, re-use and sharing](#monitoring-re-use-and-sharing)

## Triage and threat hunting

| Use case | Start with | Where to look | What it surfaces |
| --- | --- | --- | --- |
| Triage one suspicious domain | The domain | KPI banner, **Alerts**, alerts grouped by *Finding* | Risk score, newly registered and weaponized, parked-to-weaponized, hosting and name server reputation |
| Spot phishing preparation | Domains under review | Alerts (*Email*, *Registration & Lifecycle*), **Hostname Inventory** *Sensitive name* flag | MX / SPF added after dormancy, new DV certificates, `login.` / `secure.` style hostnames |
| Catch brand lookalikes | Domains, with your brands on *Settings → [Brand watchlist](REFERENCE.md#brand-watchlist)* (e.g. `paypal`, `paypal.com`) | Alerts (*Lookalike / Brand*) | Typosquats (`paypa1.com`), homoglyphs (Cyrillic `а`), combosquats (`paypal-login.com`), the brand on another TLD (`paypal.net`); IDN / punycode domains are flagged even without a watchlist |
| Spot DNS tunneling or encoded TXT | Domains | Alerts (*DNS Behavior*), **Raw Records** (TXT) | Long encoded TXT values, TXT SaaS fingerprints |
| Find malicious subdomains on a shared platform | `pages.dev`, `workers.dev`, a free subdomain service | **Subdomain Triage** | Subdomains with phishing words, brands, embedded domains or generated names, ranked; focus the views on them |
| Track piracy / IPTV infrastructure | Domains | Alerts (*Web & Content*) | IPTV endpoints in passive DNS, live streaming panels |
| Hunt C2 infrastructure | Suspected C2 domains or IPs, use case *Hunt C2 infrastructure* | **Certificates → Self-Signed**, **Pivot Ranking**, **DNS & Hosting** (domain hopping) | C2 default and live self-signed certificates, rare shared values, domains hopping across the same IPs |
| Find domains from their certificates, then analyze them | A CertsQL query, e.g. `san_dns contains "login"` AND `validity_not_before greater_than "2026-10-05"` | **CertsQL** (menu, or Data source *CertsQL*): the certificate, domain, IP and hostname tables, then analyze the ticked domains, IPs or both with a use case | Every certificate matching the names, issuer, key, validity or extensions, with the domains and IPs they name; the ones you pick analyzed as a new run |
| Find domains by what they share, then analyze them | An IrisQL query, e.g. `REGISTRANT_ORG EXACTLY_MATCH "…"` or `IP IN ["198.202.211.1", "198.202.211.2"]` | **IrisQL** (menu, or Data source *IrisQL*): the domain and IP tables, then analyze the ticked domains, IPs or both with a use case | Every domain in Iris with the registrant, range, name server, tracker or title, ranked by risk; the ones you pick analyzed as a new run |
| Follow a hunt from lead to lead | Any run | Summary *Leads to follow* (*Analyze*), certificate cards (*Analyze its domains*), Iris search results | A new run per lead, linked to the run it came from; **Runs & Diffs → Hunt Tree** shows the whole hunt |
| Keep track of what you reviewed | Any run | Status per alert group (**Alerts**), verdict per domain (**Domain profile**), Summary *Hunt status* | Open and reviewed alerts across runs; reruns show what is still open |

A suggested order for reading the results is in [A suggested triage workflow](USER_GUIDE.md#a-suggested-triage-workflow).

## Certificates and attack surface

| Use case | Start with | Where to look | What it surfaces |
| --- | --- | --- | --- |
| Pivot from a certificate | SHA-256, `cn:`, `san:`, `serial:`, `issuer:` | Certificate review steps, then any page | Every domain and IP the certificate covers, and where it was observed |
| Map an organization's attack surface | Organization name (e.g. `DomainTools`) | Certificate preview *Hostnames*, **Hostname Inventory** | Hostnames from certificates, names that never resolved, resolving names without a certificate, new names |
| Investigate selected hostnames | Hostnames ticked in the preview, or *Focus on hostnames* | Hostname focus banner, any page | Passive DNS and certificates of those hostnames only, with gap-fill when the domain was capped |
| Find subdomain takeover risks | Your own domains | **CNAME Chains** (*Dead end*, *Takeover-prone*), alerts (*Hosting & DNS Providers*) | Subdomains whose CNAME still points to a deleted S3 bucket, Azure app, Heroku app, GitHub Pages site or similar: anyone could claim the name |
| Audit certificates and CAA policy | Your own domains | **Certificates** (CAA audit, validity, keys) | CAA breaches, mis-issued wildcards, weak keys, deprecated signatures, over-long validity |
| Find C2 or proxy servers | IPs, or domains with IP certificates | **Certificates** (bare-IP certificates), alerts | Bare-IP, multi-IP and self-signed certificates |

How the certificate inputs are expanded is in [Certificate inputs](USAGE.md#certificate-inputs).

## Infrastructure and hosting

| Use case | Start with | Where to look | What it surfaces |
| --- | --- | --- | --- |
| Check who is behind IP addresses | IPv4 or IPv6 addresses or CIDR ranges, with *Check IP addresses (VPN, proxy, Tor)*: only VPNDB is queried | **Summary** (one card per IP), **VPNDB**, **Alerts**, **Raw Records** (*VPNDB Responses*), **Data Export** (*VPN / proxy / Tor*, *CIDR* tables) | VPN, residential proxy, Tor or hosting, the provider and how sure VPNDB is, Tor role, whether the exit is shared, network, ASN, country, claimed vs. real location; IPv6 is answered *not collected*; for a range, its providers and their shares and the addresses VPNDB reached in it |
| Find domains hosted on anonymizers | Domains (any use case, with a VPNDB key) | **VPNDB** (flow, heatmap, exposure timeline, Iris cross-check, neighbourhood, leads), **Summary** (*VPNDB* column, Analysis Details), **Domain profile** (*VPN, residential proxy and Tor* card), Alerts (*Hosting & DNS Providers*) | Domains resolving to Tor relays, residential proxy or VPN exits; dedicated exits worth pivoting on; hosting moved onto or rotating across exits; new domains on an exit; domains sharing a non-shared exit |
| Check every address of a range | A CIDR range (e.g. `45.248.77.0/24`), in any use case or *Check IP addresses* | **VPNDB → CIDR ranges** (one cell per address), the range card (per-IP table) | Which providers have exits in the range and their share, measured vs. interpolated exits, residential proxy addresses among VPN ones |
| Tell an anonymizer from reused hosting | Domains | **VPNDB → Exposure timeline** | Whether the IP was an exit while the domain resolved to it, or only became one later (no exit alert then) |
| Pivot from an anonymizer exit | Domains on a dedicated exit | **VPNDB → Iris cross-check** and **Leads** | Strong pivots (dedicated, few Iris domains) vs. shared-exit noise; other domains DNSDB saw on the exit, each with *Analyze* |
| Everything about one IP | Any run with VPNDB | Select the IP in any VPNDB table (VPNDB page, Summary, Domain profile) | VPNDB's verdict and whole answer, weekly history, the domains that used it and when, Iris domain count, its /24 and network, its share of Tor exit traffic; a full verdict on demand for IPs the run only summarized |
| Check the Tor network around the hosting | Domains | **Tor network** (Infrastructure), alerts *Domain on Tor Relay / Exit Node* and *Hosted Among Tor Exits* | Tor relays and exits, the networks and countries carrying most Tor exit traffic, the run's hosting networks among them; domains on a Tor exit or relay while they used it, or next to Tor exits |
| Check whether an IP is a Tor exit | IP addresses with *Check IP addresses* | **Summary** card, IP card (*Verdict*, *Full VPNDB answer*) | Exit now or until when, each relay (nickname, role, flags, first seen), share of Tor exit traffic, the operator's relay family, VPNs whose Tor feature exits there |
| Find hosting next to VPN servers | Domains | **VPNDB → Neighbourhood**, alert *Hosted Among Anonymizer Exits* | /24 ranges with known exits around the domain's IPs, hosting networks run by one VPN provider |
| Find a threat actor's other domains | One or more malicious domains | **Pivot Ranking** (*Strong*, *Shared in run*), *Find domains in Iris* | Rare IPs, name servers, emails, certificates and trackers, and the other domains in Iris that share them |
| Link domains to one operator | Several domains | **DNS & Hosting** (campaign & hosting), *Group by: Campaign Cluster*, DIF table | Shared IPs, name servers, certificates and trackers; look-alike setups through the DIF |
| Detect fast-flux or bulletproof hosting | Domains | **DNS & Hosting**, alerts (*DNS Behavior*, *Hosting*) | Rapid IP rotation across networks, offshore hosting and name servers |
| Map where CNAME redirects lead | Domains | **CNAME Chains** (chain, outcome, chain map), *Chase CNAMEs* | Every alias chain to its final addresses, like CNAME chasing in DNSDB Scout; long chains and loops |
| Spot subdomains pointed at attacker services | Domains, or a suspected compromised organization | **CNAME Chains** (service type), alerts | CNAMEs to dynamic DNS and tunnels (ngrok, Duck DNS, Cloudflare quick tunnels), free hosting with lure names, CNAMEs repointed to a new provider |
| Link domains through CNAME chains | Several domains | Alerts (*CNAME Link Between Analyzed Domains*), **CNAME Chains → Cross-domain links** | Domains whose hostnames alias into each other or through the same dedicated host, e.g. one fronting proxy for a whole campaign |
| Find origin servers behind a CDN | Domains on a CDN | Alerts (*Hosting*), **DNS & Hosting** (campaign & hosting) | Non-CDN IPs that may expose the origin |
| Find domains that moved to the same IPs | Domains, with *Pivot on hosting IPs* | **DNS & Hosting** (campaign & hosting) (domain hopping) | New domains appearing on an IP shortly after another left |

## Monitoring, re-use and sharing

| Use case | Start with | Where to look | What it surfaces |
| --- | --- | --- | --- |
| Monitor domains over time | The same target list, re-run later with the *Monitor changes* use case and *Save offline copy* | **Runs & Diffs**, *Only first detected in this run* | New, resolved and recurring alerts, trends, per-domain history; each run's API queries (Runs & Diffs), and only new passive DNS records per re-run |
| Re-analyze without API calls | An offline dataset | Data source *Offline dataset* | The same views with different thresholds or windows, no quota used |
| Repeat an earlier analysis | A recent run | **Start → Recent runs** (*Run again*, *Load offline copy*, *Open in Runs & Diffs*) | The same targets with the run's use case, analysis window and collection options, or its saved data with no API calls |
| Find where an indicator was seen before | An IP, domain or hostname, name server, MX host, certificate SHA-256, tracker code or email (defanged is fine) | **Sightings** (top menu) | Every saved run and offline dataset it was observed in, when, with which domains and how many alerts they had; open the run, load the dataset or analyze the indicator; no API query |
| Re-run a lookup in another tool | Any run | **Lookup Queries** | CertsQL, DNSDB names and record types (record-type lookups and CNAME chase steps included), Iris domain lists, VPNDB requests, `domaintools` CLI and curl commands |
| Share findings | Any run | *Export Detections, IOCs & Report* under the alerts | Detections and IOC lists (CSV / JSON), STIX 2.1 bundle, HTML / Markdown evidence report |
| Brief a manager or file a takedown | Any run | **Data Export → Case report** | One printable HTML page (save as PDF): your summary and recommendation, the run at a glance, top alerts with evidence, risk by domain, infrastructure snapshot, indicators |
| Share confirmed indicators | Alerts or domains marked Malicious | *Confirmed indicators* (Alerts page and **Data Export**) | Only what you confirmed, as CSV, a MISP event or a STIX bundle, plus Iris searches for more of the same infrastructure |
| Watch a target list | Any run, *Watch this list* on the Summary | **Runs & Diffs → Watched Lists** (*Run now*), Summary *What's new since the last analysis* | New IPs, name servers, certificates, hostnames and alerts since the list's last run |
| Hand data to another team | Any run | **Data Export** | IOCs, tables (detections, CNAME chains, hostname inventory, ...) and raw records as CSV or NDJSON, zipped with a manifest |
| Look up a hostname's certificates elsewhere | Domains | **Hostname Inventory**, *Certificates by hostname* | Every certificate hash (SHA-256 / SHA-1) that names or covers each hostname |
