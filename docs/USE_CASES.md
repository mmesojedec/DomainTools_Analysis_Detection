# Use Cases

The investigations the tool supports, what to enter in the target box, where to look in the results, and what each one
surfaces. The use cases are grouped by goal; each row is a starting point, not the only way to use the app.

Eight of them are ready-made on the app's **Start** page (*Triage a suspicious domain*, *Map related infrastructure*,
*Hunt C2 infrastructure*, *Subdomain takeover check*, *Phishing & lookalikes*, *Monitor changes*, *Check IP addresses
(VPN, proxy, Tor)*, *Report & export evidence*). Each card lists the
lookups a run makes and their limits; **Use this** sets those collection options and the analysis window, and the
Summary then shows its plan as links. You can change what a use case looks up, or save profiles of your own for other
investigations, on *Settings → Collection options*: see [Use cases and profiles](USAGE.md#use-cases-and-profiles),
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
| Find lookalikes of your brands before they are used | Your brands on *Settings → Brands & allowlist* | **Hunt lookalikes in IrisQL** (same tab), then **Search** on the IrisQL page | Registered typo, look-alike character, other-TLD and brand + phishing word names of your brands, ready to analyze with *Phishing & lookalikes* |
| Spot DNS tunneling or encoded TXT | Domains | Alerts (*DNS Behavior*), **Evidence → Records** (TXT) | Long encoded TXT values, TXT SaaS fingerprints |
| Find malicious subdomains on a shared platform | `pages.dev`, `workers.dev`, a free subdomain service | **Subdomain Triage** | Subdomains with phishing words, brands, embedded domains or generated names, ranked; focus the views on them |
| Track piracy / IPTV infrastructure | Domains | Alerts (*Web & Content*) | IPTV endpoints in passive DNS, live streaming panels |
| Hunt C2 infrastructure | Suspected C2 domains or IPs, use case *Hunt C2 infrastructure* | **Certificates → Self-Signed**, **Hunt map → All pivots**, **DNS & Hosting** (domain hopping) | C2 default and live self-signed certificates, rare shared values, domains hopping across the same IPs |
| Find domains from their certificates, then analyze them | A CertsQL query, e.g. `san_dns contains "login"` AND `validity_not_before greater_than "2026-10-05"` | **CertsQL** (menu, or *Find targets with CertsQL* on Start): the certificate, domain, IP and hostname tables, then analyze the ticked domains, IPs or both with a use case | Every certificate matching the names, issuer, key, validity or extensions, with the domains and IPs they name; the ones you pick analyzed as a new run |
| Find certificates made by the same tool (JA4X) | A JA4X fingerprint, e.g. `ja4x equals "2166164053c1_2166164053c1_30d204a01551"` (Cobalt Strike default certificate), or the *JA4X* column of an earlier CertsQL result | **Certificates → JA4X & C2** after a run (known tools, *Check how common*, *Find certificates with this JA4X*), or **CertsQL**, example *JA4X: Sliver / Havoc C2 certificates* or *JA4X: Cobalt Strike default certificate* | Certificates generated with the same issuer, subject and extension layout, typical of C2 frameworks and malware kits, and the domains and IPs they name |
| Tell whether a JA4X is a known tool | A JA4X value from a run, a CertsQL result, or one you were given | The **fingerprint card**: *JA4X worth a look* on Summary, Certificates → Overview and the Domain profile; **Certificates → JA4X & C2** (*Look up any JA4X*); the top of CertsQL results | What the value matches (C2 / malware, dual-use tool, network device, code-generated, not listed) and its source; the three parts decoded; whether the run's certificates carry the tool's default names or share only the layout (Cobalt Strike's keytool layout is also used by ordinary Java servers) |
| Find domains by what they share, then analyze them | An IrisQL query, e.g. `REGISTRANT_ORG EXACTLY_MATCH "…"` or `IP IN ["198.202.211.1", "198.202.211.2"]` | **IrisQL** (menu, or *Find targets with IrisQL* on Start): the domain and IP tables, then analyze the ticked domains, IPs or both with a use case | Every domain in Iris with the registrant, range, name server, tracker or title, ranked by risk; the ones you pick analyzed as a new run |
| Follow a hunt from lead to lead | Any run | Hunt map *Suggested hunt* (start order, ranked branches with *Analyze* / *Find in Iris*) or *More leads* (*Analyze*), certificate cards (*Analyze its domains*), Iris search results | A new run per lead, linked to the run it came from; **Hunt → Hunt map** draws the whole hunt, with each run's open and done steps |
| Keep track of what you reviewed | Any run | Status per alert group (**Alerts**), verdict per domain (**Domain profile**), Hunt map *Alert decisions* | Open and reviewed alerts across runs; reruns show what is still open |

A suggested order for reading the results is in [A suggested triage workflow](USER_GUIDE.md#a-suggested-triage-workflow).

## Certificates and attack surface

| Use case | Start with | Where to look | What it surfaces |
| --- | --- | --- | --- |
| Pivot from a certificate | SHA-256, `cn:`, `san:`, `serial:`, `issuer:` | Certificate review steps, then any page | Every domain and IP the certificate covers, and where it was observed |
| Map an organization's attack surface | Organization name (e.g. `DomainTools`) | Certificate preview *Hostnames*, **Hostname Inventory** | Hostnames from certificates, names that never resolved, resolving names without a certificate, new names |
| Investigate selected hostnames | Hostnames ticked in the preview, or *Focus on hostnames* | Hostname focus banner, any page | Passive DNS and certificates of those hostnames only, with gap-fill when the domain was capped |
| Find subdomain takeover risks | Your own domains (the takeover rules also run below *Min Risk Score*) | **CNAME Chains** (*Dead end*, *Takeover-prone*), alerts (*Hosting & DNS Providers*) | Subdomains whose CNAME still points to a deleted S3 bucket, Azure app, Heroku app, GitHub Pages site or similar: anyone could claim the name |
| Audit certificates and CAA policy | Your own domains (CAA breaches also run below *Min Risk Score*; lower it for the other certificate rules) | **Certificates** (*Issuers & policies* for CAA, *Validity & keys*) | CAA breaches, mis-issued wildcards, weak keys, deprecated signatures, over-long validity |
| Find C2 or proxy servers | IPs, or domains with IP certificates | **Certificates** (*JA4X & C2*), alerts | Bare-IP, multi-IP and self-signed certificates |

How the certificate inputs are expanded is in [Certificate inputs](USAGE.md#certificate-inputs).

## Infrastructure and hosting

| Use case | Start with | Where to look | What it surfaces |
| --- | --- | --- | --- |
| Check who is behind IP addresses | IPv4 or IPv6 addresses or CIDR ranges, with *Check IP addresses (VPN, proxy, Tor)*: only VPNDB is queried | **Summary** (one card per IP), **VPNDB**, **Alerts**, **Evidence → Records** (*VPNDB Responses*), **Export & report** (*VPN / proxy / Tor*, *CIDR* tables) | VPN, residential proxy, Tor or hosting, the provider and how sure VPNDB is, Tor role, whether the exit is shared, network, ASN, country, claimed vs. real location; IPv6 is answered *not collected*; for a range, its providers and their shares and the addresses VPNDB reached in it |
| Find domains hosted on anonymizers | Domains (any use case, with a VPNDB key) | **VPNDB** (flow, heatmap, exposure timeline, Iris cross-check, neighbourhood, leads), **Summary** (*VPNDB* column, Analysis Details), **Domain profile** (*VPNDB* card), Alerts (*Hosting & DNS Providers*) | Domains resolving to Tor relays, residential proxy or VPN exits; dedicated exits worth pivoting on; hosting moved onto or rotating across exits; new domains on an exit; domains sharing a non-shared exit |
| Check every address of a range | A CIDR range (e.g. `45.248.77.0/24`), in any use case or *Check IP addresses* | **VPNDB → CIDR ranges** (one cell per address), the range card (per-IP table) | Which providers have exits in the range and their share, measured vs. interpolated exits, residential proxy addresses among VPN ones |
| Tell an anonymizer from reused hosting | Domains | **VPNDB → Exposure timeline** | Whether the IP was an exit while the domain resolved to it, or only became one later (no exit alert then) |
| Pivot from an anonymizer exit | Domains on a dedicated exit | **VPNDB → Iris cross-check** and **Leads** | Strong pivots (dedicated, few Iris domains) vs. shared-exit noise; other domains DNSDB saw on the exit, each with *Analyze* |
| Everything about one IP | Any run with VPNDB | Select the IP in any VPNDB table (VPNDB page, Summary, Domain profile) | VPNDB's verdict and whole answer, weekly history, the domains that used it and when, Iris domain count, its /24 and network, its share of Tor exit traffic; a full verdict on demand for IPs the run only summarized |
| Check the Tor network around the hosting | Domains | **Tor network** (Infrastructure), alerts *Domain on Tor Relay / Exit Node* and *Hosted Among Tor Exits* | Tor relays and exits, the networks and countries carrying most Tor exit traffic, the run's hosting networks among them; domains on a Tor exit or relay while they used it, or next to Tor exits |
| Check whether an IP is a Tor exit | IP addresses with *Check IP addresses* | **Summary** card, IP card (*Verdict*, *Full VPNDB answer*) | Exit now or until when, each relay (nickname, role, flags, first seen), share of Tor exit traffic, the operator's relay family, VPNs whose Tor feature exits there |
| Check whether the hosting was hijacked or leaked | Domains or IPs (any use case, with a BGPDB host) | **BGP → Origin timeline** and **Routing map**, alert *BGP Origin Conflict (Possible Hijack)* | Every network that announced each hosting prefix in the last ~30 days, authorized (RPKI / IRR) or not, and when: a short red bar on an authorized prefix is a hijack or route leak |
| Spot fresh or bulletproof-style hosting from its routing | Domains | **BGP → Overview** and **Networks**, alerts *Newly Announced Prefix*, *Recently Registered Origin Network*, *Unauthorized BGP Origin*, *Low-Visibility or Single-Upstream Route* | Prefixes announced in the last two weeks, origin networks registered in the last year, unregistered or unauthorized announcements, single-homed networks; the networks' age and visibility on one chart |
| Pivot through the routing | Domains | **BGP → Neighbouring prefixes**, **Routing map** (AS paths, upstreams) | Other prefixes the same origin network announces next to the hosting (check them in VPNDB or passive DNS), and the upstream that carries it |
| Judge an anonymizer exit by its routing | Domains with VPNDB exits (VPNDB key and BGPDB host) | **BGP → VPNDB match**, alert *Anonymizer Exit on Unstable Routing* | Exits on newly announced or unauthorized prefixes (unusual for a mainstream VPN), and the origin networks that carry exits with their age and connectivity |
| Check whether Tor-exit networks route the hosting | Domains (VPNDB key for the Tor overview, BGPDB host) | **Tor network** (*Seen as*: hosting, BGP origin, unauthorized origin, upstream, neighbour), alerts *Hosted Among Tor Exits* and *Unauthorized Origin Is a Tor Exit Network* | Every network the routing shows that also carries Tor exit traffic; a Tor-exit network announcing the hosting prefix without authorization |
| Focus a campaign on one network | A run with many domains (BGPDB host or VPNDB key) | Results toolbar **Network** filter, then every page | Only the domains announced by the picked origin network(s) and / or with the picked VPNDB verdict (e.g. VPN, Tor) |
| Find hosting next to VPN servers | Domains | **VPNDB → Neighbourhood**, alert *Hosted Among Anonymizer Exits* | /24 ranges with known exits around the domain's IPs, hosting networks run by one VPN provider |
| Find a threat actor's other domains | One or more malicious domains | **Hunt map → All pivots** (*Strong*, *Shared in run*), *Find in Iris* | Rare IPs, name servers, emails, certificates and trackers, and the other domains in Iris that share them |
| Link domains to one operator | Several domains | **DNS & Hosting** (*Campaign & hosting* tab), *Group by: Campaign Cluster*, DIF table | Shared IPs, name servers, certificates and trackers; look-alike setups through the DIF |
| Detect fast-flux or bulletproof hosting | Domains | **DNS & Hosting**, alerts (*DNS Behavior*, *Hosting*) | Rapid IP rotation across networks, offshore hosting and name servers |
| Map where CNAME redirects lead | Domains | **CNAME Chains** (chain, outcome, chain map), *Chase CNAMEs* | Every alias chain to its final addresses, like CNAME chasing in DNSDB Scout; long chains and loops |
| Spot subdomains pointed at attacker services | Domains, or a suspected compromised organization | **CNAME Chains** (service type), alerts | CNAMEs to dynamic DNS and tunnels (ngrok, Duck DNS, Cloudflare quick tunnels), free hosting with lure names, CNAMEs repointed to a new provider |
| Link domains through CNAME chains | Several domains | Alerts (*CNAME Link Between Analyzed Domains*), **CNAME Chains → Cross-domain links** | Domains whose hostnames alias into each other or through the same dedicated host, e.g. one fronting proxy for a whole campaign |
| Find origin servers behind a CDN | Domains on a CDN | Alerts (*Hosting*), **DNS & Hosting** (*Campaign & hosting* tab) | Non-CDN IPs that may expose the origin |
| Find domains that moved to the same IPs | Domains, with *Pivot on hosting IPs* | **DNS & Hosting** (*Campaign & hosting* tab) (domain hopping) | New domains appearing on an IP shortly after another left |

## Monitoring, re-use and sharing

| Use case | Start with | Where to look | What it surfaces |
| --- | --- | --- | --- |
| Monitor domains over time | The same target list, re-run later with the *Monitor changes* use case and *Save offline copy* | **Runs → Compare & trends**, *Only first detected in this run* | New, resolved and recurring alerts, trends, one domain across runs; each run's API queries, and only new passive DNS records per re-run |
| Re-analyze without API calls | An offline dataset | **Data → Saved datasets** (*Load offline dataset*) | The same views with different thresholds or windows, no quota used |
| Repeat an earlier analysis | A recent run | **Runs → Recent runs** (top menu; *Run again*, *Load offline copy*, *Compare & trends*) | The same targets with the run's use case, analysis window and collection options, or its saved data with no API calls |
| See how your investigations connect | Your saved runs | **Hunt → Hunt map → All investigations** (link types, newest runs, *Only linked runs*; click a run) | Which runs came from which leads, and which separate investigations found the same IP, name server, certificate, JA4X, tracker or email on different domains |
| Find where an indicator was seen before | An IP, domain or hostname, name server, MX host, certificate SHA-256, tracker code or email (defanged is fine) | **Runs → Indicator Sightings** (top menu), *Where else seen* on the Domain profile, or **Shares N** on a run card | Every saved run and offline dataset it was observed in, when, with which domains and how many alerts they had; open the run, load the dataset or analyze the indicator; no API query |
| Re-run a lookup in another tool | Any run | **Evidence → Lookup queries** | CertsQL, DNSDB names and record types (record-type lookups and CNAME chase steps included), Iris domain lists, VPNDB requests, `domaintools` CLI and curl commands |
| Share findings | Any run | *Export Detections, IOCs & Report* under the alerts | Detections and IOC lists (CSV / JSON), STIX 2.1 bundle, HTML / Markdown evidence report |
| Present a whole hunt to another team | A hunt (two or more linked runs) | **Hunt map → Hunt result → Download hunt report (HTML)**, or **Data → Saved datasets → Download hunt report (HTML)** without loading anything | One printable page: the hunt map, every run and every value it followed, the cluster, core indicators with the domains sharing them, every indicator of every domain, every alert with its evidence, open next steps |
| Brief a manager or file a takedown | Any run | **Export & report → Case report** | One printable HTML page (save as PDF): your summary and recommendation, the run at a glance, top alerts with evidence, risk by domain, infrastructure snapshot, indicators |
| Share confirmed indicators | Alerts or domains marked Malicious | *Confirmed indicators* (**Export & report**) | Only what you confirmed, as CSV, a MISP event or a STIX bundle, plus Iris searches for more of the same infrastructure |
| Watch a target list | Any run, *Watch this list* on the Summary (*What's new since the last analysis*) | **Runs → Compare & trends → Watched Lists** (*Run now*), Summary *What's new since the last analysis* | New IPs, name servers, certificates, hostnames and alerts since the list's last run |
| Watch an IrisQL query for new domains | An IrisQL hunt query (an actor's registrant, a lookalike pattern) | **IrisQL**: *Watch this query* on the results, then *Watched queries → Check now* | Only the domains that are new since the last check, ticked and ready to analyze |
| Hand data to another team | Any run | **Export & report** | IOCs, tables (detections, CNAME chains, hostname inventory, ...) and raw records as CSV or NDJSON, zipped with a manifest |
| Look up a hostname's certificates elsewhere | Domains | **Hostname Inventory**, *Certificates by hostname* | Every certificate hash (SHA-256 / SHA-1) that names or covers each hostname |
