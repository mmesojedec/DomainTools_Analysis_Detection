# User Guide: Reading the Results

What the app shows and how to interpret it: alerts and their severity and confidence, every detection rule, the
MITRE ATT&CK mapping, Unified Risk scores, DIF fingerprints, infrastructure clusters, and run history. For setup,
credentials and running an analysis, see [Installation](INSTALLATION.md) and [Usage](USAGE.md).

Most of these explanations are also available inside the app: **Detection reasons** (next to the alert list) and
**Decode DIF fingerprints** (under the DIF table) open the same reference tables.

## Contents

- [How a run works](#how-a-run-works)
- [Analysis window](#analysis-window)
- [Data sources](#data-sources)
- [KPI banner](#kpi-banner)
- [Unified Risk and risk vectors](#unified-risk-and-risk-vectors)
- [DIF: Domain Infrastructure Fingerprint](#dif-domain-infrastructure-fingerprint)
- [Alerts](#alerts)
- [Severity, confidence and category](#severity-confidence-and-category)
- [Detection catalogue](#detection-catalogue)
- [MITRE ATT&CK mapping](#mitre-attck-mapping)
- [Infrastructure clusters and domain hopping](#infrastructure-clusters-and-domain-hopping)
- [CNAME chains](#cname-chains)
- [Detection thresholds](#detection-thresholds)
- [Run history, alert lifecycle and trends](#run-history-alert-lifecycle-and-trends)
- [JA4X: how certificates were generated](#ja4x-how-certificates-were-generated)
- [Suppressions and exports](#suppressions-and-exports)
- [Hunting: triage status, leads and the hunt map](#hunting-triage-status-leads-and-the-hunt-map)
- [Pages](#pages)
- [A suggested triage workflow](#a-suggested-triage-workflow)
- [Limitations](#limitations)

## How a run works

For diagrams of every collection step, its order and conditions, see [Workflows](WORKFLOWS.md); for the
investigations the tool supports, see [Use Cases](USE_CASES.md).

1. **Collect.** Certificate inputs (fingerprints, `cn:`, `san:`, ...) are first resolved to the domains and IPs
   their certificates cover, and you choose which to analyze (see [Certificate inputs](USAGE.md#certificate-inputs)).
   For each target the app then queries Domain History and Iris Investigate (DomainTools SDK; Iris also returns
   the DomainTools risk score and its components, so no separate Risk Evidence query is made), passive DNS (DNSDB Scout), and the Certificate API: Certificate Search for certificates naming the
   domain or any subdomain, Certificate Events for the hostname / IP over the last 365 days (the API default is 30),
   and SHA-256 / CT log events per certificate. With a VPNDB key, the hosting IPs are checked in
   [VPNDB](USAGE.md#vpn-residential-proxy-and-tor-vpndb) for VPN, residential proxy and Tor exits (with the weekly
   history of each exit, the ranges and networks around the hosting, and DNSDB's other domains on dedicated exits),
   and CIDR targets are looked up there as ranges. With a BGPDB host, the hosting IPs' BGP routing comes from
   BGPDB: announced prefix and origin network, RPKI / IRR, RIR, the AS paths, the origin and upstream networks and the
   prefixes announced around them (see [BGP routing rules](#bgp-routing-rules)). Where a passive DNS lookup stopped at its limit, record-type
   lookups fill in TXT, CAA and (when none came back) CNAME records, and the CNAME targets that point outside
   the collected data are [chased](#cname-chains) to their final addresses. Every lookup's outcome is recorded in
   the [Data sources](#data-sources) page, with the API queries it made. Independent sources run at the same
   time (see [Workflows](WORKFLOWS.md#collection-order)). Sources missing from the DomainTools account are
   skipped, and so are services without an API key (*Skipped: no DNSDB key*): they make no query until a key is
   entered. When the targets came from a CertsQL search, the certificates that matched are added to the run (Source
   *CertsQL search*), so the certificate that found a domain is analyzed with it.
2. **Window.** Records are limited to the [analysis window](#analysis-window).
3. **Score gate.** Domains whose known DomainTools risk score is below **Min Risk Score** get only the rules whose
   evidence stands on its own: the lookalike rules, subdomain takeover (*Dangling CNAME*, *Unverified CNAME to
   Takeover-Prone Service*), the CAA breaches, *Known C2 Certificate Fingerprint (JA4X)*, *Phishing Kit Staging*,
   *Mail-Capable Lookalike* and *Lure Subdomain*. A new lookalike or your own domain often has a low score. An info
   box lists these domains. Domains Iris Investigate has no score for are still fully evaluated, with a warning. IP
   targets are always evaluated.
4. **Detect.** Every [detection rule](#detection-catalogue) runs per domain or IP on raw UTC timestamps. Then the
   cross-domain checks run: [infrastructure clusters and domain hopping](#infrastructure-clusters-and-domain-hopping),
   CNAME targets shared by several analyzed domains, and anonymizer exits several analyzed domains use (see
   [VPNDB anonymizer rules](#vpndb-anonymizer-rules)). A domain among the 10,000 most popular in Iris
   Investigate (its *popularity rank*), or one on the DomainTools zerolist (known good), is far more likely
   legitimate: its Medium and Medium-High confidence alerts drop one step, and each alert's logic says so.
   High-confidence alerts are kept as they are. Your [allowlist](#allowlist) and your
   [verdicts](#your-verdicts-move-the-confidence) can move the confidence too.
5. **Merge.** Rules that run once per certificate or record can fire several times for one domain. These repeats
   are merged into **one alert per (domain, rule)**, keeping the worst severity's description, the best confidence
   and all the evidence. The *Occurrences* column shows how many were merged.
6. **Score.** [Unified Risk](#unified-risk-and-risk-vectors) and the [DIF](#dif-domain-infrastructure-fingerprint)
   are computed per domain from the alerts and telemetry.
7. **Save.** Live runs are saved to `dt_runs/` for [run history](#run-history-alert-lifecycle-and-trends);
   [suppressions](#suppressions-and-exports) are applied before anything is displayed.

## Analysis window

The window (*Show activity from*: the sidebar before a run, the results toolbar after; default *Last 30 days*) keeps only records **active** in it:

| Data | Kept when |
| --- | --- |
| Passive DNS | Last seen inside the window |
| Domain History changes | Changed inside the window |
| Certificates | Valid at some point during the window |
| Certificate / CT events | Observed inside the window |
| Iris data (current hosting, registration) and risk scores | Always: they describe the current state |

- Dormancy gaps and domain-hopping history are computed on **full history** first. Detections such as
  *Parked-to-Weaponized* still see the quiet period before the window.
- A banner shows how many records each source kept, and how many detections exist only outside the window.
  Expand **Detections outside the window** to review them, or switch to *All time*.

## Data sources

The **Data sources** page shows how every lookup of the run went. At the top, the run in numbers: targets, lookups,
the share answered (all but errors), records returned, API queries, lookups from the lookup cache and, after an
Analyze in this session, the collection time with its slowest steps. A bar per source shows its lookups by status.
The tabs below:

- **By source**: outcomes, records (total, average and largest per lookup), queries and cache hits per source, the
  ones with errors or partial lookups first. A source near its limit on many targets may need a higher limit.
- **By target**: the same per target, with the sources that failed or stopped at a limit for it.
- **Needs attention**: every failed or partial lookup with what happened.
- **API queries**: queries per service and DomainTools product, next to what each has left (known from the Account
  page, *Check DNSDB quota* and VPNDB's last answer; no query is made for it).
- **All lookups**: every lookup, filtered by status, source and target.

Each lookup has one of these statuses:

| Status | Meaning |
| --- | --- |
| OK | Data returned |
| Partial | Data returned but truncated by a result limit (DNSDB: your limit) |
| No data | The source had nothing for this target |
| Error | Authentication failure, rate limit, timeout or other error; the reason is shown |

Missing data lowers what the detections can see, so check this page when a domain has fewer alerts than expected.
Each lookup also shows **Queries**: the API queries it made (pages and retries included; 0 when the lookup cache
answered); the Runs page (*Compare & trends*) keeps each run's total. When a run returned no data at all, a status panel with every lookup
is shown instead of the pages. A source whose DomainTools product the account does not have is listed as skipped.

## KPI banner

| KPI | Meaning |
| --- | --- |
| Max Digital Risk | Highest [Unified Risk](#unified-risk-and-risk-vectors) across the analyzed domains |
| High-Risk Domains | Domains with Unified Risk at or above **High-Risk Score Cutoff** (default 70) |
| Unique Infrastructure Profiles | Number of distinct DIF fingerprints. Fewer profiles than domains suggests shared infrastructure. |
| Primary Threat Driver | The risk vector with the highest average across domains |

## Unified Risk and risk vectors

Each domain gets six risk vectors (0–100), plus **BGP Routing** when BGPDB answered for its hosting, shown in the
**Digital Risk Vector Profile** radar chart. All but the DomainTools score are built from the domain's alerts, and two
of them also from raw telemetry. "Max severity" is the highest value of
[severity weight](#severity) × confidence among the domain's alerts that match the listed techniques or names. The
confidence factor is 1.0 for High, 0.8 for Medium and 0.5 for Low, so a Low-confidence High alert counts as 35, not 70.
Informational alerts (*Short-Lived Certificate*) are left out: short certificate lifetimes never raise a risk score.

| Vector | Calculation (capped at 100) |
| --- | --- |
| Domain Risk Score | The DomainTools overall risk score (0 if unknown) |
| DNS Volatility | Max severity of T1568 / flux / rotation / parked / sinkhole / churn alerts + 2 per distinct passive DNS IP above 10 (max +20) |
| Certificate Trust | Max severity of T1588.004 / T1573 / T1587.003 / T1608.003 / certificate / weak-key alerts + 40 if any certificate is self-signed + 40 if any key is weak |
| Email/Phish Posture | Max severity of T1566 / T1583.002 / T1585.002 / phishing / SPF / mail / lure alerts. TXT, SPF and MX record counts add nothing: SaaS verification records grow with legitimate use |
| App & C2 Footprint | Max severity of T1071 / T1008 / T1048 / T1090.003 / T1572 / T1583.003 / proxy or anonymizer exit / bare-IP / payload / JA4X alerts |
| Infra Sprawl | Max severity of T1584.001 / sprawl / nested / wildcard / cohort / wave alerts. SAN counts add nothing: the *Mega-SAN* rule covers them |
| BGP Routing | Max severity of the [BGP routing alerts](#bgp-routing-rules) (origin conflict, unauthorized origin, new prefix, young network, thin route, anonymizer exit on unstable routing). Only for domains whose hosting IPs BGPDB answered for (for the others it is empty). It joins the Unified Risk average only when it is above the other vectors' mean, so clean routing never lowers the score |

**Unified Risk** = `min(100, max(base, 0.4 × base + 1.5 × average of the behavioral vectors))`, where *base*
is the DomainTools risk score and the behavioral vectors are the five above, plus BGP Routing when it is above
their mean. It never falls below the DomainTools score, and rises when the domain's own
telemetry and alerts are worse than the score suggests.

## DIF: Domain Infrastructure Fingerprint

A DIF summarizes how a domain is set up, in four segments: `Hosting_TLS_Identity&Apps_ConfigHash`, for example
`F-CF_DVLE-R2048_EM_3fa91c`. The **Infrastructure Fingerprints (DIF)** table shows each domain's fingerprint and
a plain-language **DIF Breakdown**. **Decode DIF fingerprints** opens a window with every fingerprint in the run
decoded segment by segment, a **Same DIF As** column, and the code reference below.

| Segment | Format | Example | Read as |
| --- | --- | --- | --- |
| 1 Hosting | `<flux>-<server>` | `F-CF` | Dynamic / fast-flux (3+ IPs) on Cloudflare |
| 2 TLS | `<validation><issuer>-<key>` or `NOCERT` | `DVLE-R2048` | Domain Validated, Let's Encrypt, RSA 2048-bit |
| 3 Identity & Apps | `<code>` | `EM` | SPF email routing |
| 4 Config Hash | 6 hex characters | `3fa91c` | Hash of IP count, server type, the primary certificate's issuer, validation, key and names, and TXT records |

### DIF codes

| Segment | Code | Meaning | Derived from |
| --- | --- | --- | --- |
| 1 Hosting | `P-..` | Parked / no resolved IPs | Distinct A/AAAA IPs in passive DNS |
| 1 Hosting | `S-..` | Static host (1-2 IPs) | Distinct A/AAAA IPs in passive DNS |
| 1 Hosting | `F-..` | Dynamic / fast-flux (3+ IPs) | Distinct A/AAAA IPs in passive DNS |
| 1 Hosting | `..-CF` | Cloudflare | Iris web server type |
| 1 Hosting | `..-AW` | Amazon | Iris web server type |
| 1 Hosting | `..-NX` | Nginx | Iris web server type |
| 1 Hosting | `..-UN` | Unidentified server / VPS | Iris web server type |
| 2 TLS | `DV....` | Domain Validated | Validation level of the primary certificate |
| 2 TLS | `OV....` | Organization Validated | Validation level of the primary certificate |
| 2 TLS | `EV....` | Extended Validation | Validation level of the primary certificate |
| 2 TLS | `NA....` | Validation not reported | Validation level of the primary certificate |
| 2 TLS | `UN....` | Unknown validation | Validation level of the primary certificate |
| 2 TLS | `..LE..` | Let's Encrypt | Issuer of the primary certificate |
| 2 TLS | `..ZS..` | ZeroSSL | Issuer of the primary certificate |
| 2 TLS | `..SS..` | Self-signed | Issuer of the primary certificate |
| 2 TLS | `..UN..` | Other / unknown CA | Issuer of the primary certificate |
| 2 TLS | `..-R2048` | Key type (R = RSA, E = EC) and size (U = unknown) | Certificate public key |
| 2 TLS | `NOCERT` | No certificate observed | Certificate sources |
| 3 Identity & Apps | `EM` | SPF email routing (checked first) | TXT records in passive DNS |
| 3 Identity & Apps | `GW` | Google Workspace (Google verification, no SPF) | TXT records in passive DNS |
| 3 Identity & Apps | `MS` | Microsoft 365 (MS= verification, no SPF or Google) | TXT records in passive DNS |
| 3 Identity & Apps | `NO` | No enterprise services (disposable / staging indicator) | TXT records in passive DNS |
| 4 Config Hash | `e.g. 3fa91c` | Same hash on different domains = identical backend setup | IP count, server type, primary certificate issuer, validation, key and names, TXT records |

### Reading a DIF

- **Identical DIF on unrelated domains:** same hosting pattern, same certificate profile and same mail / SaaS
  setup. A strong hint of one operator or one deployment kit.
- **Identical configuration hash:** the backend inputs are identical (same IP count, server type, primary
  certificate and TXT records), even if the readable segments look common.
- **`NO` identity code** (no SPF, Google or Microsoft records): typical of disposable or staging infrastructure.
- **Stable across renewals:** the DIF leaves out certificate validity and the certificate hash, so renewing a
  certificate, or switching to shorter lifetimes such as Let's Encrypt's 6-day profile, does not change it. The
  **DIF Breakdown** text still shows the validity. Fingerprints saved by earlier versions include the validity days
  (e.g. `DVLE90-R2048`); the decoder still reads them, and the first run after upgrading shows a one-time DIF change.
- **Automated DV certificates** (`DVLE`, `DVZS`) are normal on their own; combined with fast-flux hosting (`F-..`)
  and no enterprise services (`NO`) they fit throwaway infrastructure.
- The TLS segment describes the domain's **primary** (first listed) certificate only. The identity code checks SPF
  first, then Google, then Microsoft 365 verification records, so a domain with SPF and Google records shows `EM`.

## Alerts

The **Alerts** page lists every detection.

### Alert overview

- **Alert Heatmap:** one row per domain and one column per [category](#category); the number is the alert count
  and the color is the worst severity. Click or box-select cells to filter the alert list; double-click the
  background to clear.
- **MITRE ATT&CK tab:** a treemap of Tactic → Technique → Rule, and a table of alerts and domains per technique.

### Filters and controls

| Control | Effect |
| --- | --- |
| Confidence / Severity | In the results toolbar (*Alerts*): show only these levels, here and on Summary, Domain profile, the Hunt map and exports |
| Status | Show only alerts with these [triage statuses](#triage-status) |
| Threat type | Show only these rules (empty: every threat type) |
| Layout | *Grouped* (default) or *Table* (one flat, sortable row per alert) |
| Group by | How alerts are grouped (below) |
| Only first detected in this run | Hide detections already seen in an earlier saved run that covered these domains. Disabled until such a run exists. |
| Detection reasons | Opens the reference: severity and confidence levels, alert columns, and every rule, with a **Your Verdicts** column (how many of each rule's alerts you marked Malicious or Benign) |
| Export detections, IOCs and reports | Opens the **Export & report** page (see [Suppressions and exports](#suppressions-and-exports)) |

The filters also apply to the alert count and the detection exports. The IOC list covers the selected domains and the analysis window.

### Group by

| Mode | One group per | Use it to |
| --- | --- | --- |
| Finding | Detection rule, across all domains | See how widespread each behavior is |
| Campaign Cluster | [Infrastructure cluster](#infrastructure-clusters-and-domain-hopping); unclustered domains get their own group | Review a campaign as one incident |
| Domain | Domain | Review everything about one domain |
| ATT&CK Technique | Primary technique | Report by adversary behavior |

Groups are sorted by worst severity, then number of domains and alerts. The header shows the worst severity, the
group name, the domain and alert counts, and the date span of the evidence.

Inside a group:

- **Alert table:** Domain, Risk, Risk Evidence, Threat Type, MITRE ATT&CK, Severity, Confidence, Category,
  Occurrences, First Detected, Runs Seen, Threat Logic.
- **Related events:** every piece of evidence behind the group's alerts in one time-ordered table: time (in your
  display timezone), domain, rule, field, value, and the pivotable **artifact** (certificate hash, IP, ...).
  Undated evidence is listed last.
- **Show raw IOC text:** the original evidence text of each alert.
- **Suppress N alert(s):** adds one [suppression](#suppressions-and-exports) per (domain, rule) in the group.

### Alert columns

| Column | Meaning |
| --- | --- |
| Domain | Domain or IP the detection is about |
| Risk / Risk Evidence | DomainTools risk score and its evidence tags (e.g. Phishing, Malware), from Iris Investigate |
| Threat Type | The rule that fired; see the [catalogue](#detection-catalogue) |
| MITRE ATT&CK | Technique the behavior maps to; see the [mapping](#mitre-attck-mapping) |
| Severity | Impact if the finding is true |
| Confidence | How likely the finding is a true positive |
| Category | Kind of evidence the rule looks at |
| Occurrences | Matching certificates or records merged into this one alert |
| First Detected | First saved run (any target list) in which this detection appeared for this domain |
| Runs Seen | Number of saved runs, including this one, with this detection |
| Threat Logic | One-line explanation with the measured values (e.g. "Cycled 4 distinct SSL certs in 30 days") |

## Severity, confidence and category

Severity and confidence are independent: severity says **how bad** a finding would be, confidence says **how sure**
the rule is. A *Critical / Low* alert deserves a quick check; a *Medium / High* alert is reliable context.

### Severity

| Severity | Weight | Meaning |
| --- | --- | --- |
| Critical | 90 | Infrastructure that is almost certainly malicious or actively weaponized (e.g. CAA breach, rogue CA, parked domain suddenly armed). Investigate or block first. |
| High | 70 | Strong attacker tradecraft or a high-risk configuration (fast-flux, self-signed or weak certificates, permissive SPF, shared trackers). Prioritize after Critical. |
| Medium-High | 60 | Suspicious setup common in abuse but with benign explanations (offshore DNS, DGA-like names, CN mismatch, shared clusters). Review with context. |
| Medium | 40 | Notable change or weak-to-moderate indicator (new registration, redirects, sinkholes, CAA mismatch). Use to corroborate other findings. |
| Low | 20 | Context only: hygiene or informational observations (parking, wildcard certificate, malformed SPF). |

Severity is fixed per rule, except where the [catalogue](#detection-catalogue) lists two levels (for example
*Bare-IP Certificate* is Critical, or Medium-High for a publicly trusted short-lived IP certificate). The weights feed
the [risk vectors](#unified-risk-and-risk-vectors), except for informational rules such as *Short-Lived Certificate*,
which are shown as alerts but never scored.

### Confidence

| Confidence | Meaning |
| --- | --- |
| High | Matches a specific artifact with few false positives (exact certificate, tracker or CAA facts). Treat as true unless an allow-list explains it. |
| Medium | A strong behavioral signal that also occurs in legitimate infrastructure (CDNs, hosting migrations, registrar defaults). Confirm with a second finding or the evidence. |
| Low | A weak or heuristic signal (entropy, volume, naming). Not a verdict on its own; use it to rank or pivot. |

Each rule has a default confidence. Some adjust it from the evidence:

- *Rapid IP Rotation (Fast-Flux)* drops to **Low** when every IP belongs to a CDN (CDN rotation is normal).
- *Shared Infrastructure Cluster* is **High** for a strong link (shared certificate, key or tracker), otherwise **Medium**.
- *Domain Hopping on Shared IP* is **High** with two or more hops, otherwise **Medium**.
- *Bare-IP Certificate* is **Low** for a publicly trusted, short-lived IP certificate, which public CAs such as
  Let's Encrypt now issue.
- *Dangling CNAME* is **High** (and Critical) when the dead-end target is on a takeover-prone service, otherwise
  **Medium** (and High).
- *CNAME to Free Hosting Platform* is **Medium** (and High) when the hostname also carries a phishing word, brand or
  embedded domain, otherwise **Low**.
- *CNAME Link Between Analyzed Domains* is **High** when a name of one analyzed domain aliases into another, and
  drops to **Low** when every shared name is a known service (hosting, takeover-prone, tunnel), where unrelated
  customers share names.
- A popular domain (Iris popularity rank in the top 10,000) or a domain on the DomainTools zerolist drops its Medium
  and Medium-High alerts one step.

#### Your verdicts move the confidence

The app learns from your triage. Once a rule has at least 5 Malicious or Benign decisions (alert statuses on the
Alerts page), it adjusts that rule's confidence in every run:

- 80% or more Benign: the confidence drops one step (High to Medium, Medium to Low).
- 80% or more Malicious: the confidence rises to High.

The alert's *Threat Logic* says so, with the counts. **Detection reasons** shows them in the **Your Verdicts** column.

A domain you mark **Malicious** (domain verdict on Alerts or the Domain profile) also raises *Linked to
Confirmed-Malicious Domain* (High) on the other domains of its **Strong** [cluster](#clusters).

#### Allowlist

The **Infrastructure allowlist** (*Settings → Brands & allowlist*) lists your own or otherwise known-good
infrastructure, one entry per line (comma-separated works too; lines starting with `#` are ignored):

| Entry | Matches |
| --- | --- |
| `203.0.113.7`, `10.20.0.0/16` | An IP address or range |
| `AS13335` | An ASN (its hosting IPs, when Iris or VPNDB knows the ASN) |
| `ns:corp-dns.example` | A name server or its provider domain (a bare host name means the same) |
| `org:Example Corp` | A certificate subject organization (contains, any case) |
| `tracker:G-ABC123` | A web tracker ID |
| `registrar:MarkMonitor` | A registrar (contains, any case) |

Allowlisted values never link analyzed domains into [clusters](#clusters). Alerts whose evidence names one are kept,
but drop to **Low** confidence, and the alert says why. Saving re-runs the detections, with no new lookups. The list
is saved in `dt_settings.json`.

### Category

| Category | Evidence |
| --- | --- |
| DNS Behavior | Passive DNS and Domain History changes: resolution, flux, TXT, query volume, subdomains, CNAME retargeting and long chains |
| Hosting & DNS Providers | Name servers, hosting providers, CDN origin exposure, CNAME targets (dangling, takeover-prone, dynamic DNS / tunnel, free hosting), VPN / residential proxy / Tor exits (VPNDB) |
| Email | MX, SPF and mail-provider configuration |
| Certificates | Certificate properties, issuance, CAA and CT logs |
| Registration & Lifecycle | Registration age, parking and reactivation |
| Web & Content | Website content and redirects |
| Correlation | Links between analyzed domains (clusters, hopping, shared trackers, shared CNAME targets) |
| Domain Name | The name itself (entropy) |
| Lookalike / Brand | Resemblance to a protected brand |
| BGP Routing | How the hosting IPs are announced on the internet (BGPDB): origin conflicts, unauthorized origins, new prefixes, young networks, thin routes |

## Detection catalogue

Every rule, grouped by category. Besides the per-source rules, two families read what the run already has, with
no extra lookups: **lifecycle** rules (re-registered domains, throwaway registrant mail, name server churn, a
registrar transfer followed by new name servers; `core/threat_detection/lifecycle_rules.py`) and **compound and
cross-domain** rules (independent signals that together describe one attack stage, such as *Phishing Kit Staging*
or *Subdomain Takeover in Progress*, plus bulk-registration cohorts and campaign waves across the analyzed domains;
`core/threat_detection/compound_rules.py`). Threshold names (e.g. **Min Risk Score**, **DGA Entropy Score**) are the sliders
under *Settings → Detection thresholds*; see [Detection thresholds](#detection-thresholds) for
their defaults. **Detection reasons** in the app shows the same table with how often each rule fired in the
current run.

#### BGP Routing

| Detection | Severity | Confidence | MITRE ATT&CK | Fires when | Why it matters |
| --- | --- | --- | --- | --- | --- |
| BGP Origin Conflict (Possible Hijack) | High (unauthorized origin seen in the last 7 days) / Medium / Low (BYOIP or DDoS-protection network) | Medium | T1557 (Adversary-in-the-Middle) | A prefix covering one of the domain's hosting IPs has its authorized origin (RPKI or IRR valid) and also another origin that RPKI or IRR names as invalid (BGPDB, last ~30 days). | Two networks claiming the same addresses, one of them without authorization, is how BGP hijacks and route leaks look: traffic to the domain may have gone to the wrong network while it lasted. |
| Unauthorized BGP Origin | Medium-High / Medium (BYOIP or DDoS-protection network) / Low (... with an authorized more-specific inside) | Medium | T1583 (Acquire Infrastructure) | The network that usually announces the prefix of a hosting IP is RPKI- or IRR-invalid for it, and no authorized origin is seen (BGPDB). A cloud or DDoS-protection network that announces customers' space (Cloudflare, AWS, Google, Akamai, Fastly, Imperva, ...) counts lower. | Hosting on space the registries do not tie to its announcer: squatted, informally leased or hijacked prefixes are favoured by bulletproof hosters. |
| Newly Announced Prefix | Medium | Medium | T1583 (Acquire Infrastructure) | The prefix of a hosting IP was first announced by its origin in the last 14 days, and after the first days of BGPDB's ~30-day window (an older announcement can't be told apart there). | Fresh address space comes and goes with short-lived campaign infrastructure. |
| Recently Registered Origin Network | Medium-High (under 90 days) / Medium (under a year) | Medium | T1583 (Acquire Infrastructure) | The origin AS of a hosting IP was registered at its RIR within the last year (BGPDB's RIR record). | Young networks host a large share of malicious infrastructure; established hosters rarely are. |
| Low-Visibility or Single-Upstream Route | Low | Low | T1583 (Acquire Infrastructure) | The prefix of a hosting IP is seen by fewer than 10 route collectors, or its origin network has a single upstream and no downstream networks (BGPDB); not when that upstream is the same company's network. | Context: small and bulletproof hosters often look like this, so do many legitimate small networks. |
| Anonymizer Exit on Unstable Routing | High | High | T1090 (Proxy) | A hosting IP VPNDB names as a VPN, proxy or Tor exit sits on a prefix with an origin conflict, an unauthorized origin or a new announcement (BGPDB). | An anonymizer on unstable or unregistered space is rarely a mainstream service: likely the actor's own or a fly-by-night provider. |
| Unauthorized Origin Is a Tor Exit Network | Medium-High | Medium | T1557 (Adversary-in-the-Middle) | A network that announced a hosting prefix without authorization (origin conflict or unauthorized origin, BGPDB) also carries Tor exit traffic: at least 0.5 % of it or 10+ exit addresses (VPNDB Tor overview). | The hijacking or squatting network welcomes Tor exits: privacy or bulletproof-style hosting, where traffic drawn by the announcement is hard to trace. |
| Hosting Moved to a New Network | Medium (none of the earlier networks left) / Low (a network added) | Medium | T1583 (Acquire Infrastructure) | The usual origin network of the domain's hosting IPs (BGPDB) is not one the domain's latest earlier saved run recorded (any target list). | Re-hosting after a takedown or a block, or a campaign moving to fresh infrastructure; routine CDN or provider changes look the same, so check the new network. |

#### Certificates

| Detection | Severity | Confidence | MITRE ATT&CK | Fires when | Why it matters |
| --- | --- | --- | --- | --- | --- |
| ACME Certificate Sprawl | Low | Low | T1588.004 (Obtain Digital Certificates) | More than 10 distinct _acme-challenge hostnames in passive DNS (renewals of one name count once). | Mass automated certificate issuance supports fast setup of many hostnames. |
| Rapid Weaponization (Cert-to-DNS Gap) | High | Medium | T1588.004 (Obtain Digital Certificates) | Certificate issued within Cert-to-DNS Gap (Hours) of the first DNS record. | Certificate and DNS set up together point to scripted, disposable deployment. |
| Self-Signed Certificate Detected | Critical to Low (graded: High, Medium) | High | T1573.002 (Encrypted Channel) | Certificate subject equals its issuer. Graded like the Certificates page: a C2 framework's default certificate or one served on the domain now is Critical, an expired one a step lower. | Common on C2 servers and malware panels; untrusted by browsers. |
| Known C2 Certificate Fingerprint (JA4X) | High | Medium | T1588.002 (Obtain Capabilities: Tool) | The certificate's JA4X is on the built-in list of C2 framework and malware fingerprints (Cobalt Strike, Sliver / Havoc, Metasploit, Qakbot, ...). | The certificate was generated the way that tool generates its own. Other certificates built with the same fields match too, so confirm with the certificate (self-signed, default names, the IP's ports). |
| Dual-Use Tool Certificate Fingerprint (JA4X) | Medium | Low | T1572 (Protocol Tunneling) | The certificate's JA4X is on the built-in list of dual-use tools (e.g. SoftEther VPN). | Legitimate software that attackers also run for tunnels and remote access; unexpected on a phishing or brand domain. |
| Network Device Default Certificate (JA4X) | Medium | Low | T1584.008 (Compromise Infrastructure: Network Devices) | The certificate's JA4X is on the built-in list of network devices' default certificates (e.g. Cisco RV32x routers). | The host serves a router's own management certificate; small-office routers are often compromised and used as relays. |
| Code-Generated Certificate Layout (JA4X) | Medium | Low | T1587.003 (Develop Capabilities: Digital Certificates) | The certificate's JA4X has an empty issuer part (no issuer attributes) and is not on a built-in list. | No CA issues a certificate without issuer attributes; C2 frameworks that generate their own do (Sliver, Havoc). Search CertsQL for the JA4X to find the set. |
| Short-Lived Certificate | Low (informational, not scored) | High | T1588.004 (Obtain Digital Certificates) | Certificate valid at most Short-Lived Certificate Max Validity (Days), e.g. Let's Encrypt's 6-day profile. | Context only: short lifetimes reflect good automation, so this is excluded from risk scores and DIF. |
| Mega-SAN Cluster (Bulk Infrastructure) | High | Medium | T1583.001 (Acquire Infrastructure) | One certificate covers at least Mega-SAN Min Root Domains registrable domains. Low confidence on CDN / shared-hosting certificates (Cloudflare, cPanel, ...). | Bundling unrelated domains in one certificate links bulk-registered infrastructure. |
| Multi-IP Certificate (Shared C2 / Proxy Cluster) | High | Medium | T1008 (Fallback Channels) | Certificate for an IP target also lists other raw IPs. | Points to a cluster of C2 or proxy nodes sharing one certificate. |
| Bare-IP Certificate (C2 / Proxy Node) | Critical / Medium-High (public short-lived IP certificate) | High | T1008 (Fallback Channels) | Certificate common name or SAN contains a raw IP address. A publicly trusted, short-lived IP certificate (e.g. Let's Encrypt) is Medium-High with Low confidence. | Legitimate sites rarely certify bare IPs; C2 frameworks often do. |
| SSL Common Name (CN) Mismatch | Medium-High | Low | T1071.001 (Web Protocols / Shared C2) | Served certificate is issued to a different name. | Shared or reused certificates can expose hidden relationships or shared C2. |
| Pre-Certificate Staging (CT Log Only) | Low | Low | T1588.004 (Obtain Digital Certificates) | Certificate seen only as a CT log precertificate. | Shows infrastructure being prepared before it goes live. |
| CT Log Evasion / Missing SCTs | Medium-High | Medium | T1588.004 (Obtain Capabilities: Digital Certificates) | Final (not pre-) certificate from a public CA without embedded Signed Certificate Timestamps. | Missing SCTs suggest an interception proxy or attempts to avoid CT monitoring. |
| Rogue Certificate Authority | Critical | High | T1553.004 (Subvert Trust Controls: Install Root Certificate) | Endpoint serves a certificate with CA signing capability (CA=True). | A host that can mint certificates enables traffic interception. |
| Non-Compliant Validity Window | Medium | High | T1588.004 (Obtain Digital Certificates) | Publicly trusted certificate valid longer than the CA/B Forum limit on its issue date: 398 days from 2020-09-01, 200 from 2026-03-15, 100 from 2027-03-15, 47 from 2029-03-15. | Browsers reject such certificates; typical of private or misconfigured CAs. |
| Deprecated Signature Algorithm | High (Medium before 2017) | High | T1588 (Obtain Capabilities) | Certificate signed with MD5 or SHA-1. Issued before 2017 (when public CAs stopped SHA-1) it is Medium with Low confidence: history, not a new forgery. | Weak signatures can be forged and indicate outdated or attacker-made certificates. |
| Non-Public / Private CA Certificate | Medium | Medium | T1588.004 (Obtain Digital Certificates) | Issuer shows no sign of public trust (no SCTs, no CA/B policy, unknown CA). | Typical of internal CAs, interception proxies, or attacker-run infrastructure. |
| CAA Mismatch (CA Trust Unverified) | Medium | Low | T1588.004 (Obtain Digital Certificates) | Issuer not allowed by the domain's CAA policy, but public trust of the CA is unknown. | Possible CAA breach that needs confirmation. |
| Wildcard Issuance Forbidden by CAA Policy | Critical | High | T1588.004 (Obtain Digital Certificates) | Publicly trusted wildcard certificate although CAA forbids wildcards. | Issuance against the owner's policy points to mis-issuance or account compromise. |
| Unauthorized CA Certificate Issuance (CAA Breach) | Critical | High | T1588.004 (Obtain Digital Certificates) | Publicly trusted certificate from a CA the CAA policy does not authorize. | Strong sign of mis-issuance or a hijacked domain. |
| Suspicious CAA Stripping / Evasion | High | Low | T1562.001 (Disable or Modify Tools) | Unauthorized certificate issued within 90 days after CAA records disappeared. | Removing CAA before issuing is a way to bypass the owner's CA restrictions. |
| Wildcard Infrastructure Sprawl | Medium | Medium | T1584.001 (Compromise Infrastructure: Domains) | Wildcard certificate bundling 5 or more names. | Supports rotating subdomains for phishing or C2 without new certificates. |
| Wildcard Certificate Observed | Low | High | T1588.004 (Obtain Digital Certificates) | Wildcard certificate with fewer than 5 names. | Common for legitimate hosting; new hostnames under it never appear in CT logs. |
| Suspicious Domain Validation (DV) | Medium | Low | T1588.004 (Obtain Digital Certificates) | DV certificate on a domain with risk score above Suspicious DV Min Risk Score. | DV certificates are free and instant, so they are the default for abusive sites. |
| Weak Cryptographic Key Material | High | High | T1588 (Obtain Capabilities) | RSA key below 2048 bits or EC key below 224 bits. | Weak keys are breakable and rare on maintained infrastructure. |
| Certificate Churn (Ephemeral SSL) | High | Medium | T1588.004 (Obtain Digital Certificates) | At least Cert Churn Min Early Replacements within Cert Churn Window (Days): certificates reissued for the same names while the previous one still had over half its validity left. Scheduled renewals of short-lived certificates do not count. | Replacing valid certificates early accompanies disposable or evasive infrastructure. |
| Certificate Staged Before DNS | Medium | Medium | T1608.003 (Stage Capabilities: Install Digital Certificate) | A certificate issued 1 to 30 days before a hostname it names first resolved (each hostname apart). | Infrastructure prepared ahead of going live is typical of phishing and C2 staging. |
| Backdated Certificate | Medium | Medium | T1588.004 (Obtain Digital Certificates) | Not Before more than 48 hours earlier than the certificate's first embedded CT log timestamp (SCT). | Backdating hides when a certificate was really made; CAs backdate by an hour at most. |
| Unusual Certificate Fields | Medium | Medium | T1587.003 (Develop Capabilities: Digital Certificates) | CA-issued certificate with a serial of 2 bytes or less, extended key usage without server authentication, or a default subject (Internet Widgits, Some-State, ...). | Fields that tools set and public CAs never do point to a hand-made or tool-made certificate. |

#### Correlation

| Detection | Severity | Confidence | MITRE ATT&CK | Fires when | Why it matters |
| --- | --- | --- | --- | --- | --- |
| CNAME Link Between Analyzed Domains | Medium-High | Medium | T1583.001 (Acquire Infrastructure: Domains) | CNAME chains connect two or more analyzed domains: a name of one analyzed domain reached from another, or a name outside them all that several reach (CDNs and shared final addresses left out). Confidence is High for a CNAME into another analyzed domain, Low when every shared name is a known service (hosting, takeover-prone, tunnel). | A dedicated proxy or host, or one domain aliasing into another, is a strong operator link. |
| Shared Web Tracker Fingerprint | High | High | T1583.001 (Acquire Infrastructure) | The same analytics / tag manager ID appears on other analyzed domains. | Shared tracker IDs tie domains to the same operator. |
| Shared Infrastructure Cluster | High (strong link) / Medium-High | High | T1583.001 (Acquire Infrastructure: Domains) | Linked to other analyzed domains by a shared certificate, key, or tracker (strong), or by IP plus name server. Confidence High for strong links, otherwise Medium. | Shared infrastructure reveals campaigns run by one operator. |
| Domain Hopping on Shared IP | Medium-High | Medium | T1583.001 (Acquire Infrastructure: Domains) | A new domain appears on an IP within Domain Hopping Gap (Days) after the previous one went dark. Confidence High with 2+ hops. | Typical takedown evasion: the operator moves to a fresh domain on the same server. |
| Bulk Registration Cohort | Medium | Medium | T1583.001 (Acquire Infrastructure: Domains) | Analyzed domains registered within 48 hours at the same registrar that also share an own name server, a registrant mail domain or a hosting ASN. | Registered together by one operator, often for one campaign. |
| Campaign Wave (Same-Day Setup) | Medium | Medium | T1583.001 (Acquire Infrastructure: Domains) | Three or more analyzed domains registered within 48 hours, each given a certificate by the same CA within 72 hours of registering. | One campaign set up in one go. |
| Linked to Confirmed-Malicious Domain | High | Medium | T1583.001 (Acquire Infrastructure: Domains) | In a Strong infrastructure cluster with a domain you marked Malicious (domain verdict on Alerts or the Domain profile). | Domains sharing certificates, keys, trackers or rare hosting with a confirmed-bad one are usually the same operator. |

#### DNS Behavior

| Detection | Severity | Confidence | MITRE ATT&CK | Fires when | Why it matters |
| --- | --- | --- | --- | --- | --- |
| Parked-to-Weaponized | High | Medium | T1583.001 (Acquire Infrastructure) | Dormant longer than Parked Dormancy (Days), then 3+ DNS changes within 48 hours that include a new address (A / AAAA). | Aged domains are bought or reactivated to evade new-domain reputation checks. |
| Rapid IP Rotation (Fast-Flux) | High | Medium | T1568.001 (Fast Flux DNS) | At least Rapid IP Rotation Event Count distinct IPs on one hostname within 7 days (each subdomain counted apart). Confidence drops to Low when every IP belongs to a CDN. | Rotating IPs hide the real hosting and resist takedowns. |
| Multi-Network Fast-Flux (ASN-Diverse) | High | High | T1568.001 (Fast Flux DNS) | Non-CDN IPs of one hostname across at least Fast-Flux Min Distinct Networks ASNs or prefixes within 7 days. | Spreading across networks is typical of botnet-hosted flux, not CDNs. |
| Sinkhole / Loopback Resolution | Medium | High | T1568 (Dynamic Resolution) | A or NS record points to 127.0.0.1, 0.0.0.0, or a known sinkhole. | Usually means the domain was taken over by researchers or law enforcement after abuse. |
| Anomalous TXT Payload | High | Low | T1071.004 (DNS C2) | TXT record longer than Anomalous TXT Length with almost no spaces, that is neither a known SaaS / mail record (DKIM, verification tokens) nor a key=value setting. | Long encoded TXT data is a classic DNS tunneling / C2 channel. |
| Flash/Burst Campaign | High | Medium | T1583.001 (Acquire Infrastructure: Domains) | Over 1,000 queries on a record alive 7 days or less and no longer seen, above pDNS Burst Density (a record that is merely new does not count). | Short, intense query bursts match spam blasts and botnet check-ins. |
| Query Volume Anomaly | Medium | Low | T1071.004 (App Layer Protocol: DNS) | Daily pDNS volume with a robust z-score above Query Volume Anomaly (100+ queries). | Sudden traffic spikes point to campaign activity; counts are approximate. |
| Deeply Nested Subdomains | Medium | Low | T1584.001 (Compromise Infrastructure) | Hostnames 3 or more labels deeper than the domain, not counting service labels (_domainkey, _acme-challenge, ...). | Deep nesting is used for domain shadowing on compromised DNS accounts. |
| CNAME Retargeted to Another Provider | Medium | Low | T1584.001 (Compromise Infrastructure: Domains) | A hostname's current CNAME points to a different registrable domain than its earlier one, and the new target is external and not a CDN. | Repointed subdomains are how takeovers and compromised DNS accounts show up; also normal during migrations, so check the new provider. |
| Long CNAME Chain / Loop | Medium (Medium-High for a loop) | Low | T1090 (Proxy) | A current CNAME chain of at least Long CNAME Chain Min Hops CNAMEs, a chain stopped at the step limit, or a loop. | Layered redirects hide the final hosting and let operators swap it without touching the visible name. |
| Name Server Churn | Medium | Medium | T1584.002 (Compromise Infrastructure: DNS Server) | Three or more name server providers within 30 days (parking name servers not counted). | Abusive domains move DNS repeatedly to stay ahead of takedowns. |
| Generated Fast-Flux Domain | Critical | High | T1568.001 (Fast Flux DNS) | Compound: a generated-looking (DGA) name with fast-flux or ASN-diverse flux. | The pattern of botnet C2 domains. |

#### Domain Name

| Detection | Severity | Confidence | MITRE ATT&CK | Fires when | Why it matters |
| --- | --- | --- | --- | --- | --- |
| DGA / High Entropy Domain | Medium-High | Low | T1568.002 (Dynamic Resolution: DGA) | Domain label of 13+ characters with Shannon entropy above the DGA Entropy Score threshold, or of 8+ characters that looks generated (letter/digit mix, long consonant run). | Algorithmically generated names are used by malware to find C2 servers. |

#### Email

| Detection | Severity | Confidence | MITRE ATT&CK | Fires when | Why it matters |
| --- | --- | --- | --- | --- | --- |
| High-Risk Mail Provider | Medium | Low | T1585.002 (Acquire Email Accounts) | MX records (passive DNS, or the current MX in Iris Investigate) point to an anonymous, throwaway mail provider (cock.li, guerrillamail, mailinator, ...; not large consumer providers). | Disposable mail backends are common in phishing and fraud operations. |
| Phishing/Spam Prep | Medium-High | Low | T1583.001 (Acquire Infrastructure) | MX / TXT / SPF records added after longer than Phishing Prep Dormancy (Days). | Mail setup on a quiet domain often precedes a phishing or spam campaign. |
| Invalid/Malformed SPF | Low | Medium | T1583.001 (Acquire Infrastructure) | SPF record without the required 'v=' prefix. | Hygiene issue; mostly useful as a sign of hastily configured infrastructure. |
| Highly Permissive SPF (+all) | High | High | T1583.001 (Acquire Infrastructure) | SPF record (passive DNS, or the current SPF in Iris Investigate) ends in +all, authorizing any server to send mail. | Lets anyone spoof the domain; rarely legitimate. |

#### Hosting & DNS Providers

| Detection | Severity | Confidence | MITRE ATT&CK | Fires when | Why it matters |
| --- | --- | --- | --- | --- | --- |
| Suspicious / Offshore Name Server | Medium-High | Medium | T1583.001 (Acquire Infrastructure) | Name server at a dynamic, free, or bulletproof DNS provider. | These providers ignore abuse reports and are favored for malicious domains. |
| Dangling CNAME (Subdomain Takeover Risk) | Critical (High when no target is on a takeover-prone service) | Medium | T1584.001 (Compromise Infrastructure: Domains) | A current CNAME whose chain (collected passive DNS, then the DNSDB chase) ends at a name with no A, AAAA or CNAME record. Critical and High confidence when the target is on a takeover-prone service (S3, Azure, Heroku, GitHub Pages, Shopify, ...). | A dangling CNAME lets anyone who claims the target resource serve content, phishing pages or cookies-stealing scripts on the organization's own subdomain. |
| Unverified CNAME to Takeover-Prone Service | Medium | Low | T1584.001 (Compromise Infrastructure: Domains) | A current CNAME to a takeover-prone service whose chain was not chased (chasing off, over the per-domain chase budget, or the lookup failed). | Same takeover exposure as a dangling CNAME, but unconfirmed: chase it in the CNAME Chains lens. |
| CNAME to Dynamic DNS / Tunnel Service | High | Medium | T1568 (Dynamic Resolution) | Any CNAME in the analysis window to a dynamic DNS or tunnel service (Duck DNS, No-IP, ngrok, Cloudflare quick tunnels, localtunnel, ...). | These names follow a home or attacker machine or expose a local service; legitimate organizations rarely point their subdomains there, attackers use them for C2 and short-lived phishing. |
| CNAME to Free Hosting Platform | Medium (High when the hostname has a phishing word, brand or embedded domain) | Low | T1583.006 (Acquire Infrastructure: Web Services) | A current CNAME from the domain to a free hosting platform it does not belong to (pages.dev, workers.dev, Vercel, Netlify, Firebase, ...). High when the hostname also shows a Subdomain Triage name signal. | Free platforms give attackers disposable, reputable-looking hosting behind a trusted name. |
| High-Abuse / Offshore Hosting Provider | Medium-High | Medium | T1583.003 (Acquire Infrastructure: Virtual Private Server) | Currently resolves to a provider on the high-abuse / offshore watchlist. | Bulletproof and offshore hosts are preferred for malicious services. |
| Potential Origin IP Exposure (Behind CDN) | Medium-High | Medium | T1090.002 (Proxy: External Proxy) | Non-CDN IPs observed for a domain that sits behind a CDN. | May reveal the real origin server hidden behind the proxy. |
| Domain on Tor Relay / Exit Node | High (exit) / Medium-High (relay) | High | T1090.003 (Proxy: Multi-hop Proxy) | An IP the domain resolves to (in the window, or now in Iris) exits Tor traffic (High) or runs a guard / middle relay (Medium-High), by the Tor Project's data in VPNDB, while the domain used it (exit dates checked when known). New exits (last 30 days) are called out. | The host also carries anonymized Tor traffic; services on it are often run by operators who want to stay unattributed. |
| Domain on Residential Proxy Exit | High | Medium | T1090.002 (Proxy: External Proxy) | An IP the domain resolves to is a residential or mobile proxy exit (VPNDB). Confidence is VPNDB's for the IP (Low below its medium level). | Rented home connections hide the real server and evade IP reputation; legitimate sites rarely point DNS at one. |
| Domain on VPN / Proxy Exit | Medium-High | Medium | T1090.002 (Proxy: External Proxy) | An IP the domain resolves to is an exit of a commercial VPN or datacenter proxy service (VPNDB). Confidence is VPNDB's for the IP. | Unusual for a website: can mark infrastructure meant to be hard to attribute. A shared exit identifies the service, not the actor. |
| Domain on Dedicated Anonymizer Exit | High | Medium | T1090.002 (Proxy: External Proxy) | An IP the domain resolves to is a VPN or proxy exit few customers share (VPNDB sharing LOW or IOC value HIGH), e.g. a dedicated VPN IP. | The address points to one customer, so it is a usable actor indicator: pivot on it and block it. |
| Hosting Moved onto Anonymizer Exit | Medium-High | Medium | T1090.002 (Proxy: External Proxy) | The domain resolved to ordinary hosting first and its newest addresses in the window are VPN, proxy or Tor exits (passive DNS and VPNDB). | Moving a domain behind an anonymizer often follows a report or a block and hides the real server. |
| Domain Rotates Across Anonymizer Exits | Medium-High | Medium | T1090.002 (Proxy: External Proxy) | The domain resolves to three or more anonymizer exits, or to exits of two or more providers (VPNDB). | Rotating exits keeps hosting ahead of IP blocks and reputation lists. |
| Newly Registered Domain on Anonymizer Exit | High | High | T1583.001 (Acquire Infrastructure: Domains) | A Newly Registered Domain that already resolves to a VPN, proxy or Tor exit (Iris Investigate and VPNDB). | A fresh domain hidden behind an anonymizer from the start is a common phishing and C2 set-up. |
| Anonymizer Exit Shared by Analyzed Domains | Medium-High | Medium | T1583.003 (Acquire Infrastructure: Virtual Private Server) | Two or more analyzed domains resolve to the same anonymizer exit, one that few customers share (shared exits are left out). | Domains behind one non-shared exit are probably run by the same operator. |
| Hosted Among Tor Exits | Medium | Low | T1090.003 (Proxy: Multi-hop Proxy) | The domain's IPs are not Tor relays, but sit in a Tor exit prefix, or on a network carrying 0.5 % or more of Tor exit traffic or 10+ exit addresses (VPNDB /tor). | A hoster that welcomes Tor exits, often privacy or bulletproof-style, or a server next to the operator's own exits. |
| Hosted Among Anonymizer Exits | Medium | Low | T1090.002 (Proxy: External Proxy) | The domain's IPs are not exits, but their /24 holds known VPN / proxy exits, or the network (Iris ASN) is one VPN provider's (VPNDB). | The domain is probably hosted on an anonymizer operator's servers or next to them. |
| Subdomain Takeover in Progress | Critical | Medium | T1584.001 (Compromise Infrastructure: Domains) | Compound: a dangling CNAME and a subdomain repointed to another provider on the same domain. | A takeover may already have happened, not only be possible. |
| Bulletproof-Hosted New Domain | High | Medium | T1583.003 (Acquire Infrastructure: Virtual Private Server) | Compound: newly registered and on a suspicious name server, watchlisted hosting, an anonymizer exit, or with name server churn. | Set up to resist takedown from day one. |

#### Lookalike / Brand

| Detection | Severity | Confidence | MITRE ATT&CK | Fires when | Why it matters |
| --- | --- | --- | --- | --- | --- |
| Homoglyph / IDN Brand Impersonation | Critical | High | T1583.001 (Acquire Infrastructure: Domains) | Domain renders like a protected brand using look-alike characters. | Built to deceive users visually; strongly associated with phishing. |
| Typosquatting Lookalike | High | Medium | T1583.001 (Acquire Infrastructure: Domains) | Small edit distance from a protected brand domain. | Catches mistyped traffic and lends credibility to phishing. |
| Combosquatting (Brand + Keyword) | High (Medium without a risky keyword) | Medium | T1583.001 (Acquire Infrastructure: Domains) | Brand as a whole word of the name, or joined only to words such as login, secure, support or digits (`paypallogin`; `purchase` does not match `chase`). | Brand + keyword names are the most common phishing domain pattern. |
| Brand in Subdomain | Medium-High | Medium | T1566.002 (Phishing: Spearphishing Link) | Protected brand appears as a subdomain of an unrelated domain. | Makes phishing links look legitimate at a glance. |
| Brand Name on Alternate TLD | Low | Low | T1583.001 (Acquire Infrastructure: Domains) | Exact brand name registered on another TLD. | May be defensive or third-party; watch for activation. |
| IDN / Punycode Domain | Low | Low | T1583.001 (Acquire Infrastructure: Domains) | Domain uses internationalized (punycode) characters. | Context for homoglyph abuse; common and benign in many languages. |
| Phishing Kit Staging | Critical | High | T1583.001 (Acquire Infrastructure: Domains) | Compound: a brand lookalike, newly registered (or re-registered), with a certificate issued as a hostname went live (Rapid Weaponization or Certificate Staged Before DNS). | Three independent signals together describe the setup of a phishing site. |
| Mail-Capable Lookalike | High | Medium | T1566.002 (Phishing: Spearphishing Link) | A brand lookalike with MX records and no DMARC record, no SPF, or SPF without -all. | It can send mail that passes as the brand. |
| Lure Subdomain | Medium | Medium | T1566.002 (Phishing: Spearphishing Link) | Subdomains whose names alone score Medium or more in Subdomain Triage with a phishing word, brand, embedded domain or punycode. | Lure names hide the real domain in links sent to victims. |

#### Registration & Lifecycle

| Detection | Severity | Confidence | MITRE ATT&CK | Fires when | Why it matters |
| --- | --- | --- | --- | --- | --- |
| Parked Domain (Parking Name Servers) | Low | High | T1583.001 (Acquire Infrastructure: Domains) | Domain is or was delegated to parking name servers. | Context: parked domains can be sold and weaponized later. |
| Parking Exit / Reactivation | High | Medium | T1583.001 (Acquire Infrastructure: Domains) | Domain left parking name servers and gained live A/AAAA/MX records within 7 days. | Reactivation of a parked domain often marks the start of malicious use. |
| Newly Registered Domain | Medium | High | T1583.001 (Acquire Infrastructure: Domains) | Created within Newly Registered Domain Age (Days). | Most malicious domains are used within days of registration. |
| Newly Registered & Weaponized Domain | High | High | T1583.001 (Acquire Infrastructure: Domains) | Newly registered and already resolving, mailing, or serving certificates (resolving does not count while it is on parking name servers). | A brand-new domain that is already operational is a strong abuse signal. |
| Re-Registered Domain | Medium | Medium | T1583.001 (Acquire Infrastructure: Domains) | Iris first saw the domain over a year before its current registration, or it has certificates issued more than 30 days before the registration. | Lapsed domains are drop-caught and reused for their history and reputation. |
| Disposable Registrant Email | Medium | Medium | T1585.002 (Establish Accounts: Email Accounts) | The registration's email domains include a throwaway mail service (mailinator, guerrillamail, cock.li, ...). | Nobody can be reached there for abuse reports; legitimate owners rarely register with one. |
| Registrar Transfer then New Name Servers | Medium-High | Medium | T1584.001 (Compromise Infrastructure: Domains) | A registrar change in Domain History followed within 14 days by name servers of a provider that is neither a large DNS provider nor parking. | The pattern of a hijacked or drop-caught domain being put to new use. |
| Weaponized Reactivation | High | Medium | T1583.001 (Acquire Infrastructure: Domains) | Compound: parked, dormant, re-registered or transferred domain (Parking Exit, Parked-to-Weaponized, Re-Registered, Registrar Transfer) that got a fresh, staged or backdated certificate. | Aged domains are bought or hijacked to borrow their reputation. |

#### Web & Content

| Detection | Severity | Confidence | MITRE ATT&CK | Fires when | Why it matters |
| --- | --- | --- | --- | --- | --- |
| IPTV / Stream Distribution Endpoint | Medium | Medium | T1584.001 (Compromise Infrastructure) | Subdomains such as m3u., xtream., stalker. in passive DNS, or two or more generic ones (stream., live., panel., ...). | Typical of illegal IPTV / restreaming infrastructure. |
| Live Pirate Streaming Panel Detected | Critical | High | T1584.001 (Compromise Infrastructure) | Website returns HTTP 200 with an IPTV panel title (Xtream, Stalker, ...). | Confirms an active illegal streaming management panel. |
| Cross-Domain Redirect | Medium | Medium | T1608.005 (Stage Capabilities: Link Target) | Website redirects to a different registrable domain. | Redirect chains are used for cloaking and traffic distribution. |

**Notes**

- **Lookalike rules** need a brand watchlist: the brands you protect, entered on *Settings → Brands & allowlist*. IDN /
  punycode domains are always flagged; the brand-based checks only run for the brands listed there. See [Brand
  watchlist](REFERENCE.md#brand-watchlist).
- **CAA rules** apply only to publicly trusted CAs. A certificate counts as public when it has embedded SCTs, a
  CA/B Forum policy OID, a DV / OV / EV validation level, or a recognized public CA issuer. Only those can be a
  *CAA Breach*. Certificates with explicit signs of a private CA are reported as *Non-Public / Private CA
  Certificate*, and unverifiable issuers as a low-confidence *CAA Mismatch (CA Trust Unverified)*.
- **CAA lookup:** without a direct CAA lookup and with truncated pDNS results, the CAA audit reports
  *No CAA Observed (pDNS Incomplete)* rather than *Unprotected*.
- **CNAME rules** read the [CNAME chains](#cname-chains). *Dangling CNAME* needs a chase result, so it only fires
  for chased chains (*Chase CNAMEs* in the CNAME Chains page); unchased takeover-prone
  targets are reported as *Unverified CNAME to Takeover-Prone Service* instead.
- Reference lists in `core/intel_data.py` (CDN ranges, parking providers, hosting watchlist, impersonated brands,
  takeover-prone services, ...) are curated snapshots; review and extend them for your environment. Every list, with
  its entries and the detections that use it, is in [Built-in lists](REFERENCE.md#built-in-lists).

### VPNDB anonymizer rules

The VPNDB rules follow VPNDB's own guidance on what an anonymizer IP is worth:

- **Shared or dedicated.** VPNDB rates each exit's *sharing* (how many users leave through it) and *IOC value*. A
  shared exit (sharing HIGH or IOC value LOW) identifies the VPN or proxy service, not the actor: it still alerts,
  marked *shared exit* in the IOCs, but it is kept out of the confirmed-indicator downloads and never links domains.
  A dedicated exit (sharing LOW or IOC value HIGH) points to one customer and raises *Domain on Dedicated Anonymizer
  Exit*.
- **Confidence is VPNDB's.** Each alert takes VPNDB's confidence in the attribution: measured exits (probe, scan) are
  High or Medium, addresses VPNDB only *interpolates* from their range are lower. Tor relays and exits come from the
  Tor Project's own data and are always High.
- **Tor.** A Tor exit is High, a guard or middle relay Medium-High: an exit sends anonymized traffic out of the
  domain's own address, a relay only forwards it. The exit dates from the Tor exit lists are checked against the
  domain's use of the IP (an address that became an exit after the domain left counts for nothing), and an exit set up
  in the last 30 days is called out. *Hosted Among Tor Exits* uses the free Tor overview: the domain's IP in a prefix
  with Tor exits, or on a network carrying a real share of Tor exit traffic (0.5 % or 10+ exit addresses). The
  network is BGPDB's usual origin of the IP when the run has one (the network that really announces it), else the
  Iris or VPNDB ASN.
- **What it means for the domain.** A website rarely points its DNS at an anonymizer exit. The compound rules weigh
  the context: a new registration on an exit (*Newly Registered Domain on Anonymizer Exit*), hosting that moved from
  an ordinary provider onto an exit (*Hosting Moved onto Anonymizer Exit*, often after a report or a block), and
  rotation across several exits or providers (*Domain Rotates Across Anonymizer Exits*).
- **Linking domains.** Two analyzed domains on the same non-shared exit are probably one operator (*Anonymizer Exit
  Shared by Analyzed Domains*; High confidence when the exit is dedicated).
- **Exit at the time.** With VPNDB's weekly history of an exit, an exit counts only when VPNDB saw it exit in a week
  the domain resolved to it (passive DNS first to last seen; the last two weeks for a current Iris IP). Hosting
  addresses are reused: an IP that became a residential proxy months after the domain left it says nothing about the
  domain. The IOCs give the overlapping weeks and how many domains Iris has on the IP.
- **Hosted next to exits.** *Hosted Among Anonymizer Exits* looks beyond the domain's own IPs: their /24 holding known
  exits, or a hosting network one VPN provider runs (single tenant with 25 or more known exits; a hoster where one
  proxy customer runs a single server does not count).
- **Only what the domain used.** The rules look at the IPs the domain resolved to in the analysis window and its
  current Iris IPs. VPNDB's *Not observed* is not an all-clear: it only knows the exits it measured or that public
  lists name, and it does not collect IPv6.

### BGP routing rules

With a BGPDB host (Settings → API credentials, or the bgpdbq tool's `~/.bgpdbq.conf`), each public hosting IP of the run
(IP targets, current Iris IPs, passive DNS; IPv4 and IPv6, no CDN addresses) is looked up in BGPDB, the routing table
history of about the last 30 days. The [BGP page](#pages) shows the result; the rules read it as follows:

- **Who announces the IP.** Each covering prefix and each network (origin AS) that announced it, with first and last
  seen, how many route collectors saw it, and whether the registries allow it. The *usual* origin is the one with the
  most updates.
- **Authorized or not.** RPKI decides when it has an answer (it is signed); IRR only when RPKI has none. *Valid*: the
  registry names this origin; *Unauthorized*: it names another one; *Not in RPKI / IRR*: nobody registered the prefix
  (common, not a finding on its own). A record can carry both an IRR match and an IRR mismatch: a match wins.
- **Private AS at one collector.** A private or reserved origin AS (0, 23456, 64496–65535, 4200000000+) seen by at
  most 2 route collectors is a collector peer leaking its internal AS number, not something the internet routed. It is
  shown (orange, *Private AS (collector-local)*) but never counts as unauthorized or as a conflict, is never the
  usual origin when another network announces the IP, and a prefix only such a leak announced raises no finding.
- **Origin conflict.** A prefix with its authorized origin and, at some point, another origin the registries name as
  invalid: a hijack or a route leak. High when the unauthorized announcement was seen in the last 7 days of the data.
  BGPDB writes announcements of more-specific prefixes inside a block as `1.2.3.0/24+`: they count as a conflict with
  the block's authorized origin.
- **Bring-your-own-IP and DDoS protection.** Clouds and DDoS-protection services announce their customers' address
  space (Cloudflare incl. Spectrum, AWS, Google, Microsoft, Akamai incl. Prolexic, Fastly, Imperva, Oracle), while the
  customer's registry objects often still name the customer's own network. When such a network is the unauthorized
  origin, an origin conflict is Low and an unauthorized usual origin Medium, or Low when an authorized network is seen
  announcing the prefix or a more-specific inside it (the customer). The detail says *likely bring-your-own-IP or DDoS
  protection*.
- **New prefix.** The usual origin started announcing the prefix in the last 14 days. A prefix first seen on the first
  days of BGPDB's window only means *at least that old* and never counts as new.
- **Young network.** The origin AS was registered at its RIR in the last year (Medium-High under 90 days).
- **Thin route.** Fewer than 10 route collectors see the prefix, or the origin network has a single upstream and no
  downstream networks. Low: many legitimate small networks look like this. A single upstream of the same company (AS
  names sharing a distinctive word, e.g. Cloudflare Spectrum behind Cloudflare) does not count.
- **Hosting moved.** The usual origin network of the domain's hosting is compared with the domain's latest earlier
  saved run that recorded routing (any target list): *Hosting Moved to a New Network* is Medium when none of the
  earlier networks is left, Low when a new one joined them. Re-hosting after a takedown or a campaign moving on looks
  like this; so does a routine CDN or provider change.
- **With VPNDB.** A VPN, proxy or Tor exit (VPNDB) on a prefix with a conflict, an unauthorized origin or a new
  announcement raises *Anonymizer Exit on Unstable Routing*: mainstream VPN providers announce stable, registered
  space. The BGP page's *VPNDB match* tab lists the exits with their routing and the origin networks that carry exits.
- **With the Tor overview.** A network that announced a hosting prefix without authorization (an origin conflict or
  an unauthorized usual origin) and that carries Tor exit traffic (0.5 % of it or 10+ exit addresses, VPNDB `/tor`)
  raises *Unauthorized Origin Is a Tor Exit Network* (Medium-High, T1557): privacy or bulletproof-style hosting
  drawing the traffic. The Tor network page matches every network BGPDB showed (origins, unauthorized origins,
  upstreams, neighbouring origins) against the Tor exit networks; only an unauthorized origin is an alert, since a
  transit or neighbouring network carrying Tor exits says little about the domain.

## MITRE ATT&CK mapping

Each rule maps to one ATT&CK technique; the tactic is derived from the technique ID. The **MITRE ATT&CK** tab of the
alert overview and the *ATT&CK Technique* grouping both use this mapping. In the tab, each technique row names the
technique and the rule categories it was detected from (e.g. *BGP Routing* for the BGPDB rules: T1557
Adversary-in-the-Middle for origin conflicts and Tor-exit origins, T1583 for unauthorized, new and young routing,
T1090 for anonymizer exits on unstable routing). **Rules** is how many detection rules map to
the technique, not how many alerts fired; the in-app **MITRE ATT&CK** tab shows alert counts for the current run.

| Tactic | Technique | Name(s) used by rules | Rules |
| --- | --- | --- | --- |
| Resource Development | T1583 | Acquire Infrastructure | 5 |
| Resource Development | T1583.001 | Acquire Infrastructure; Acquire Infrastructure: Domains | 27 |
| Resource Development | T1583.003 | Acquire Infrastructure: Virtual Private Server | 3 |
| Resource Development | T1583.006 | Acquire Infrastructure: Web Services | 1 |
| Resource Development | T1584.001 | Compromise Infrastructure; Compromise Infrastructure: Domains | 9 |
| Resource Development | T1584.002 | Compromise Infrastructure: DNS Server | 1 |
| Resource Development | T1584.008 | Compromise Infrastructure: Network Devices | 1 |
| Resource Development | T1585.002 | Acquire Email Accounts; Establish Accounts: Email Accounts | 2 |
| Resource Development | T1587.003 | Develop Capabilities: Digital Certificates | 2 |
| Resource Development | T1588 | Obtain Capabilities | 2 |
| Resource Development | T1588.002 | Obtain Capabilities: Tool | 1 |
| Resource Development | T1588.004 | Obtain Capabilities: Digital Certificates; Obtain Digital Certificates | 14 |
| Resource Development | T1608.003 | Stage Capabilities: Install Digital Certificate | 1 |
| Resource Development | T1608.005 | Stage Capabilities: Link Target | 1 |
| Initial Access | T1566.002 | Phishing: Spearphishing Link | 3 |
| Defense Evasion | T1562.001 | Disable or Modify Tools | 1 |
| Credential Access | T1557 | Adversary-in-the-Middle | 2 |
| Command and Control | T1008 | Fallback Channels | 2 |
| Command and Control | T1071.001 | Web Protocols / Shared C2 | 1 |
| Command and Control | T1071.004 | App Layer Protocol: DNS; DNS C2 | 2 |
| Command and Control | T1090 | Proxy | 2 |
| Command and Control | T1090.002 | Proxy: External Proxy | 7 |
| Command and Control | T1090.003 | Proxy: Multi-hop Proxy | 2 |
| Command and Control | T1568 | Dynamic Resolution | 2 |
| Command and Control | T1568.001 | Fast Flux DNS | 3 |
| Command and Control | T1568.002 | Dynamic Resolution: DGA | 1 |
| Command and Control | T1572 | Protocol Tunneling | 1 |
| Command and Control | T1573.002 | Encrypted Channel | 1 |
| Other | T1553.004 | Subvert Trust Controls: Install Root Certificate | 1 |

Most domain-infrastructure behavior falls under **Resource Development** (the adversary acquiring and preparing
domains, servers and certificates), with **Command and Control** for resolution, tunneling and proxy behavior.

## Infrastructure clusters and domain hopping

### Clusters

Analyzed domains are linked when they share infrastructure:

| Link | Artifacts |
| --- | --- |
| Strong | The same certificate, public key or web tracker ID; a JA4X of a certificate not from a public CA; an IP or name server Iris sees on 50 domains or fewer |
| Moderate | Two different weak artifact types together, from: the same IP, the same name server, the same CNAME target |

Iris Investigate counts how many domains use each IP, name server and tracker, and that count sets the link:

- An IP or name server on 50 domains or fewer links strongly; on more, it is a weak artifact.
- A web tracker links strongly up to 500 domains; above that it is weak.
- Any value Iris sees on more than 10,000 domains links nothing (shared hosting, big DNS providers, a common
  analytics account).
- A JA4X from a public CA links nothing: public CAs share a few JA4X values by design.

Linked domains are joined into clusters (C1, C2, ...). A cluster is **Strong** if any strong artifact links it.
CDN IPs, private IPs, large managed DNS providers, parking name servers and values on your
[allowlist](#allowlist) are ignored, so shared CDNs and your own infrastructure do not create false clusters. Each member gets a *Shared Infrastructure Cluster* alert, and the *Campaign Cluster* grouping turns
each cluster into one incident. The **DNS & Hosting** page (*Campaign & hosting* tab) shows the clusters and an infrastructure
graph.

### Domain hopping

A hop is a new registrable domain appearing on an IP within **Domain Hopping Gap (Days)** after every earlier
domain on that IP went dark: a typical way to move to a fresh domain after a takedown. It needs IP observations:
analyze IP targets, or enable **Pivot on hosting IPs** (DNSDB Scout). IPs with more than 50 domains (shared
hosting), CDN IPs and private IPs are ignored. With a window set, only hops whose new domain appeared inside the
window are reported.

## CNAME chains

A CNAME makes one name an alias of another; the alias can point to another alias, and so on, until a name has
addresses. The **CNAME Chains** page maps every CNAME in the analysis window: the hostname, its target, the service
the target runs on, the full chain, and where it ends.

**How a chain is followed.** First through the run's own passive DNS (no API calls): each name's most recent CNAME,
until a name has A / AAAA records. Where the chain leaves the collected data, a **DNSDB CNAME chase** continues it,
like CNAME chasing in DNSDB Scout: one exact-name lookup per step (`name/CNAME`; at the end `name/A`, then
`name/AAAA`), following the most recent CNAME, at most 10 steps. Chases run on demand from the page (*Chase CNAMEs*: the
selected hostnames or all shown, up to 10 DNSDB queries per domain per click; dynamic DNS, takeover-prone and free
hosting first). The table fills in a hostname's chain once it is chased.

| Outcome | Meaning |
| --- | --- |
| Resolves | The chain ends at A / AAAA records; **Final** lists the latest addresses |
| Dead end | A name in the chain has no CNAME, A or AAAA record in DNSDB: it never resolved, or stopped long ago. A current CNAME to such a name is a possible **dangling CNAME** |
| Incomplete | The chain ends at a CDN name DNSDB has no address for (DNSDB Scout: *Chasing incomplete*): the final address is unknown, not a dangling CNAME |
| Loop | The chain returns to a name it already passed |
| Step limit | Stopped after 10 steps |
| Lookup failed | A DNSDB lookup failed (see the Data sources page) |
| Not chased | The chain leaves the collected data and was not chased |

| Service type | Examples | Why it matters |
| --- | --- | --- |
| Dynamic DNS / tunnel | Duck DNS, No-IP, ngrok, Cloudflare quick tunnels, localtunnel | Follows a home or attacker machine, or exposes a local service: C2 and short-lived phishing |
| Takeover-prone | AWS S3, Azure App Service, Heroku, GitHub Pages, Shopify, Zendesk | A deleted resource leaves the CNAME claimable by anyone: subdomain takeover |
| Free hosting | pages.dev, workers.dev, Vercel, Netlify, Firebase | Anyone can publish there under a reputable-looking name |
| CDN | CloudFront, Akamai, Fastly, Azure Front Door | Fronts the real origin; see CDN Origin Exposure |
| Parking | Namecheap and Porkbun parking, Sedo, Bodis, ParkingCrew | Parked or for-sale page shared by thousands of unrelated domains: links through it are weak |
| Other (empty Service) | Any name on none of the lists | An ordinary domain, often the operator's own: the most interesting targets for links and reverse lookups |

The lists are in `core/intel_data.py` (`DYNAMIC_DNS_CNAME_SUFFIXES`, `TAKEOVER_CNAME_SUFFIXES`, `SHARED_PLATFORMS`,
`CDN_CNAME_SUFFIXES`, `PARKING_CNAME_SUFFIXES`). **Current** marks each hostname's most recent target (not replaced by A / AAAA records since);
older targets are history, used by *CNAME Retargeted to Another Provider*. The detections built on the chains are
in the [catalogue](#detection-catalogue): *Dangling CNAME (Subdomain Takeover Risk)*, *Unverified CNAME to
Takeover-Prone Service*, *CNAME to Dynamic DNS / Tunnel Service*, *CNAME to Free Hosting Platform*, *CNAME
Retargeted to Another Provider*, *Long CNAME Chain / Loop* and *CNAME Link Between Analyzed Domains*.

**Cross-domain links.** Every name and final address in the chains is compared across the analyzed domains:

| Link | Meaning |
| --- | --- |
| CNAME into analyzed domain | A hostname of one analyzed domain aliases (directly or further down the chain) into a name of another analyzed domain: the strongest link |
| Shared CNAME | Chains of several analyzed domains pass through the same name outside all of them, e.g. one fronting proxy |
| Shared final address | Chains of several analyzed domains end at the same IP. Weak on its own; links through a CDN are marked CDN |

Shared final addresses and links through CDNs are shown in the page but do not raise the detection.

**Reverse CNAME.** In the page, *Related domains* asks DNSDB which names, of any domain, point to a chain's target
or any name you type (`rdata/name/{target}/CNAME`), and lists their number and domains. Analyzed domains found this way join the links above and the
detection; other domains are listed as **Related domains**, leads for the same operator when the target is
dedicated, ordinary neighbours when it is a shared parking or hosting service.

## Detection thresholds

Every threshold is a slider under *Settings → Detection thresholds*. Changing one re-runs the
engine on data already collected, with no new API calls.

| Threshold | Default | Range | Section | What it controls |
| --- | --- | --- | --- | --- |
| Min Risk Score | 70 | 0–100 | DomainTools Risk | Domains with a known DomainTools risk score below this value get only the rules that stand on their own (lookalikes, subdomain takeover, CAA breaches, known C2 JA4X). Domains without a risk score get every rule. |
| High-Risk Score Cutoff | 70 | 0–100 | DomainTools Risk | Unified/predictive risk score at or above which a domain counts as high risk (KPIs). |
| Parked Dormancy (Days) | 180 | 30–365 | Passive DNS & Domain History | Days of inactivity before a sudden infrastructure burst triggers a Parked-to-Weaponized alert. |
| Rapid IP Rotation Event Count | 5 | 2–20 | Passive DNS & Domain History | Minimum distinct IPs within 7 days needed to flag Fast-Flux DNS behavior. |
| Fast-Flux Min Distinct Networks | 3 | 2–10 | Passive DNS & Domain History | Distinct ASNs (or network prefixes when ASN is unknown) of non-CDN IPs within 7 days for Multi-Network Fast-Flux. |
| Phishing Prep Dormancy (Days) | 60 | 10–365 | Passive DNS & Domain History | Days of domain dormancy prior to a sudden Mail (MX) or SPF/TXT addition. |
| Anomalous TXT Length | 200 | 50–1000 | Passive DNS & Domain History | Character length above which continuous TXT records trigger DNS Tunneling / C2 alerts. |
| pDNS Burst Density (Queries/Day) | 10000 | 1000–50000 | Passive DNS & Domain History | Query rate per day on short-lived infrastructure that flags flash-spam or botnet campaigns. |
| Query Volume Anomaly (Robust Z) | 6 | 3–15 | Passive DNS & Domain History | Robust z-score (median/MAD) of daily pDNS query volume above which a day is flagged as anomalous. |
| Domain Hopping Gap (Days) | 14 | 1–90 | Passive DNS & Domain History | Max days between one domain going dark on an IP and the next domain appearing there. |
| Long CNAME Chain Min Hops | 4 | 2–10 | Passive DNS & Domain History | CNAME chains with at least this many CNAME hops before an address are flagged as hiding the final infrastructure. |
| Newly Registered Domain Age (Days) | 30 | 1–365 | Iris Investigate & Domain Name | Domains created within this many days (Iris create date) are flagged as newly registered. |
| DGA Entropy Score | 3.6 | 2–5 | Iris Investigate & Domain Name | Shannon Entropy cutoff. English names average ~2.5; algorithmic DGA names typically exceed 3.6. |
| Cert-to-DNS Gap (Hours) | 1 | 0.5–48 | Certificate API | Maximum gap between certificate issuance and first DNS observation for a Rapid Weaponization alert. |
| Short-Lived Certificate Max Validity (Days) | 10 | 1–30 | Certificate API | Certificates valid this many days or less (e.g. Let's Encrypt's 6-day 'shortlived' profile) are flagged as short-lived. Informational only: not used in risk scores or DIF fingerprints. |
| Cert Churn Min Early Replacements | 2 | 1–10 | Certificate API | Early certificate replacements within the churn window that indicate abnormal rotation. A replacement is early when a new certificate for the same names is issued while the previous one still has over half its validity left; scheduled renewals of short-lived certificates do not count. |
| Cert Churn Window (Days) | 30 | 7–90 | Certificate API | Timeframe window in days in which early certificate replacements are counted. |
| Mega-SAN Min Root Domains | 3 | 2–20 | Certificate API | Minimum unique registrable domains bundled into one certificate before a Mega-SAN alert. |
| Suspicious DV Min Risk Score | 50 | 0–100 | Certificate API | Risk score above which a Domain Validated (DV) certificate is flagged as suspicious. |

## Run history, alert lifecycle and trends

Every live run is saved to `dt_runs/` with its certificate inputs (if any), alerts (severity, confidence, category, ATT&CK), per-domain Unified
Risk and DIF, and infrastructure. Alerts are matched across runs by **(domain, threat type)**.

- **Changes Since Last Run** (Alerts page): compared with the previous run of the same target list, it shows new and
  resolved alerts and added / removed infrastructure (IPs, name servers, certificates, ...).
- **First Detected / Runs Seen** use every saved run, from any target list, that covered the domain.
- The **Runs** page (top menu) has three tabs: *Recent runs*, *Compare & trends* and *Indicator Sightings*.
- **Recent runs** shows the newest saved runs as a timeline (one lane per target list, dot size = alerts, color =
  highest severity), as cards (one card per target list: its newest run with the number of runs, alerts new and
  resolved since the previous run of the same list, Unified Risk trend, the indicators it shares with other target
  lists, each a click away from its sightings; *Show all runs* opens the table with every run of that list) or as a
  table (one row per target list, or every run newest first with *Show all runs*: time, targets, alerts per severity,
  new and resolved alerts, change, risk, use case, window, API queries, what started the run, offline copy, shared
  indicators and runs of the list). It has a filter, a run count (in Cards and the compact table, target lists),
  *With alerts* / *New alerts* toggles and a **Runs and detections per day** chart (runs per day, hunt runs started from a lead in
  purple, and below, new detections or all alerts found per day by severity; dated days with week numbers, over 2, 6
  or 12 weeks). Click a dot, card or row to pick a run (the newest is picked at first). Under the view:
  - **Run again**: a new live run with the same use case, analysis window and collection options (runs saved before
    options were recorded use the current ones);
  - **Load offline copy**: the newest offline dataset saved from that run, re-analyzed with no API calls (greyed out
    when none was saved);
  - **Compare & trends**: opens that tab on the run.
- **Compare & trends** (titled *Previous Runs & Comparison*):
  - **Run Details:** one run's alerts, risk and DIF.
  - **Compare Runs:** any two runs; new, resolved and persisting alerts, infrastructure changes, and risk / DIF changes.
  - **Trends:** detections per run by severity, Unified Risk per domain with DIF-change markers, and infrastructure counts per run.
  - **Domain across runs:** one domain across every saved run that included it, with a detection lifecycle (first /
    last detected, active in the latest run).
  - **Watched Lists:** the target lists you watch, each with *Run now* ([below](#watched-target-lists)).
  - **Manage Runs:** name and annotate runs, export as JSON, and delete (with confirmation).
- How many runs are kept per target list (default 10) is set under *Settings → Storage & cache → Retention*.
- Runs saved by earlier versions show in a reduced *legacy* format (no severity, risk or DIF).
- Offline datasets have their own page, *Data → Saved datasets*: see [Usage](USAGE.md#offline-datasets).

## JA4X: how certificates were generated

JA4X (part of FoxIO's JA4+) fingerprints how a certificate was generated, not what it names: three 12-character
parts `a_b_c` hash the issuer's attribute types, the subject's, and the extension OIDs. `000000000000` means that
part is empty. Certificates made by the same tool or template have the same JA4X, whatever their names and keys.

The Certificates API returns `ja4x` with the latest CertsQL release. Certificates collected before it is live have no
JA4X, and everything below stays empty for them.

The built-in fingerprints come from FoxIO's JA4+ mapping (`ja4plus-mapping.csv`) and the JA4+ introduction on the
APNIC blog (*JA4+ network fingerprinting*, 2023): C2 and malware (Cobalt Strike default certificate, Sliver / Havoc
C2, Metasploit, Qakbot, Pikabot, AsyncRAT / QuasarRAT / BitRAT), a dual-use tool (SoftEther VPN) and a network
device's default certificate (Cisco RV32x routers). The values are in Reference → Built-in lists.

| Where | What it does |
| --- | --- |
| Alerts | **Known C2 Certificate Fingerprint (JA4X)** (High) when a certificate's JA4X is on the built-in list of C2 and malware fingerprints (Cobalt Strike, Sliver / Havoc, Metasploit, Qakbot, Pikabot, AsyncRAT / QuasarRAT / BitRAT); confidence is High when the certificate is also self-signed, else Medium. **Dual-Use Tool Certificate Fingerprint (JA4X)** (Medium, Low confidence) for tools such as SoftEther VPN. **Network Device Default Certificate (JA4X)** (Medium, Low confidence) when the host serves a router's own certificate (Cisco RV32x): small-office routers are often compromised and used as relays. **Code-Generated Certificate Layout (JA4X)** (Medium, Low confidence) when a JA4X not on the lists has an empty issuer part (`000000000000_…`): no CA issues such a certificate, while C2 frameworks that generate their own do (Sliver and Havoc build random ones this way); search CertsQL for the JA4X to find the rest of the set. The lists are in Reference → Built-in lists |
| **JA4X worth a look** (Summary → Analysis Details, Certificates → Overview, Domain profile) | Only shown when a run has one: each JA4X that matches a known tool or device, has a code-generated layout, or is shared by two or more of your domains off public CAs (one tool or template made them), with why, the domains and *In Window* (unticked: only on certificates older than the analysis window; the alerts still use them), and *Open the JA4X & C2 tab*. Each known or code-generated value has a **fingerprint card** (below). The Domain profile lists its own domain's, and its *Newest certificates* table shows each JA4X with a note |
| **Fingerprint card** (JA4X worth a look, the JA4X & C2 tab, *Look up any JA4X*, CertsQL results) | What the value matches (tool and kind: C2 / malware, dual-use tool, network device, code-generated, not listed) and the source; the three parts and what each says; for Cobalt Strike, how its certificate is made and its default names. With the run's certificates it says whether they carry the tool's **default names** (the tool's own certificate) or share **only the layout**: Cobalt Strike's default is made with Java keytool, so any keytool certificate with a full six-part name has the same JA4X. Then what to check and why a match can be innocent |
| **Evidence → Records → Certificates** | The *JA4X* column with a *JA4X Note*: the known tool or device and its kind, or what the layout says (*empty issuer*, *issuer = subject layout*) |
| **Certificates → JA4X & C2** tab | One row per JA4X in the run: the tool it matches, the domains and certificates with it, issuers, self-signed, and what the layout says (*issuer = subject layout*, *empty issuer*, *no extensions*). The fingerprint card of the value picked under *JA4X to pivot on*, and *Look up any JA4X* decodes any value you paste (no API query) |
| *Check how common* | Counts each JA4X in the Certificates API: one Certificate Search request per value, at most 10 per click, cached. *Rare* is 50 certificates or fewer, *Uncommon* up to 1,000, else *Common*. A rare or uncommon JA4X shared by two domains is called out: the same tool or template made their certificates |
| *Find certificates with this JA4X* | Opens CertsQL with `ja4x equals "…"`, to find every certificate with it, not only this run's. *Hunt for a known tool's certificates* does the same for a value from the built-in lists |
| Runs (Compare & trends, Indicator Sightings) | Each domain's JA4X values are saved with the run, so a changed JA4X between two runs (the operator rebuilt the server) shows up in the diff, and *Runs → Indicator Sightings* finds earlier runs with the same value |

Certificates from public CAs share a few very common JA4X values, so a shared JA4X alone is no link: use *Check how
common* before treating it as one. A known-tool match means the certificate was built the way that tool builds its
own; other certificates built with the same fields match too, so confirm with the certificate itself.

## Suppressions and exports

- **Suppressions** (Alerts page → *Manage Suppressions*, or *Suppress N alert(s)* in a group) hide a threat type for one
  domain or for all domains (`*`), with a note. Suppressed alerts are excluded from the alert list, KPIs, exports and
  saved runs, and can be reviewed and removed in the same panel. They are stored in `dt_suppressions.json`.
- **Exports** (*Data → Export & report*; on the Alerts page, *Export detections, IOCs and reports* opens it):
  detections follow the current alert filters and exclude suppressed alerts; indicators cover the selected domains
  and the analysis window.

  | Export | Contents |
  | --- | --- |
  | Detections (CSV) | Every alert column except the structured evidence |
  | IOCs (CSV / JSON) | Target domains, resolved IPs (with CDN notes), name servers, certificate hashes and, with BGPDB, origin networks and announced prefixes (context, with the routing findings naming them), with source and first / last seen |
  | STIX 2.1 Bundle | The indicators and detections as STIX 2.1 objects (below) |
  | Evidence Report (HTML / Markdown) | Risk overview with DIF, detections by severity, infrastructure clusters, indicators, and each detection's evidence |

  The STIX bundle holds one indicator per IOC, with a confidence value. An indicator is `malicious-activity` only
  when an alert of Medium or High confidence, and not of Low severity, backs it; otherwise it is
  `anomalous-activity`. Each ATT&CK technique of those alerts is an `attack-pattern` object, linked to the indicator
  by an `indicates` relationship. Each infrastructure cluster is an `infrastructure` object. In a MISP event,
  attributes carry a `mitre-attack-pattern` galaxy tag for their technique. Origin networks and prefixes are context:
  in MISP `AS` / `ip-dst` attributes with `to_ids: false`, in STIX only when a routing finding names them, and then
  never `malicious-activity`.

  For a manager or a takedown request, the **Case report** at the top of *Export & report* is the short version: one
  printable HTML page (print it to PDF) with your summary, the run at a glance, the most severe alerts with their
  evidence, risk by domain, an infrastructure snapshot (registrar, dates, IPs with ASN and country, name servers,
  MX) and the indicators. It contains no scripts and loads nothing from the internet.

## Hunting: triage status, leads and the hunt map

### Triage status

Every alert has a **status**, and every domain a **verdict**:

| Status | Meaning |
| --- | --- |
| New | Not looked at yet (the default) |
| Investigating | Someone is on it |
| Benign | Checked: expected or harmless |
| Malicious | Confirmed bad; its indicators go into the confirmed-indicator export |

Set the status of all alerts in a group at the top of the group on the **Alerts** page (with a note), and a domain's
verdict on its **Domain profile**. Decisions are kept in `dt_triage.json` by (domain, threat type), so a rerun of the
same domains shows what was already reviewed. The Hunt map's **Alert decisions** count them, *What to check next* only
uses the open alerts (New and Investigating), and the alert filters and tables show the status.

### Risk drivers

*Risk drivers* (Summary) and *Why this score* (Domain profile) split the [Unified Risk](#unified-risk-and-risk-vectors)
into its parts, largest first: 0.4 × the DomainTools risk score and 0.3 × each risk vector, with the most severe alert
behind that vector. When the DomainTools score alone is higher than the telemetry score, it sets the score and is the
only driver.

### Leads and the hunt map

The suggested hunt's branches and, below them on the Hunt map, **More leads (All pivots)** (strong values the
suggested hunt doesn't already list) are the strongest values of *Hunt map → All pivots* (see [Pages](#pages)):
shared by a few hundred domains or fewer in Iris (values two or more of your domains share come first). Each lead has:

- **Analyze**: analyzes the value (IPs, certificates, redirect domains) right away as a new run, linked to the
  current one, with the current collection options;
- **Find in Iris**: one Iris Investigate search for the domains that share the value; they open on *Hunt map → All
  pivots*, where *Analyze now (N domains)* analyzes the highest-risk ones.

Self-signed certificate cards (Certificates → Self-Signed) offer the same: *Analyze its domains* (the certificate as
a `sha256:` / `sha1:` input) and *Find in Iris* (by SHA-1).

A run started this way remembers the run it came from and what led to it. The Summary shows the **hunt trail**
(first run → … → this run; runs of the same targets again are counted, e.g. *(5 runs)*, not repeated), and **Hunt → Hunt map** draws the whole hunt (see [Hunt map](#hunt-map)). Runs join the
loaded run's hunt in three more ways:

- **IrisQL and CertsQL**: while a run is loaded, *Add the new run to the hunt of the loaded run* (above the Analyze
  button, ticked by default) links the run you analyze from a search to it. Untick it to start a hunt of its own.
- **The same targets again**: *Run again*, or analyzing exactly the same target list, continues the hunt of that
  list's newest earlier run (*Same targets again* on the map) instead of starting a new hunt.
- **Join**: see *Combined hunts* below.

### Suggested hunt

Before you follow anything, the Hunt map's **Suggested hunt** (under *Next steps from the loaded run*) proposes where to start and which branches to follow.
It ranks what the run already knows, with no API call until you click; it is a ranking, not a prediction of what new
lookups will find.

- **Start here**: the indicators the open alerts name, in order. The most severe alerts come first; within a
  severity, what identifies an operator best goes first: a JA4X, then the certificate, then the IP, then other hosts.
  An indicator that is also a lead is followed by a step for its shared domains (*Find in Iris*). The Summary's
  *Hunt* box names the first one.
- **The hunt this run would grow**: the five best leads (*All pivots* values another domain shares) as branches,
  each with a score and its reasons:

  | Counts for a lead | Points |
  | --- | --- |
  | Few domains share it in Iris | up to 40 (10 or fewer: 40; 50 or fewer: 32; 200 or fewer: 24; 500 or fewer: 16) |
  | Several of your domains have it | 5 per extra domain, up to 10 |
  | Named in open alerts | 30 critical, 22 high, 15 medium-high, 10 medium, 4 low, +2 per extra alert, up to 35 |
  | Kind of value | certificates 12, tracker codes and contact emails 10, redirect domains 9, registrant details 6–7, IPs 6, name servers 4, mail servers 2 |
  | Seen in other investigations | 8, +4 when those domains had alerts. Only runs on other domains count: an earlier run of the same domains is the same investigation |

  Under the first three, a look-ahead (gray) says what following them would bring: how many domains are not in
  this run yet (Iris count), where earlier investigations saw the value and with how many alerts, and, when the Iris
  search was already made (*All pivots*), the riskiest of its domains and how many earlier investigations flagged.
  Each branch has *Analyze* (when the app can take the value as a target) and *Find in Iris*; a branch you followed is
  marked *followed* and links to the Hunt map. *Analyze now (top 3)* analyzes the best target-able leads
  together.
- **Set aside**: leads not worth following, with the reason: shared by more than 500 domains in Iris (shared hosting
  or a service), a CDN edge, a private address, a large DNS provider or parking name server, already analyzed in
  this hunt, every domain that has it already in this run, or no Iris count and no alert naming it.

**Details** on a step or a branch opens that indicator alone, with no API call: how many of your domains have it,
the open alerts that name it, its certificates (certificates and JA4X) or passive DNS records (IPs and hosts), its
VPNDB verdict, and the earlier investigations of other domains that saw it. Its next steps are already pointed at it:

| Indicator | Next steps |
| --- | --- |
| Certificate | *Show on Certificates (only this)*: every Certificates tab narrowed to it, with *Show every certificate* to go back; *Analyze its domains*; *Search CertsQL* (its `sha256` / `sha1` query, ready to run); *Find in Iris* |
| JA4X | *Show on Certificates (only this)*; *Search CertsQL* (`ja4x equals …`) |
| IP, host | *Analyze*; *Find in Iris* |
| Any | *Where else was it seen?* (Runs → Indicator Sightings) |

The Summary keeps only a short **Hunt** box: open alerts to decide, indicators to confirm first, leads worth
following, the first step, and **Open the Hunt map** (its *This hunt* tab), where all of the hunting work is.

The suggested steps are numbered in one list: the *Start here* indicators first, then the branches (an indicator
that is both is one step). **Run suggested hunt…** (Hunt map) lists every step in order, ticked, with what
each does: *Analyze* a target, an *Iris search*, or a JA4X to search by hand on CertsQL (not run). Steps a run
already followed are not run. Untick what you don't want, then:

- **Run all ticked**: starts **one** new run right away with the ticked targets (at most 10), linked to this one, and
  makes their Iris searches (results on *Hunt map → All pivots*). Certificate steps skip the *review the searches* and *choose
  what to analyze* screens: their searches run as recognized and the domains and IPs pre-selected there are analyzed.
  The same goes for *Analyze* on a step (Hunt map, Summary, Details). You stay on the page: the map grows with the
  new run and its next steps.
- **Guide me, one step at a time**: a banner on the Hunt map (and the Summary) shows the next step, with *Run this
  step*, *Skip* and *Stop*. Each step's run is linked to the run the hunt started from.

Nothing runs before you click; every run uses API quota as a normal Analyze or Iris search does.

### Hunt map

**Hunt → Hunt map** is where a hunt is seen and steered. *This hunt* picks a hunt (the loaded run's comes first),
shows where it stands and draws it:

| On the map | What it shows |
| --- | --- |
| Run (box) | Its targets, when, how many domains; what it added to the hunt (new domains, new alerts and how many are High or Critical; grey when it added little); its alerts by severity and its two most common alert types; its BGP routing (*BGP: 3 prefixes · AS13335, AS16509 · 1 routing alert (High)*, from BGPDB); whether its new domains share infrastructure with the starting point (an announced prefix of /22 or smaller counts, as IPs do: *linked to start: 4 Certificate, 1 IP, 1 Prefix*, or a red outline and *no link to start: drifted*). The loaded run is outlined in blue. A later run linked to the start also gets a dotted line back to it |
| Open step (dashed) | A step the run suggested that no run of the hunt has followed: its number, type and value, score, Iris count, the open alerts that name it (and the worst), their alert types, how many of your domains have it. Orange: *start here*; grey: a lead |
| Done step (green ✓) | A step followed, with an arrow on to the run it started. Steps that had already led to this run are one box (*✓ N steps repeated from before*). A run started some other way is linked with what led to it |

**Focus on a start indicator.** When the hunt's first run analyzed several targets (domains, IPs), the pills above
the map pick one of them, or *All indicators* (default). Each pill names how many of its steps are open. With one
picked, the map keeps that indicator's steps (from the alerts on it and the leads it shares with other domains) and
the runs that grew from them, with everything after them; the counts, the hunt status and the *Next steps from the
loaded run* (alerts, *Check next*, the suggested hunt and its steps) follow the focus. Joins, detaches and *Runs of
this hunt* still cover the whole hunt. A first run saved before steps recorded their indicator shows every step under
each focus, with a note; load that run (its offline copy, or run it again) to split them.

**A step is only ever open once in a hunt.** Values any run of the hunt analyzed or started from (targets, and the
certificates a run came from) are never suggested again, as a *Start here* step or as a lead, so *Run suggested hunt*
can't go round in circles.

**Hunt status** (above the map):

| Status | When |
| --- | --- |
| Growing | The newest run still adds domains or new kinds of alerts |
| Converging | The newest run added 2 new domains or fewer and no new kind of alert: following more steps is unlikely to find much |
| Done | No open step is left, or a hunt limit is reached (*Hunt limits*: runs deep, default 4; domains in the hunt, default 100). Runs of the same targets again (*Run again*) add no depth |
| Closed | You closed the hunt with a verdict |

When the hunt is converging or done, the *Hunt result* opens and *Run suggested hunt* says so (you can still run
more). **Highlight alerts** picks a severity (*High or worse*) or an alert type: the runs with such alerts and the
open steps they name are outlined in red, the rest dimmed, so you can see whether a detection runs through the whole
hunt or one branch.

**Map options** (next to *Highlight alerts*) set how the map looks, and stay set while you work:

- **Show on the map**: each run's box always shows its targets, when it ran, how many domains and its alerts. You
  can add *New domains & alerts*, *Top alert types*, *BGP routing*, *Link to the start*, *Followed steps* and *Lookup
  details*. *BGP routing* (on by default) adds the run's announced prefixes, its origin networks and its BGP routing
  alerts with the worst severity (red when there are any). *Lookup details* shows the run's use case and window, its main collection options, the API queries it made and
  what led to it. The default is compact; add details as the hunt grows.
- **Open steps under the loaded run**: how many open steps to draw (default 6; other runs show at most 3; 0 hides
  them, and the list below the map still has them).
- **Layout**: *Auto* draws left to right up to 3 runs, then top to bottom with each run's open steps on its row, so a
  long hunt stays readable. *Left to right* and *Top to bottom* fix it.
- **Size**: *Fit* (default) draws the map at its own size, shrunk to the page when it is wider. *Fill width*
  stretches it to the page width, which makes a small hunt very large.

**Hunt result**: the **cluster** (the starting domains, and every domain the hunt found that shares a value with them,
with what links it), the **core indicators** (values two or more cluster domains share: the best detections to keep),
**alerts by type** across the hunt, and the runs (new domains, alerts, link to the start). Under it:

- **Close hunt**: a verdict (Malicious cluster, Suspicious, Benign, Inconclusive) and a note, kept with the hunt's
  first run; *Reopen* removes it.
- **Download hunt report (HTML)**: everything the hunt found, in full, as one page with no scripts and no network
  use (print it to PDF to share). It has:
  - the status, verdict, note and summary figures (runs, domains, cluster, core indicators, alerts per severity);
  - the **hunt map**, drawn into the page: one box per run with all its targets up to five (the rest under *Runs*),
    alerts and link to the start, and arrows labelled with what was followed. Left to right, or top to bottom from
    three runs deep;
  - **Runs**: each run's origin (the IrisQL or CertsQL query, or the hunt step) with every value it followed and
    every target, no "+N";
  - the **cluster** with risk scores and alerts, and the **core indicators** with the domains that share each;
  - **indicators by domain**: every IP, name server, MX, email, certificate, JA4X and hostname the runs recorded,
    core indicators in bold;
  - **alerts by type** (with the domains and ATT&CK technique) and **alert details**: every alert with its
    confidence, category and evidence;
  - the **open next steps** of the newest run.
- **Use in the case report**: opens Export & report with the result as the case report's summary.
- **Watch these domains**: adds the cluster as a watched target list (Runs → Compare & trends → Watched Lists).

Each run keeps its suggested steps when you analyze it or load it, so the map still shows a run's open steps after
you move on. Under the map, **Next steps from the loaded run** has, in order: **Alert decisions** (open, investigating, benign
and malicious alerts, domains marked malicious), **What to check next** (each with a button to the right page),
*Run suggested hunt…*, step chips to pick (one step: *Details*, *Analyze*, *Find in Iris*; several: *Run N picked
steps*), the **Suggested hunt** with each step's reasons, look-ahead and buttons, the leads set aside, and **More
leads (All pivots)**. *Runs of this hunt* picks a run for *Run again*, *Load offline copy* and
*Compare & trends*. The path to the loaded run is one short line: each run's first target and how many steps led
to it.

*Combined hunts* shows several hunts on one map. The hunts that share values with the loaded hunt are listed first,
with what they share (for example *shares 18 Certificate, 12 IP, 5 Web Tracker*), and the two closest are picked with
it; single runs count as hunts too. Each hunt is drawn in its own frame, top-down, side by side; dashed cyan lines join
runs of different hunts that recorded the same certificate, IP, name server, tracker or email, or analyzed the same
domain (*18 Cert · 12 IP*; the strongest three per pair of hunts). Under the map: the *Highlight alerts* filter,
*Connections between the hunts* (each link with its values), a **Combined result** (the cluster linked to any of the
hunts' starting points, core indicators, alerts by type, *Watch these domains*) and **Join them into one hunt**: pick
the main hunt and each other hunt's first run is attached to the run of the main hunt it shares the most with (a
bold purple arrow, *Joined: shares …*). From then on they are one hunt everywhere. On *This hunt*, **Join to another
hunt** does the same for the hunt shown, and each joined run has **Detach**, which gives it back its own hunt.

*All investigations* is the timeline of every saved run on its target list's lane: arrows where a run was started
from a lead in another, dashed lines where two target lists found the same IP, name server, certificate, JA4X,
tracker or email on different domains. Click a run for its links and actions.

*All pivots* ranks every value in the run's Iris Investigate records that other domains can share (IPs, name
servers, emails, registrant details, certificates, trackers) by how many domains share it in Iris; see
[All pivots](USAGE.md#all-pivots) in Usage.

After **Analyze**, a run that continues a hunt (started from a lead, or *Add the new run to the hunt of the loaded
run*) opens on *Hunt map → This hunt* instead of the Summary.

### Watched target lists

*Watch this list* (Summary → *What's new since the last analysis*) saves the run's target list in `dt_settings.json`.
**Runs → Compare & trends → Watched Lists** reruns it with *Run now*; the Summary then lists what is new since the list's last run:
alerts and IPs, name servers, MX hosts, certificates, web trackers and hostnames. (Hostnames are compared from the
second run after this version; older runs did not record them.)

### Confirmed indicators

*Confirmed indicators* (on **Export & report**) lists the indicators of what you marked
Malicious: every IOC of a domain with a Malicious verdict or a Malicious alert, and the artifacts (IPs, domains,
certificate hashes) in those alerts' evidence. Download them as CSV, a MISP event (JSON import format) or a STIX 2.1
bundle; the section also lists the Iris Investigate searches for the strong and useful pivots those domains have.

## Pages

The top menu has plain links to **Start**, **IrisQL**, **CertsQL**, **Runs** and **Evidence**, and dropdowns:
**Overview** (Summary, Domain profile, Alerts), **Infrastructure** (DNS & Hosting, VPNDB, Tor network, BGP, CNAME
Chains, Certificates), **Hunt** (Hunt map, Hostname Inventory, Subdomain Triage), **Data** (Saved datasets, Export & report,
Data sources) and **Settings** (Settings, Account, Documentation). Red and yellow banners at the top of every page
warn when a product this app uses has used up (or nearly) its monthly quota or expires soon. With *Analyst mode*
off, Hunt (including the Hunt map with *What to check next*) and Evidence are left out.

| Page | Highlights |
| --- | --- |
| Start | A **Targets** box with **Analyze**, links to *Find targets with IrisQL*, *Find targets with CertsQL* and *Runs & Sightings*; use cases (triage, related infrastructure, C2 hunting, subdomain takeover, phishing & lookalikes, monitoring, reporting, checking IP addresses for VPN, proxy and Tor): each sets the collection options and window and gives a plan; the last run |
| IrisQL | Examples to start from, an IrisQL query on Iris Investigate (the editor suggests fields, each field's operators and the value, and marks lines with a problem) and the same search as a DomainTools Python SDK command, curl and a Python script; results: matching domains (risk, dates, registrar, hosting, name servers, tags), their hosting IPs and a breakdown; tick domains and IPs, pick a use case and analyze them as a new run; *Watch this query* and *Watched queries* (check a saved query again for new domains only) |
| CertsQL | Examples to start from (dates counted from today), a CertsQL query on Certificate Search (same autocomplete as IrisQL, with dotted subfields), checked against the field catalog before sending, and the same search as a curl command and a Python script; results: a fingerprint card for each known or code-generated JA4X among them, matching certificates, the domains, IPs and hostnames they name and a breakdown; untick certificates to leave out, tick domains and IPs, pick a use case and analyze them as a new run. The ticked certificates go into the run (Source *CertsQL search*) for the domains they name, so the certificate that found a domain is in its analysis even when the domain's own certificate lookup does not return it |
| Runs | *Recent runs*: the newest saved runs as a timeline, one card per target list or a table (one row per target list, or every run with *Show all runs*; filter, alerts and new-alerts toggles), what changed, the risk trend and the indicators each run shares with other target lists; run again, load the offline copy or open it in *Compare & trends*. *Compare & trends*: run details, compare any two runs, trends, one domain across runs, watched lists, manage runs. *Indicator Sightings*: where an IP, domain, name server, MX, certificate hash, JA4X, tracker code or email was observed across saved runs and offline datasets, over time; with nothing entered, the indicators shared across your target lists. A shared indicator opens its sightings, a sighting picks its run (local files, no API query) |
| Summary | From the top: hunt trail and KPIs; every domain with its verdict, risk drivers and VPNDB exits (select one for its profile; Unicode form of internationalized domains); analysis details (linked counts, the VPNDB row: IPs checked, VPN / proxy, residential proxy and Tor exits; and the BGP row: IPs routed, prefixes, origin networks, routing findings, with a short description of who announces the hosting and the worst findings); linked domains; a short *Hunt* box (open alerts, steps and leads, with *Open the Hunt map*); top alerts (pick one to open Alerts filtered to it); run statistics (alerts by category, shared infrastructure, weekly activity, lifecycle, data health); what's new since the last analysis with *Watch this list*; the use-case plan with checkboxes; the lookups of the last collection |
| Domain profile | One domain: risk and DIF, why this score, your verdict, an action row (*Where else seen*, *Similar domains / IPs in IrisQL*, *Its certificates in CertsQL*, *Copy*), one card per source (registration and hosting from Iris Investigate, VPN / proxy / Tor verdicts of its IPs from VPNDB, BGP routing of its IPs from BGPDB: prefix, origin network and RPKI / IRR status, network age, routing findings), alerts, latest DNS records per type, CNAME chains, newest certificates, latest Domain History changes |
| Alerts | KPIs, risk radar, DIF table and decoder, alert heatmap and ATT&CK view, grouped alerts with related events and a triage status per group, detection reasons (with *Your Verdicts*), suppressions, run diff, DomainTools risk evidence; *Export detections, IOCs and reports* opens Export & report |
| VPNDB | Which VPN or proxy provider operates behind an IP, prefix or ASN (each tab opens with *How to read this*): domain → provider → exit flow, domain × category heatmap, providers, exit countries, exposure timeline against VPNDB's weekly history, Iris cross-check (domain count, pivot value, disagreements), neighbouring ranges and hosting networks, other domains on dedicated exits (DNSDB) with *Analyze*, CIDR address grids and range cards; select any IP for its full card (verdict, whole VPNDB answer, history, where the run saw it, Tor share) |
| Tor network | Network-wide Tor statistics provided through VPNDB (`/tor`): relays and exits, the networks and countries that carry Tor exit traffic, exit prefixes, and a warning when a network the run saw is among them, with *Seen as* (hosting from VPNDB / Iris; with BGPDB also origin, unauthorized origin, upstream / transit, neighbouring prefix) |
| BGP | BGP routing of the hosting IPs from BGPDB (each tab opens with *How to read this*): *Overview* (routing findings, each hosting IP with its prefix, usual origin, RPKI / IRR, RIR and Iris country, upstream; select one for every origin, AS path and network, as curl commands), *Routing map* (domain → prefix → origin network → upstream Sankey, unauthorized flows in red, and the AS paths towards a prefix as a graph), *Origin timeline* (each prefix and network on its own row, authorized green, unauthorized red), *Networks* (RIR registration, age and visibility of the origin and upstream ASes), *Neighbouring prefixes* (the /20 around each prefix: the run's own networks, others, unauthorized), *VPNDB match* (exits and their routing, networks that carry exits), *Responses* (every BGPDB answer, as curl) |
| DNS & Hosting | One-line VPNDB and BGP summaries, then four tabs (only the open one is drawn): *Timeline* (event scatter, lifespans, velocity, tempo), *Subdomains & IPs* (subdomains, IP clusters, Nexus overlap), *Web & TXT* (trackers, TXT fingerprints), *Campaign & hosting* (domain story timeline, infrastructure graph, clusters, hosting map, Domain ➔ ASN ➔ IP Sankey, CDN origin exposure, domain hopping) |
| CNAME Chains | Every CNAME with its target service, full chain and outcome (resolves, dead end, loop); per-hostname table with CNAME history; chains filled in on demand and read from the analyzed domain; chain map boxed per domain with optional one node per hostname; chase results grouped by chain, most hostnames first; cross-domain links and link map; reverse CNAME (RDATA) related domains for chain targets or typed names; chase selected or all hostnames, up to 10 DNSDB queries per domain per click |
| Certificates | Six tabs, only the open one drawn: *Overview* (the security & hygiene summary on top, then SAN sprawl, up to 15 certificates per domain and 12 SANs each with the rest grouped; Sankey flow; CA distribution; data sources; wildcards), *Self-Signed* (rated Critical to Low, with the reasons and what to do), *Validity & keys* (validity, keys, key reuse), *JA4X & C2* ([JA4X](#ja4x-how-certificates-were-generated): known tools, how common, pivot to CertsQL; bare-IP certificates), *Issuers & policies* (geography and organizations, EKU, policy OIDs, CAA) and *CT logs* |
| Hunt map | *This hunt*: the hunt's status (growing, converging, done, closed) and map (runs with what they added, their alerts, their BGP routing (prefixes, origin networks, routing alerts) and link to the start; open steps with their facts; done steps), an alert highlight, the hunt result (cluster, core indicators, alerts by type; close, report, watch), *Join to another hunt* / *Detach* and the loaded run's next steps; *Combined hunts*: several hunts on one map with the links between them, a combined result and *Join them into one hunt*; *All investigations*: every saved run over time, linked by leads and shared infrastructure; *All pivots*: every shared value in Iris Investigate (IPs, name servers, emails, registrant, certificates, trackers) ranked by how many domains share it, with *Analyze now* and *Find in Iris* |
| Hostname Inventory | Every hostname from certificates, passive DNS and certificate events, with lifecycle and flags (never resolved, no certificate, new, sensitive name), and each hostname's certificates with their hashes |
| Subdomain Triage | Subdomains ranked by phishing words, brands, embedded domains, punycode, random names and new / burst / never-resolved lifecycle, with shared platforms (pages.dev, workers.dev, ...) called out; focus the views on the picks |
| Evidence | *Records*: raw TXT, certificate, co-occurrence, Domain History and passive DNS records, and every VPNDB and BGPDB answer as received (select one to see it as tables; a BGPDB answer as one row per record, downloadable as NDJSON). *Lookup queries*: every lookup the run made as a reusable query (the IrisQL search the targets came from, CertsQL, DNSDB names and record types, including record-type lookups and CNAME chase steps, Iris domain lists, VPNDB endpoints and the IPs of each bulk request, BGPDB lookups as `bgpdbq` commands) and `domaintools` CLI / `bgpdbq` / curl command, in one table per tool, with the selected rows' queries and commands ready to copy |
| Saved datasets | Saved offline datasets: what each holds, *Load offline dataset* (re-analyze with no API calls), *Download hunt report (HTML)* of the hunt its run belongs to (no loading, no API query), rename and delete |
| Export & report | Case report (the run as one printable HTML page: summary, top alerts with evidence, risk, infrastructure, IOCs); confirmed indicators (CSV, MISP, STIX); detections, IOCs, STIX bundle and evidence report; IOCs, tables (detections, risk profiles, hostname inventory, CNAME chains, lookups) and raw records as CSV or NDJSON files (zipped with a manifest) for sharing; no charts |
| Data sources | The run in numbers and every lookup by source, target and status (including the IrisQL or CertsQL search a run's targets came from), Cached details (cache age, expiry, re-run with fresh lookups or the cache), certificate-input provenance |
| Settings | Tabs: *Collection options* (the next Analyze, or any use case or profile; create a custom profile), *Detection thresholds*, *Brands & allowlist* (brand watchlist, *Hunt lookalikes in IrisQL*, infrastructure allowlist), *Storage & cache* (cache lifetime, clear cache, retention of runs and offline datasets), *API credentials* (which source each key comes from, *Enter API keys*, *Show the welcome screen and disclaimer again*) |
| Account | Your DomainTools products with their quota, usage and expiry, and the API queries this app made |
| Documentation | These guides inside the app |

## A suggested triage workflow

1. Read the **Summary**, then open the **Hunt map** (Analyst mode) and work through *What to check next*. If the status line reports errors, open **Data
   sources** first; missing sources mean missing detections.
2. Check the **KPI banner** and the **Unique Infrastructure Profiles** count against the number of domains.
3. In the alert list, start with **Group by: Finding**, Severity *Critical* and *High*, Confidence *High* and *Medium*.
4. Expand a group and read **Related events** in time order; pivot on the **Artifact** column (certificate hashes, IPs).
5. Switch to **Group by: Campaign Cluster** to see which findings belong to one operator, and open **Hunt map → All
   pivots** for strong values the targets share; *Find in Iris* lists the operator's other domains.
6. Use **Decode DIF fingerprints** and the **Same DIF As** column to find look-alike setups that are not yet clustered.
   In **CNAME Chains**, filter on *Dead end* and the takeover-prone, dynamic DNS and free hosting service types,
   and chase the chains that are still *Not chased*.
7. Mark each group's status as you go (Benign with a note for known-good findings, or suppress them), follow the
   suggested hunt's steps and leads on the **Hunt map** with *Analyze*, then export the confirmed indicators, a STIX bundle, an evidence report or a case report.
   Check a new indicator against earlier investigations on **Runs → Indicator Sightings**.
8. Re-run later and use **Only first detected in this run** and **Changes Since Last Run** to focus on what changed.

## Limitations

- Detections are only as complete as the collected data: truncated passive DNS (result limits), missing risk scores
  or failed lookups reduce what the rules can see. The [Data sources](#data-sources) page shows these gaps.
- Severity and confidence are rule-based heuristics, not verdicts. Benign infrastructure (CDNs, large hosters,
  marketing platforms) can trigger medium-confidence rules; use the evidence and suppressions.
- Passive DNS query counts are attributed to each record's first-seen day, so volume anomalies are approximate.
- CNAME chains come from passive DNS, not live resolution: a *Dead end* means DNSDB never saw the name resolve (or
  not recently), which is strong evidence of a dangling CNAME but should be confirmed with a live lookup before
  reporting a takeover.
- DIF fingerprints and risk vectors summarize the primary certificate and the current window, not every certificate
  ever issued.
- VPNDB only knows the exits it measured or that public lists name: *Not observed* is not an all-clear, and it does
  not collect IPv6. Addresses it did not see itself but attributes from their range are *interpolated*, with lower
  confidence. Its history is weekly, so a domain that used an exit for a few days is matched to that week. The checks
  stop at the use case's budget (hosting IPs, full verdicts), so a run on many domains may leave IPs unchecked.
- International domains are looked up and stored in punycode (`xn--bcher-kva.de`). *Show international domains in
  Unicode* changes only how they are shown, so filters and searches still match the ASCII form; see
  [International domains](USAGE.md#international-domains).
