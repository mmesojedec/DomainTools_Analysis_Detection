# User Guide: Reading the Results

What the app shows and how to interpret it: alerts and their severity and confidence, every detection rule, the
MITRE ATT&CK mapping, Unified Risk scores, DIF fingerprints, infrastructure clusters, and run history. For setup,
credentials and running an analysis, see [Installation](INSTALLATION.md) and [Usage](USAGE.md).

Most of these explanations are also available inside the app: **Detection reasons** (next to the alert list) and
**Decode DIF fingerprints** (under the DIF table) open the same reference tables.

## Contents

- [How a run works](#how-a-run-works)
- [Analysis window](#analysis-window)
- [Data Source Status](#data-source-status)
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
- [Suppressions and exports](#suppressions-and-exports)
- [Hunting: triage status, leads and the hunt tree](#hunting-triage-status-leads-and-the-hunt-tree)
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
   and CIDR targets are looked up there as ranges. Where a passive DNS lookup stopped at its limit, record-type
   lookups fill in TXT, CAA and (when none came back) CNAME records, and the CNAME targets that point outside
   the collected data are [chased](#cname-chains) to their final addresses. Every lookup's outcome is recorded in
   [Data Source Status](#data-source-status), with the API queries it made. Independent sources run at the same
   time (see [Workflows](WORKFLOWS.md#collection-order)), and sources missing from the DomainTools account are
   skipped.
2. **Window.** Records are limited to the [analysis window](#analysis-window).
3. **Score gate.** Domains whose known DomainTools risk score is below **Min Risk Score** are skipped by the
   behavioral engine (an info box lists them). Domains Iris Investigate has no score for are still evaluated, with
   a warning. IP targets are always evaluated.
4. **Detect.** Every [detection rule](#detection-catalogue) runs per domain or IP on raw UTC timestamps. Then the
   cross-domain checks run: [infrastructure clusters and domain hopping](#infrastructure-clusters-and-domain-hopping),
   CNAME targets shared by several analyzed domains, and anonymizer exits several analyzed domains use (see
   [VPNDB anonymizer rules](#vpndb-anonymizer-rules)). A domain among the 10,000 most popular in Iris
   Investigate (its *popularity rank*) is far more likely legitimate: its Medium and Medium-High confidence alerts
   drop one step, and each alert's logic says so. High-confidence alerts are kept as they are.
5. **Merge.** Rules that run once per certificate or record can fire several times for one domain. These repeats
   are merged into **one alert per (domain, rule)**, keeping the worst severity's description, the best confidence
   and all the evidence. The *Occurrences* column shows how many were merged.
6. **Score.** [Unified Risk](#unified-risk-and-risk-vectors) and the [DIF](#dif-domain-infrastructure-fingerprint)
   are computed per domain from the alerts and telemetry.
7. **Save.** Live runs are saved to `dt_runs/` for [run history](#run-history-alert-lifecycle-and-trends);
   [suppressions](#suppressions-and-exports) are applied before anything is displayed.

## Analysis window

The window (sidebar, default *Last 30 days*) keeps only records **active** in it:

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

## Data Source Status

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
answered); Runs & Diffs keeps each run's total. When a run returned no data at all, a status panel with every lookup
is shown instead of the pages. A source whose DomainTools product the account does not have is listed as skipped.

## KPI banner

| KPI | Meaning |
| --- | --- |
| Max Digital Risk | Highest [Unified Risk](#unified-risk-and-risk-vectors) across the analyzed domains |
| High-Risk Domains | Domains with Unified Risk at or above **High-Risk Score Cutoff** (default 70) |
| Unique Infrastructure Profiles | Number of distinct DIF fingerprints. Fewer profiles than domains suggests shared infrastructure. |
| Primary Threat Driver | The risk vector with the highest average across domains |

## Unified Risk and risk vectors

Each domain gets six risk vectors (0–100), shown in the **Digital Risk Vector Profile** radar chart. Five are
built from the domain's alerts plus raw telemetry. "Max severity" is the highest
[severity weight](#severity) among the domain's alerts that match the listed techniques or names. Informational alerts
(*Short-Lived Certificate*) are left out: short certificate lifetimes never raise a risk score.

| Vector | Calculation (capped at 100) |
| --- | --- |
| Domain Risk Score | The DomainTools overall risk score (0 if unknown) |
| DNS Volatility | Max severity of T1568 / flux / rotation / parked / sinkhole alerts + 2 per distinct resolved IP (max +40) |
| Certificate Trust | Max severity of T1588.004 / T1573 / certificate / weak-key alerts + 40 if any certificate is self-signed + 40 if any key is weak |
| Email/Phish Posture | Max severity of T1583.002 / T1585.002 / phishing / SPF / mail alerts + 5 per distinct TXT / SPF / MX value (max +30) |
| App & C2 Footprint | Max severity of T1071 / T1008 / T1048 / bare-IP / payload alerts |
| Infra Sprawl | Max severity of T1584.001 / sprawl / nested / wildcard alerts + 2 per SAN of the largest certificate (max +50) |

**Unified Risk** = `min(100, max(base, 0.4 × base + 1.5 × average of the five behavioral vectors))`, where *base*
is the DomainTools risk score. It never falls below the DomainTools score, and rises when the domain's own
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
| Confidence / Severity | Show only these levels |
| Status | Show only alerts with these [triage statuses](#triage-status) |
| Layout | *Grouped* (default) or *Table* (one flat, sortable row per alert) |
| Group by | How alerts are grouped (below) |
| Only first detected in this run | Hide detections already seen in an earlier saved run that covered these domains. Disabled until such a run exists. |
| Detection reasons | Opens the reference: severity and confidence levels, alert columns, and every rule |

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

## Detection catalogue

Every rule, grouped by category. Threshold names (e.g. **Min Risk Score**, **DGA Entropy Score**) are the sliders
under *Settings → Detection thresholds*; see [Detection thresholds](#detection-thresholds) for
their defaults. **Detection reasons** in the app shows the same table with how often each rule fired in the
current run.

#### Certificates

| Detection | Severity | Confidence | MITRE ATT&CK | Fires when | Why it matters |
| --- | --- | --- | --- | --- | --- |
| ACME Certificate Sprawl | Medium-High | Low | T1588.004 (Obtain Digital Certificates) | More than 3 _acme-challenge names in passive DNS. | Mass automated certificate issuance supports fast setup of many hostnames. |
| Rapid Weaponization (Cert-to-DNS Gap) | High | Medium | T1588.004 (Obtain Digital Certificates) | Certificate issued within Cert-to-DNS Gap (Hours) of the first DNS record. | Certificate and DNS set up together point to scripted, disposable deployment. |
| Self-Signed Certificate Detected | High | High | T1573.002 (Encrypted Channel) | Certificate subject equals its issuer. | Common on C2 servers and malware panels; untrusted by browsers. |
| Short-Lived Certificate | Low (informational, not scored) | High | T1588.004 (Obtain Digital Certificates) | Certificate valid at most Short-Lived Certificate Max Validity (Days), e.g. Let's Encrypt's 6-day profile. | Context only: short lifetimes reflect good automation, so this is excluded from risk scores and DIF. |
| Mega-SAN Cluster (Bulk Infrastructure) | High | Medium | T1583.001 (Acquire Infrastructure) | One certificate covers at least Mega-SAN Min Root Domains registrable domains. | Bundling unrelated domains in one certificate links bulk-registered infrastructure. |
| Multi-IP Certificate (Shared C2 / Proxy Cluster) | High | Medium | T1008 (Fallback Channels) | Certificate for an IP target also lists other raw IPs. | Points to a cluster of C2 or proxy nodes sharing one certificate. |
| Bare-IP Certificate (C2 / Proxy Node) | Critical / Medium-High (public short-lived IP certificate) | High | T1008 (Fallback Channels) | Certificate common name or SAN contains a raw IP address. A publicly trusted, short-lived IP certificate (e.g. Let's Encrypt) is Medium-High with Low confidence. | Legitimate sites rarely certify bare IPs; C2 frameworks often do. |
| SSL Common Name (CN) Mismatch | Medium-High | Low | T1071.001 (Web Protocols / Shared C2) | Served certificate is issued to a different name. | Shared or reused certificates can expose hidden relationships or shared C2. |
| Pre-Certificate Staging (CT Log Only) | Low | Low | T1588.004 (Obtain Digital Certificates) | Certificate seen only as a CT log precertificate. | Shows infrastructure being prepared before it goes live. |
| CT Log Evasion / Missing SCTs | Medium-High | Medium | T1562.001 (Disable or Modify Tools) | Non-self-signed certificate without embedded Signed Certificate Timestamps. | Missing SCTs suggest an interception proxy or attempts to avoid CT monitoring. |
| Rogue Certificate Authority | Critical | High | T1552.004 (Private Keys) | Endpoint serves a certificate with CA signing capability (CA=True). | A host that can mint certificates enables traffic interception. |
| Non-Compliant Validity Window | Medium | High | T1588.004 (Obtain Digital Certificates) | Publicly trusted certificate valid longer than the CA/B Forum limit on its issue date: 398 days from 2020-09-01, 200 from 2026-03-15, 100 from 2027-03-15, 47 from 2029-03-15. | Browsers reject such certificates; typical of private or misconfigured CAs. |
| Deprecated Signature Algorithm | High | High | T1588 (Obtain Capabilities) | Certificate signed with MD5 or SHA-1. | Weak signatures can be forged and indicate outdated or attacker-made certificates. |
| Non-Public / Private CA Certificate | Medium | Medium | T1588.004 (Obtain Digital Certificates) | Issuer shows no sign of public trust (no SCTs, no CA/B policy, unknown CA). | Typical of internal CAs, interception proxies, or attacker-run infrastructure. |
| CAA Mismatch (CA Trust Unverified) | Medium | Low | T1588.004 (Obtain Digital Certificates) | Issuer not allowed by the domain's CAA policy, but public trust of the CA is unknown. | Possible CAA breach that needs confirmation. |
| Wildcard Issuance Forbidden by CAA Policy | Critical | High | T1588.004 (Obtain Digital Certificates) | Publicly trusted wildcard certificate although CAA forbids wildcards. | Issuance against the owner's policy points to mis-issuance or account compromise. |
| Unauthorized CA Certificate Issuance (CAA Breach) | Critical | High | T1588.004 (Obtain Digital Certificates) | Publicly trusted certificate from a CA the CAA policy does not authorize. | Strong sign of mis-issuance or a hijacked domain. |
| Suspicious CAA Stripping / Evasion | High | Low | T1562.001 (Disable or Modify Tools) | Unauthorized certificate issued within 90 days after CAA records disappeared. | Removing CAA before issuing is a way to bypass the owner's CA restrictions. |
| Wildcard Infrastructure Sprawl | High | Medium | T1584.001 (Compromise Infrastructure: Domains) | Wildcard certificate bundling 5 or more names. | Supports rotating subdomains for phishing or C2 without new certificates. |
| Wildcard Certificate Observed | Low | High | T1588.004 (Obtain Digital Certificates) | Wildcard certificate with fewer than 5 names. | Common for legitimate hosting; new hostnames under it never appear in CT logs. |
| Suspicious Domain Validation (DV) | Medium | Low | T1588.004 (Obtain Digital Certificates) | DV certificate on a domain with risk score above Suspicious DV Min Risk Score. | DV certificates are free and instant, so they are the default for abusive sites. |
| Weak Cryptographic Key Material | High | High | T1588 (Obtain Capabilities) | RSA key below 2048 bits or EC key below 224 bits. | Weak keys are breakable and rare on maintained infrastructure. |
| Certificate Churn (Ephemeral SSL) | High | Medium | T1588.004 (Obtain Digital Certificates) | At least Cert Churn Min Early Replacements within Cert Churn Window (Days): certificates reissued for the same names while the previous one still had over half its validity left. Scheduled renewals of short-lived certificates do not count. | Replacing valid certificates early accompanies disposable or evasive infrastructure. |

#### Correlation

| Detection | Severity | Confidence | MITRE ATT&CK | Fires when | Why it matters |
| --- | --- | --- | --- | --- | --- |
| CNAME Link Between Analyzed Domains | Medium-High | Medium | T1583.001 (Acquire Infrastructure: Domains) | CNAME chains connect two or more analyzed domains: a name of one analyzed domain reached from another, or a name outside them all that several reach (CDNs and shared final addresses left out). Confidence is High for a CNAME into another analyzed domain, Low when every shared name is a known service (hosting, takeover-prone, tunnel). | A dedicated proxy or host, or one domain aliasing into another, is a strong operator link. |
| Shared Web Tracker Fingerprint | High | High | T1583.001 (Acquire Infrastructure) | The same analytics / tag manager ID appears on other analyzed domains. | Shared tracker IDs tie domains to the same operator. |
| Shared Infrastructure Cluster | High (strong link) / Medium-High | High | T1583.001 (Acquire Infrastructure: Domains) | Linked to other analyzed domains by a shared certificate, key, or tracker (strong), or by IP plus name server. Confidence High for strong links, otherwise Medium. | Shared infrastructure reveals campaigns run by one operator. |
| Domain Hopping on Shared IP | Medium-High | Medium | T1583.001 (Acquire Infrastructure: Domains) | A new domain appears on an IP within Domain Hopping Gap (Days) after the previous one went dark. Confidence High with 2+ hops. | Typical takedown evasion: the operator moves to a fresh domain on the same server. |

#### DNS Behavior

| Detection | Severity | Confidence | MITRE ATT&CK | Fires when | Why it matters |
| --- | --- | --- | --- | --- | --- |
| Parked-to-Weaponized | Critical | Medium | T1583.001 (Acquire Infrastructure) | Dormant longer than Parked Dormancy (Days), then 3+ DNS changes within 48 hours. | Aged domains are bought or reactivated to evade new-domain reputation checks. |
| Rapid IP Rotation (Fast-Flux) | High | Medium | T1568.001 (Fast Flux DNS) | At least Rapid IP Rotation Event Count distinct IPs within 7 days. Confidence drops to Low when every IP belongs to a CDN. | Rotating IPs hide the real hosting and resist takedowns. |
| Multi-Network Fast-Flux (ASN-Diverse) | High | High | T1568.001 (Fast Flux DNS) | Non-CDN IPs across at least Fast-Flux Min Distinct Networks ASNs or prefixes within 7 days. | Spreading across networks is typical of botnet-hosted flux, not CDNs. |
| Sinkhole / Loopback Resolution | Medium | High | T1568.001 (Dynamic Resolution) | A or NS record points to 127.0.0.1, 0.0.0.0, or a known sinkhole. | Usually means the domain was taken over by researchers or law enforcement after abuse. |
| Anomalous TXT Payload | High | Low | T1071.004 (DNS C2) | TXT record longer than Anomalous TXT Length with almost no spaces. | Long encoded TXT data is a classic DNS tunneling / C2 channel. |
| Flash/Burst Campaign | Critical | Medium | T1071.004 (App Layer Protocol: DNS) | Over 1,000 queries on a record alive 7 days or less, above pDNS Burst Density. | Short, intense query bursts match spam blasts and botnet check-ins. |
| Query Volume Anomaly | Medium | Low | T1071.004 (App Layer Protocol: DNS) | Daily pDNS volume with a robust z-score above Query Volume Anomaly (100+ queries). | Sudden traffic spikes point to campaign activity; counts are approximate. |
| Deeply Nested Subdomains | High | Low | T1584.001 (Compromise Infrastructure) | Hostnames 3 or more labels deeper than the domain. | Deep nesting is used for domain shadowing on compromised DNS accounts. |
| CNAME Retargeted to Another Provider | Medium | Low | T1584.001 (Compromise Infrastructure: Domains) | A hostname's current CNAME points to a different registrable domain than its earlier one, and the new target is external and not a CDN. | Repointed subdomains are how takeovers and compromised DNS accounts show up; also normal during migrations, so check the new provider. |
| Long CNAME Chain / Loop | Medium (Medium-High for a loop) | Low | T1090 (Proxy) | A current CNAME chain of at least Long CNAME Chain Min Hops CNAMEs, a chain stopped at the step limit, or a loop. | Layered redirects hide the final hosting and let operators swap it without touching the visible name. |

#### Domain Name

| Detection | Severity | Confidence | MITRE ATT&CK | Fires when | Why it matters |
| --- | --- | --- | --- | --- | --- |
| DGA / High Entropy Domain | Medium-High | Low | T1568.002 (Dynamic Resolution: DGA) | Domain label of 10+ characters with Shannon entropy above the DGA Entropy Score threshold. | Algorithmically generated names are used by malware to find C2 servers. |

#### Email

| Detection | Severity | Confidence | MITRE ATT&CK | Fires when | Why it matters |
| --- | --- | --- | --- | --- | --- |
| High-Risk Mail Provider | Medium | Low | T1585.002 (Acquire Email Accounts) | MX records (passive DNS, or the current MX in Iris Investigate) point to an anonymous, offshore, or temporary mail provider. | Disposable mail backends are common in phishing and fraud operations. |
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

#### Lookalike / Brand

| Detection | Severity | Confidence | MITRE ATT&CK | Fires when | Why it matters |
| --- | --- | --- | --- | --- | --- |
| Homoglyph / IDN Brand Impersonation | Critical | High | T1583.001 (Acquire Infrastructure: Domains) | Domain renders like a protected brand using look-alike characters. | Built to deceive users visually; strongly associated with phishing. |
| Typosquatting Lookalike | High | Medium | T1583.001 (Acquire Infrastructure: Domains) | Small edit distance from a protected brand domain. | Catches mistyped traffic and lends credibility to phishing. |
| Combosquatting (Brand + Keyword) | High (Medium without a risky keyword) | Medium | T1583.001 (Acquire Infrastructure: Domains) | Brand combined with words such as login, secure, support. | Brand + keyword names are the most common phishing domain pattern. |
| Brand in Subdomain | Medium-High | Medium | T1566.002 (Phishing: Spearphishing Link) | Protected brand appears as a subdomain of an unrelated domain. | Makes phishing links look legitimate at a glance. |
| Brand Name on Alternate TLD | Low | Low | T1583.001 (Acquire Infrastructure: Domains) | Exact brand name registered on another TLD. | May be defensive or third-party; watch for activation. |
| IDN / Punycode Domain | Low | Low | T1583.001 (Acquire Infrastructure: Domains) | Domain uses internationalized (punycode) characters. | Context for homoglyph abuse; common and benign in many languages. |

#### Registration & Lifecycle

| Detection | Severity | Confidence | MITRE ATT&CK | Fires when | Why it matters |
| --- | --- | --- | --- | --- | --- |
| Parked Domain (Parking Name Servers) | Low | High | T1583.001 (Acquire Infrastructure: Domains) | Domain is or was delegated to parking name servers. | Context: parked domains can be sold and weaponized later. |
| Parking Exit / Reactivation | High | Medium | T1583.001 (Acquire Infrastructure: Domains) | Domain left parking name servers and gained live A/AAAA/MX records within 7 days. | Reactivation of a parked domain often marks the start of malicious use. |
| Newly Registered Domain | Medium | High | T1583.001 (Acquire Infrastructure: Domains) | Created within Newly Registered Domain Age (Days). | Most malicious domains are used within days of registration. |
| Newly Registered & Weaponized Domain | High | High | T1583.001 (Acquire Infrastructure: Domains) | Newly registered and already resolving, mailing, or serving certificates. | A brand-new domain that is already operational is a strong abuse signal. |

#### Web & Content

| Detection | Severity | Confidence | MITRE ATT&CK | Fires when | Why it matters |
| --- | --- | --- | --- | --- | --- |
| IPTV / Stream Distribution Endpoint | High | Medium | T1584.001 (Compromise Infrastructure) | Subdomains such as m3u., stream., xtream., panel. in passive DNS. | Typical of illegal IPTV / restreaming infrastructure. |
| Live Pirate Streaming Panel Detected | Critical | High | T1584.001 (Compromise Infrastructure) | Website returns HTTP 200 with an IPTV panel title (Xtream, Stalker, ...). | Confirms an active illegal streaming management panel. |
| Cross-Domain Redirect | Medium | Medium | T1608.005 (Stage Capabilities: Link Target) | Website redirects to a different registrable domain. | Redirect chains are used for cloaking and traffic distribution. |

**Notes**

- **Lookalike rules** need a brand watchlist: the brands you protect, entered on *Settings → Brand watchlist*. IDN /
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
  with Tor exits, or on a network carrying a real share of Tor exit traffic (0.5 % or 10+ exit addresses).
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

## MITRE ATT&CK mapping

Each rule maps to one ATT&CK technique; the tactic is derived from the technique ID. The **MITRE ATT&CK** tab of the
alert overview and the *ATT&CK Technique* grouping both use this mapping. **Rules** is how many detection rules map to
the technique, not how many alerts fired; the in-app **MITRE ATT&CK** tab shows alert counts for the current run.

| Tactic | Technique | Name(s) used by rules | Rules |
| --- | --- | --- | --- |
| Resource Development | T1583.001 | Acquire Infrastructure; Acquire Infrastructure: Domains | 20 |
| Resource Development | T1583.003 | Acquire Infrastructure: Virtual Private Server | 2 |
| Resource Development | T1583.006 | Acquire Infrastructure: Web Services | 1 |
| Resource Development | T1584.001 | Compromise Infrastructure; Compromise Infrastructure: Domains | 7 |
| Resource Development | T1585.002 | Acquire Email Accounts | 1 |
| Resource Development | T1588 | Obtain Capabilities | 2 |
| Resource Development | T1588.004 | Obtain Digital Certificates | 12 |
| Resource Development | T1608.005 | Stage Capabilities: Link Target | 1 |
| Initial Access | T1566.002 | Phishing: Spearphishing Link | 1 |
| Defense Evasion | T1562.001 | Disable or Modify Tools | 2 |
| Credential Access | T1552.004 | Private Keys | 1 |
| Command and Control | T1008 | Fallback Channels | 2 |
| Command and Control | T1071.001 | Web Protocols / Shared C2 | 1 |
| Command and Control | T1071.004 | App Layer Protocol: DNS; DNS C2 | 3 |
| Command and Control | T1090 | Proxy | 1 |
| Command and Control | T1090.002 | Proxy: External Proxy | 7 |
| Command and Control | T1090.003 | Proxy: Multi-hop Proxy | 2 |
| Command and Control | T1568 | Dynamic Resolution | 1 |
| Command and Control | T1568.001 | Dynamic Resolution; Fast Flux DNS | 3 |
| Command and Control | T1568.002 | Dynamic Resolution: DGA | 1 |
| Command and Control | T1573.002 | Encrypted Channel | 1 |

Most domain-infrastructure behavior falls under **Resource Development** (the adversary acquiring and preparing
domains, servers and certificates), with **Command and Control** for resolution, tunneling and proxy behavior.

## Infrastructure clusters and domain hopping

### Clusters

Analyzed domains are linked when they share infrastructure:

| Link | Artifacts |
| --- | --- |
| Strong | The same certificate, public key or web tracker ID |
| Moderate | Two different weak artifact types together, from: the same IP, the same name server, the same CNAME target |

Linked domains are joined into clusters (C1, C2, ...). A cluster is **Strong** if any strong artifact links it.
CDN IPs, private IPs, large managed DNS providers and parking name servers are ignored, so shared CDNs do not create
false clusters. Each member gets a *Shared Infrastructure Cluster* alert, and the *Campaign Cluster* grouping turns
each cluster into one incident. The **DNS & Hosting** page (campaign & hosting part) shows the clusters and an infrastructure
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
| Lookup failed | A DNSDB lookup failed (see Data Source Status) |
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
| Min Risk Score | 70 | 0–100 | DomainTools Risk | Domains with a known DomainTools risk score below this value are skipped by the behavioral engine. Domains without a risk score are still evaluated. |
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
- **Runs & Diffs** page (*Manage Data → Runs & Diffs*, titled *Previous Runs & Comparison*). The Start page's **Recent runs** (under the IrisQL / CertsQL links; click *Show the last 10 runs*) lists the newest saved runs in a table (time, targets, window, use case, alerts, whether an offline copy was saved). Click a row to pick a run (the newest is picked at first); under the table, **Run again** (a new live run with the same use case, analysis window and collection options; runs saved before options were recorded use the current ones), **Load offline copy** (the newest offline dataset saved from that run, re-analyzed with no API calls; greyed out when none was saved) and **Open in Runs & Diffs** (this page, on that run):
  - **Run Details:** one run's alerts, risk and DIF.
  - **Compare Runs:** any two runs; new, resolved and persisting alerts, infrastructure changes, and risk / DIF changes.
  - **Trends:** detections per run by severity, Unified Risk per domain with DIF-change markers, and infrastructure counts per run.
  - **Domain History:** one domain across every saved run that included it, with a detection lifecycle (first /
    last detected, active in the latest run).
  - **Hunt Tree:** every hunt, from its first run to each run started from a lead ([below](#leads-and-the-hunt-tree)).
  - **Watched Lists:** the target lists you watch, each with *Run now* ([below](#watched-target-lists)).
  - **Manage Runs:** name and annotate runs, export as JSON, delete (with confirmation), and set retention (default 10 per target list).
- Runs saved by earlier versions show in a reduced *legacy* format (no severity, risk or DIF).
- **Offline Datasets** has its own page, *Manage Data → Offline Datasets*: see [Usage](USAGE.md#offline-datasets).

## Suppressions and exports

- **Suppressions** (Alerts page → *Manage Suppressions*, or *Suppress N alert(s)* in a group) hide a threat type for one
  domain or for all domains (`*`), with a note. Suppressed alerts are excluded from the alert list, KPIs, exports and
  saved runs, and can be reviewed and removed in the same panel. They are stored in `dt_suppressions.json`.
- **Exports** (Alerts page → *Export Detections, IOCs & Report*): detections follow the current alert filters and
  exclude suppressed alerts; indicators cover the selected domains and the analysis window.

  | Export | Contents |
  | --- | --- |
  | Detections (CSV) | Every alert column except the structured evidence |
  | IOCs (CSV / JSON) | Target domains, resolved IPs (with CDN notes), name servers and certificate hashes, with source and first / last seen |
  | STIX 2.1 Bundle | The indicators and detections as STIX 2.1 objects |
  | Evidence Report (HTML / Markdown) | Risk overview with DIF, detections by severity, infrastructure clusters, indicators, and each detection's evidence |

  For a manager or a takedown request, the **Case report** at the top of *Data Export* is the short version: one
  printable HTML page (print it to PDF) with your summary, the run at a glance, the most severe alerts with their
  evidence, risk by domain, an infrastructure snapshot (registrar, dates, IPs with ASN and country, name servers,
  MX) and the indicators. It contains no scripts and loads nothing from the internet.

## Hunting: triage status, leads and the hunt tree

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
same domains shows what was already reviewed. The Summary's **Hunt status** counts them, *What to check next* only
uses the open alerts (New and Investigating), and the alert filters and tables show the status.

### Risk drivers

*Risk drivers* (Summary) and *Why this score* (Domain profile) split the [Unified Risk](#unified-risk-and-risk-vectors)
into its parts, largest first: 0.4 × the DomainTools risk score and 0.3 × each risk vector, with the most severe alert
behind that vector. When the DomainTools score alone is higher than the telemetry score, it sets the score and is the
only driver.

### Leads and the hunt tree

**Leads to follow** on the Summary are the strongest values of [Pivot Ranking](#pages): shared by a few hundred
domains or fewer in Iris (values two or more of your domains share come first). Each lead has:

- **Analyze**: replaces the sidebar targets with the value (IPs, certificates, redirect domains) and runs Analyze
  right away with the current collection options;
- **Find in Iris**: one Iris Investigate search for the domains that share the value; they open on Pivot Ranking,
  where *Analyze the top 25 as a new run* analyzes the highest-risk ones.

Self-signed certificate cards (Certificates → Self-Signed) offer the same: *Analyze its domains* (the certificate as
a `sha256:` / `sha1:` input) and *Find in Iris* (by SHA-1).

A run started this way remembers the run it came from and what led to it. The Summary shows the **hunt trail**
(first run → … → this run), and **Runs & Diffs → Hunt Tree** shows every hunt as a tree, with *Analyze again* to rerun a
branch.

### Watched target lists

*Watch this list* (Summary, *What's new since the last analysis*) saves the run's target list in `dt_settings.json`.
**Runs & Diffs → Watched Lists** reruns it with *Run now*; the Summary then lists what is new since the list's last run:
alerts and IPs, name servers, MX hosts, certificates, web trackers and hostnames. (Hostnames are compared from the
second run after this version; older runs did not record them.)

### Confirmed indicators

*Confirmed indicators* (Alerts page, and on top of **Data Export**) lists the indicators of what you marked
Malicious: every IOC of a domain with a Malicious verdict or a Malicious alert, and the artifacts (IPs, domains,
certificate hashes) in those alerts' evidence. Download them as CSV, a MISP event (JSON import format) or a STIX 2.1
bundle; the section also lists the Iris Investigate searches for the strong and useful pivots those domains have.

## Pages

The top menu groups the pages: **Start**, **IrisQL**, **CertsQL**, **Sightings**, **Overview** (Summary, Domain profile, Alerts),
**Infrastructure** (DNS & Hosting, VPNDB, Tor network, CNAME Chains, Certificates), **Hunt** (Pivot Ranking, Hostname Inventory,
Subdomain Triage), **Evidence** (Raw Records, Lookup Queries), **Manage Data** (Save offline copy, Offline Datasets, Data Export, Runs & Diffs),
**Data sources**, **Settings**, **Account** and **Help**. Red and yellow banners at the top of every page warn when a product this app uses has used up (or nearly) its monthly quota or expires soon. With *Analyst mode* off, Hunt,
Raw Records and Lookup Queries are left out.

| Page | Highlights |
| --- | --- |
| Start | Use cases (triage, related infrastructure, C2 hunting, subdomain takeover, phishing & lookalikes, monitoring, reporting): each sets the collection options and window and gives a plan; Recent runs (the last 10 runs: run again with the same options, load their offline copy, open in Runs & Diffs) |
| IrisQL | Examples to start from, an IrisQL query on Iris Investigate (the editor suggests fields, each field's operators and the value, and marks lines with a problem) and the same search as CLI, curl and SDK code; results: matching domains (risk, dates, registrar, hosting, name servers, tags), their hosting IPs and a breakdown; tick domains and IPs, pick a use case and analyze them as a new run |
| CertsQL | Examples to start from (dates counted from today), a CertsQL query on Certificate Search (same autocomplete as IrisQL, with dotted subfields), checked against the field catalog before sending, and the same search as curl and Python code; results: matching certificates, the domains, IPs and hostnames they name and a breakdown; untick certificates to leave out, tick domains and IPs, pick a use case and analyze them as a new run |
| Sightings | *Indicator Sightings*: where an IP, domain, name server, MX, certificate hash, tracker code or email was observed across saved runs and offline datasets (local files, no API query); open the run, load the dataset or analyze the indicator |
| Summary | KPIs, hunt trail, every domain with its verdict, risk drivers and VPNDB exits (select one for its profile; Unicode form of internationalized domains), analysis details (linked counts, and the VPNDB row: IPs checked, VPN / proxy, residential proxy and Tor exits), top alerts, hunt status, the use-case plan with checkboxes, *What to check next* with a button to the right page (filtered where useful), leads to follow, linked domains, run statistics (alerts by category, shared infrastructure, weekly activity, lifecycle, data health), what's new since the last analysis and *Watch this list* |
| Domain profile | One domain: risk and DIF, why this score, your verdict, one card per source (registration and hosting from Iris Investigate, VPN / proxy / Tor verdicts of its IPs from VPNDB), alerts, latest DNS records per type, CNAME chains, newest certificates, latest Domain History changes |
| Alerts | KPIs, risk radar, DIF table and decoder, alert heatmap and ATT&CK view, grouped alerts with related events and a triage status per group, detection reasons, suppressions, run diff, exports, confirmed indicators, DomainTools risk evidence |
| VPNDB | Which VPN or proxy provider operates behind an IP, prefix or ASN (each tab opens with *How to read this*): domain → provider → exit flow, domain × category heatmap, providers, exit countries, exposure timeline against VPNDB's weekly history, Iris cross-check (domain count, pivot value, disagreements), neighbouring ranges and hosting networks, other domains on dedicated exits (DNSDB) with *Analyze*, CIDR address grids and range cards; select any IP for its full card (verdict, whole VPNDB answer, history, where the run saw it, Tor share) |
| Tor network | Network-wide Tor statistics provided through VPNDB (`/tor`): relays and exits, the networks and countries that carry Tor exit traffic, exit prefixes, and a warning when one of the run's hosting networks is among them |
| DNS & Hosting | A one-line VPNDB summary, then infrastructure & DNS tracking (event scatter, heatmap, lifespans, tempo, subdomains, IP clusters, Nexus overlap, trackers, TXT fingerprints), then campaign & hosting intel (domain story timeline, infrastructure graph, clusters, hosting map, Domain ➔ ASN ➔ IP Sankey, CDN origin exposure, domain hopping) |
| CNAME Chains | Every CNAME with its target service, full chain and outcome (resolves, dead end, loop); per-hostname table with CNAME history; chains filled in on demand and read from the analyzed domain; chain map boxed per domain with optional one node per hostname; chase results grouped by chain, most hostnames first; cross-domain links and link map; reverse CNAME (RDATA) related domains for chain targets or typed names; chase selected or all hostnames, up to 10 DNSDB queries per domain per click |
| Certificates | SAN sprawl (up to 15 certificates per domain and 12 SANs each, the rest grouped), Sankey flow, self-signed certificates (rated Critical to Low, with the reasons and what to do), validity, keys, reuse, CAA audit, CT logs, bare-IP certificates |
| Pivot Ranking | Every shared value in Iris Investigate (IPs, name servers, emails, registrant, certificates, trackers) ranked by how many domains share it; add values to the targets or find their domains in Iris |
| Hostname Inventory | Every hostname from certificates, passive DNS and certificate events, with lifecycle and flags (never resolved, no certificate, new, sensitive name), and each hostname's certificates with their hashes |
| Subdomain Triage | Subdomains ranked by phishing words, brands, embedded domains, punycode, random names and new / burst / never-resolved lifecycle, with shared platforms (pages.dev, workers.dev, ...) called out; focus the views on the picks |
| Save offline copy | Saves the run on screen as an offline dataset (no API calls) and opens Offline Datasets with it selected, to give it a name |
| Offline Datasets | Saved offline datasets: what each holds, *Load offline dataset* (re-analyze with no API calls), rename, delete and how many are kept |
| Data sources | The run in numbers and every lookup by source, target and status (including the IrisQL or CertsQL search a run's targets came from), Cached details (cache age, expiry, re-run with fresh lookups or the cache), certificate-input provenance |
| Raw Records | Raw TXT, certificate, co-occurrence, Domain History and passive DNS records, and every VPNDB answer as received (select one to see it as tables) |
| Runs & Diffs | Previous Runs & Comparison: run details, compare any two runs, trends, per-domain history across target lists, hunt tree, watched lists, manage runs |
| Lookup Queries | Every lookup the run made as a reusable query (the IrisQL search the targets came from, CertsQL, DNSDB names and record types, including record-type lookups and CNAME chase steps, Iris domain lists, VPNDB endpoints and the IPs of each bulk request) and `domaintools` CLI / curl command, in one table per tool, with the selected rows' queries and commands ready to copy |
| Data Export | Case report (the run as one printable HTML page: summary, top alerts with evidence, risk, infrastructure, IOCs); confirmed indicators (CSV, MISP, STIX); IOCs, tables (detections, risk profiles, hostname inventory, CNAME chains, lookups) and raw records as CSV or NDJSON files (zipped with a manifest) for sharing; no charts |

## A suggested triage workflow

1. Start on the **Summary**: work through *What to check next*. If the status line reports errors, open **Data
   sources** first; missing sources mean missing detections.
2. Check the **KPI banner** and the **Unique Infrastructure Profiles** count against the number of domains.
3. In the alert list, start with **Group by: Finding**, Severity *Critical* and *High*, Confidence *High* and *Medium*.
4. Expand a group and read **Related events** in time order; pivot on the **Artifact** column (certificate hashes, IPs).
5. Switch to **Group by: Campaign Cluster** to see which findings belong to one operator, and open **Pivot Ranking**
   for strong values the targets share; *Find domains in Iris* lists the operator's other domains.
6. Use **Decode DIF fingerprints** and the **Same DIF As** column to find look-alike setups that are not yet clustered.
   In **CNAME Chains**, filter on *Dead end* and the takeover-prone, dynamic DNS and free hosting service types,
   and chase the chains that are still *Not chased*.
7. Mark each group's status as you go (Benign with a note for known-good findings, or suppress them), follow the
   **Leads to follow** with *Analyze*, then export the confirmed indicators, a STIX bundle, an evidence report or a case report.
   Check a new indicator against earlier investigations on **Sightings**.
8. Re-run later and use **Only first detected in this run** and **Changes Since Last Run** to focus on what changed.

## Limitations

- Detections are only as complete as the collected data: truncated passive DNS (result limits), missing risk scores
  or failed lookups reduce what the rules can see. [Data Source Status](#data-source-status) shows these gaps.
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
