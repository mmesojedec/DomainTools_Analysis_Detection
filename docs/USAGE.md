# Usage

How to run an analysis, work with offline datasets, and fix common problems. Install the app and set up credentials
first ([Installation](INSTALLATION.md)); to read the results, see the [User Guide](USER_GUIDE.md). For an overview of what each run collects and in which
order, see [Workflows](WORKFLOWS.md); for the investigations it supports, see [Use Cases](USE_CASES.md).

All guides can also be read in the app: **Help → Documentation** in the top menu, or the **Documentation** link at
the top of the sidebar (a new browser tab), with a topic tree on the left (every guide and its sections) and a search box that searches all guides at
once. Diagrams are drawn there; drawing them needs internet access (Mermaid is loaded from a CDN), and without it
their text is shown.

## Contents

- [The app at a glance](#the-app-at-a-glance)
- [Running an analysis](#running-an-analysis)
- [VPN, residential proxy and Tor (VPNDB)](#vpn-residential-proxy-and-tor-vpndb)
  - [CIDR ranges](#cidr-ranges)
- [Certificate inputs](#certificate-inputs)
- [IrisQL](#irisql)
- [CertsQL](#certsql)
- [Offline datasets](#offline-datasets)
- [Where local data is stored](#where-local-data-is-stored)
- [Troubleshooting](#troubleshooting)

## The app at a glance

The **menu at the top** groups every page; the **sidebar** holds what you need while working (targets, Analyze,
analysis window, timezone, view filters).

| Menu | Pages |
| --- | --- |
| **Start** | *Start*: pick a use case (see below) |
| **IrisQL** | *IrisQL*: find domains with an IrisQL query, then analyze the ones you pick |
| **CertsQL** | *CertsQL*: find certificates with a CertsQL query, then analyze the domains and IPs they name |
| **Overview** | *Summary* · *Domain profile* · *Alerts* |
| **Infrastructure** | *DNS & Hosting* · *VPNDB* · *CNAME Chains* · *Certificates* |
| **Hunt** | *Pivot Ranking* · *Hostname Inventory* · *Subdomain Triage* |
| **Evidence** | *Raw Records* · *Lookup Queries* |
| **Manage Data** | *Save offline copy*: saves the run on screen as an offline dataset and opens *Run History → Offline Datasets* to name it (see [Offline datasets](#offline-datasets)) · *Data Export* · *Run History* (saved runs, comparisons, trends, offline datasets) |
| **Data sources** | *Data sources*: how every lookup of the run went, the lookup cache, re-runs |
| **Settings** | *Settings*: collection options, use cases & profiles, detection thresholds, brand watchlist, lookup cache, API credentials |
| **Account** | *Account*: the DomainTools account of your API credentials and every product's limits, usage this month and today, and expiry (see [Account](#account)) |
| **Help** | *Documentation*: these guides |

Each page has its own address (e.g. `/cname`), so the browser's Back button and bookmarks work. What each page shows
is in [Pages](USER_GUIDE.md#pages).

- **Start** asks *What do you want to do?* Eight use cases: *Triage a suspicious domain*, *Map related
  infrastructure*, *Hunt C2 infrastructure*, *Subdomain takeover check*, *Phishing & lookalikes*, *Monitor
  changes*, *Check IP addresses (VPN, proxy, Tor)*, *Report & export evidence*. Each card shows its title, a short description and the **Analysis window** it sets in the sidebar (it
  filters what the pages show, not what is looked up). Expand **See more details** on a card for:
  - **Lookups per domain, with their limits**: every lookup a run with this use case makes, by source, and how much
    each one fetches, as saved on Settings. When you changed the use case there, a changed lookup shows the use
    case's own limit as *(default: …)*, and a lookup you turned off shows *off*. Lookups marked *only when the main
    lookup hit its limit* run only for busy domains.
  - **After Analyze, work through**: the pages to read, in order. They appear on the Summary as links with a
    checkbox each, so you can tick them off as you go (the bar shows how many are done).

  **Use this** only changes settings (the collection options and the window); enter the targets and click
  **Analyze**. Your own saved profiles are listed below the use cases. See [Use cases and
  profiles](#use-cases-and-profiles).
- **IrisQL** (next to Start in the menu) finds the targets for you: an IrisQL query lists the matching domains from
  Iris Investigate, and the ones you tick (and their IPs) are analyzed with the use case you pick. See [IrisQL](#irisql).
- **CertsQL** (after IrisQL) does the same from certificates: a CertsQL query lists the matching certificates, and
  the domains and IPs they name that you tick are analyzed. See [CertsQL](#certsql).
- **Summary** opens after every Analyze or dataset load. From top to bottom:
  - the **hunt trail** when this run was started from another run's lead (see [Hunting](USER_GUIDE.md#hunting-triage-status-leads-and-the-hunt-tree));
  - the risk numbers, then every **domain** with its verdict, open alerts and **risk drivers** (select one to open
    its profile; a **Unicode** column is added for internationalized domains; with VPNDB verdicts a **VPNDB** column
    says how many of its checked IPs are VPN, proxy or Tor exits and whose, e.g. `1 of 58 IPs: Residential proxy
    birdproxies`);
  - **Analysis Details**: alerts per severity, domains, IPs, ASNs, name servers, certificates, self-signed
    certificates, hostnames and passive DNS records, each with a link to the page that lists them (*Self-Signed tab*
    opens the Certificates page at that tab), and with VPNDB verdicts a **VPNDB** row:
    IPs checked, VPN / proxy exits, residential proxy exits and Tor relays / exits, with the exits listed in an
    expander (shared ones counted);
  - **Top alerts**: the ten most severe alerts with their triage status;
  - **Hunt status**: open, investigating, benign and malicious alerts, and the domains marked malicious;
  - the use-case plan, when the run was started from a use case;
  - **What to check next** (open critical alerts, the riskiest domain, alert categories, dead-end or unchased
    CNAMEs, changes since the last analysis, failed lookups), each with a button to the page that shows it, already
    filtered where that helps;
  - **Leads to follow**: the strongest pivots, each with *Analyze* (a new run on that value) and *Find in Iris*;
  - **Linked domains**: the infrastructure clusters in one sentence each;
  - **Run statistics**: alerts by category, the top shared hosting networks, registrars, name servers and
    certificate issuers, activity per week, lifecycle (newest domain, domains and certificates expiring within 30
    days) and data health;
  - **What's new since the last analysis**: new alerts and new IPs, name servers, MX, certificates, trackers and
    hostnames, with *Watch this list*.
- **Domain profile** shows one domain on one screen: risk and DIF, *Why this score*, your verdict on the domain,
  one card per source: **Registration** and **Hosting** (Iris Investigate: registrar and dates, current IPs with ASN,
  ISP and country, name servers) and **VPNDB** (which VPN or proxy provider operates behind each IP: every checked IP of the domain with
  where it was seen, category, provider, confidence, sharing, IOC value, Tor role, network and country, exits first),
  its alerts, latest DNS records, CNAME chains, newest certificates and latest Domain History changes, with links to
  the full pages.
- A one-line **status** at the top of every data page names the data (live run or offline dataset), the targets, the
  window and how the lookups went (from cache, errors, partial), with a link to *Data sources*. On a live run it also has **Save offline copy** (see [Offline datasets](#offline-datasets)).
- **Help → Documentation** opens these guides; each topic picked in the left tree (or with ← / →) opens at its top.
- **Analyst mode** (top of the sidebar, on by default): off shows a simpler set of pages for a quick review (no Hunt
  group, no Raw Records or Lookup Queries) and hides the record type filters.

### A typical session

1. **Start**: pick the use case that matches your question (optional), e.g. *Subdomain takeover check*.
2. **Sidebar**: enter the targets (domains, IPs or certificates), check the *Options* line (change them under
   *Settings* if needed) and click **Analyze**. Or choose *Offline dataset* and load a saved one. Don't have the
   targets yet? Choose **Data source → IrisQL** or **CertsQL** (or open them from the menu), search, and analyze the domains you pick.
3. **Summary** opens: read the key numbers, then work through **What to check next**; each button opens the page that
   shows it.
4. **Domain profile** for the domain that matters, then the detail pages it links to: **Alerts** for the evidence,
   **CNAME Chains** to chase chains, **Certificates**, **DNS & Hosting**.
5. Mark what you reviewed: a status per alert group on **Alerts**, a verdict per domain on its profile. Follow a lead
   with *Analyze* to start the next run of the hunt.
6. **Data Export** (and **Lookup Queries**) to hand the findings over, including the *Confirmed indicators* of what
   you marked Malicious; **Run History** next time, to see what changed.

### Use cases and profiles

- **Global defaults**: the collection options the app starts with. Each use case is the global defaults with a few
  changes that suit it.
- **Change a use case**: *Settings → Use cases & profiles*. Pick the use case, change its options or window, and
  **Save**. The Start page then applies your version until you click **Reset to default**. **Save and use now** also
  applies it to the next Analyze.
- **Custom profiles**: on the same tab, **Create a custom profile** with a name and a description, starting from the
  current collection options or from a use case. Change its options and **Save**. It appears on the Start page under
  *Your profiles*; **Delete profile** removes it.
- The tab shows, for the options you are editing, what a run looks up per domain and the limit of each lookup.
- Use case changes and profiles are saved in `dt_settings.json`. *Settings → Collection options* (what the next
  Analyze uses) lasts for the browser session; the sidebar names the selected use case and says *(options changed
  since)* when they no longer match it.

What each use case sets, the global defaults and every fixed limit are in the [Reference](REFERENCE.md#use-cases-and-profiles).

Change the analysis window or timezone in the sidebar at any point: every page is recalculated from the data already
collected, with no API calls.

## Running an analysis

The sidebar, top to bottom; collection options are on the **Settings** page.

### 1. Lookups

| Control | What it does |
| --- | --- |
| **Data source** | *Live lookups* opens the **Start** page and queries the DomainTools APIs for the targets you enter (only when you click it: leaving the IrisQL, CertsQL or Run History page switches the option back to *Live lookups* without moving you). *IrisQL* opens the IrisQL page, where an IrisQL query finds the targets first and the ones you pick are analyzed with live lookups (see [IrisQL](#irisql)); the option stays selected while you are on that page, and leaving it switches back to *Live lookups*. *CertsQL* does the same with the CertsQL page, where a CertsQL query finds certificates and the domains and IPs they name (see [CertsQL](#certsql)). *Offline dataset* opens **Manage Data → Run History → Offline Datasets**: pick a dataset and click **Load offline dataset** to re-analyze data saved from an earlier live run, with no API calls (leaving that page switches back to *Live lookups*). |
| **Targets: domains, IPs, or certificates** | One target per line. Defanged input (`hxxp`, `[.]`) and URLs are cleaned. Subdomains are analyzed at their apex domain (`vpn.example.com` → `example.com`); lookups still cover the subdomains. International domains can be typed in Unicode or punycode ([International domains](#international-domains)). IPv4 and IPv6 addresses go to every source; CIDR ranges (`104.21.59.0/24`) go to VPNDB only ([CIDR ranges](#cidr-ranges)). Certificate details (fingerprints, serials, and prefixed fields) are also accepted; see [Certificate inputs](#certificate-inputs). |
| **Save offline copy** | Also saves everything this run collects to `dt_offline/` for later re-analysis. Forgot to tick it? Click **Save offline copy** on the status line at the top of any page after the run. |
| **Show international domains in Unicode** | Shows punycode names (`xn--bcher-kva.de`) as Unicode (`bücher.de`) in every table, text and chart, on every page; also in *Offline dataset* mode. Display only: see [International domains](#international-domains). |
| **Analyze** | Collects data and runs the detection engine, then opens the Summary. With certificate inputs, it first shows [two review steps](#certificate-inputs): the searches, then the domains / IPs to analyze. |
| **Use case** / **Options** | The use case or profile picked on the Start page (*options changed since* when you changed them afterwards), and one line naming the collection options of the next run, with *Change collection options* (the Settings page). |
| **API credentials** | One line saying how many services have credentials; the full matrix, and a form to enter keys, is under *Settings → API credentials* (see [API Credentials panel](INSTALLATION.md#api-credentials-panel)). |

**Collection progress.** While Analyze runs, its status box shows a progress bar with the share done and the time
elapsed, and one line per lookup of the run (the lookups of the use case card). Finished lookups come first, in the
order they finished, then the running ones; the rest are listed under *Up next* until they start. Each line starts
with how much of it is done (**100%**, a running share such as **40%**, or **skipped**) and counts the lookups
done out of the total, how many are running right now, how many came from the lookup cache (with how old they are and when the first one expires), how many failed (after the
one retry), the records returned and how long it ran
(the certificate events, which run after passive DNS, do not count the wait in between). The TXT, CAA and CNAME supplements show how many domains needed them; when the
main passive DNS lookup already returned everything, they are skipped with *Not needed*. CT telemetry is skipped
when the certificate search found no certificates, IP pivots when there is no public, non-CDN hosting IP. Once
done, the Summary keeps the list in **Lookups of the last Analyze** (collapsed), with a table of every result that
came from the cache: lookup, target, when it was fetched, its age and when it expires; the Data sources page still has
every single lookup's status. Between the end of the collection and the first page, *Analyzing the collected
data* shows the steps that turn the lookups into the pages: the tables, the detection rules, the comparison with
earlier runs and the risk profiles. Domain History is usually the slowest lookup: it pages through up to 1,000
change events, 100 per request, and the API allows a limited number of Domain History requests per minute (20 on
a standard service level, about one every 3 s), so a domain with 1,000 changes takes about 30 s. Asking for pages
in parallel does not help: requests over the limit fail with HTTP 503. A cached run costs nothing.

**Collection options** (*Settings → Collection options*), grouped by data source. Picking a use case or profile on the
Start page sets them; changes here are kept for the browser session and apply to the next Analyze. Below the options,
the tab shows what the next Analyze looks up per domain and the limit of each lookup. The defaults below are the
global defaults:

| Section | Option | Default | What it does |
| --- | --- | --- | --- |
| Passive DNS | pDNS provider | DNSDB Scout | *DNSDB Scout* (DNSDB v2 REST API) or *Iris pDNS* (browser-authenticated Iris session, at most 500 records per query). |
| Passive DNS | DNSDB result limit per domain | 5,000 | Maximum passive DNS records per queried name. Each domain is looked up as `*.domain`, which returns the domain's own records and its subdomains. Only when that lookup hits the limit is the domain itself also looked up on its own, so its own records stay complete. Very large limits slow charts and tables and produce large offline datasets. |
| Passive DNS | Supplemental TXT lookup | On | One extra TXT-only pDNS query per domain (DNSDB `*.name/TXT`, plus `name/TXT` if that hits its limit; Iris `rrtype=TXT`). The main query's limit is often filled by A/NS/CNAME records before any TXT appears; this keeps TXT fingerprinting and the SPF / tunneling detections working. With DNSDB it only runs for domains whose main lookup hit its limit, since a complete main lookup already holds every TXT record. |
| Passive DNS | Latest TXT records per domain | 10 | How many TXT records the supplemental lookup keeps (latest by last-seen time). |
| Passive DNS | Supplemental CAA lookup | On | Queries each domain's CAA record directly, so the CAA verdict does not depend on the pDNS limit. With DNSDB it only runs for domains whose main lookup hit its limit; otherwise the main lookup already holds the CAA records. |
| Passive DNS | Supplemental CNAME lookup | On | Queries CNAME records of the domain and its subdomains (DNSDB `*.name/CNAME`, up to 5,000 records, plus `name/CNAME` if that hits its limit; Iris `rrtype=CNAME` in the same session) for domains whose main lookup hit its limit. Busy domains fill the limit with A / NS / SOA records and daily repeats, so the main lookup holds only a few of their CNAMEs (nytimes.com: 10 hostnames). DNSDB CNAME lookups, chases and reverse CNAME lookups are aggregated (`aggr=t`): one record per hostname and target with its first and last seen, as in the DNSDB Scout table, instead of one per time slice. Data Source Status lists the domains where it was not needed. |
| Passive DNS | Pivot on hosting IPs (domain hopping) | Off | DNSDB reverse lookups on each domain's current non-CDN IPs, to find other domains that used them. One extra query per IP. DNSDB Scout only. |
| Passive DNS | Max IPs to pivot on | 10 | Caps the pivots above. |
| VPNDB | Check hosting IPs for VPN, residential proxy and Tor | On in every use case | Sends the run's public IPv4 hosting addresses (IP targets, current Iris IPs, passive DNS addresses most recently seen first; no CDN or private addresses) to VPNDB in one bulk request, then fetches the full verdict (sharing, Tor role, evidence) of the ones VPNDB attributes to a VPN, proxy or Tor, within the budget of the three options below. Each use case sets its own budget: *Map related infrastructure*, *Hunt C2* and *Report & export* 500 IPs / 50 verdicts with the neighbourhood; *Triage* 100 / 20 with it; *Subdomain takeover* 100 / 10, *Phishing* and *Monitor changes* 200 / 20 without it (see [Reference](REFERENCE.md)). Each IP is one VPNDB query (a demo account has 30,000 a day). Needs a VPNDB key ([Credentials](INSTALLATION.md#credentials)); without one the check is skipped. See [VPN, residential proxy and Tor](#vpn-residential-proxy-and-tor-vpndb). |
| VPNDB | Hosting IPs per run | 500 (the use case sets it) | Public IPv4 hosting addresses sent in the bulk request; each IP is one VPNDB query. |
| VPNDB | Full verdicts per run | 50 (the use case sets it) | Exits given the full verdict (sharing, IOC value, Tor role, evidence) and the weekly history (exit while the domain used it?); two queries each. With *Only the VPNDB IP check*: the IPv4 targets given the full verdict. |
| VPNDB | Neighbourhood and leads | On (the use case sets it) | The /24 around each non-exit hosting IP (up to 30) and the Iris hosting networks (up to 20) in VPNDB, and DNSDB reverse lookups on dedicated exits (up to 10). |
| VPNDB | Only the VPNDB IP check (no other source) | Off | A different kind of run, for IP addresses and CIDR ranges only: they are looked up in VPNDB and **nothing else** is queried (no Iris, passive DNS, Domain History or certificates). Domain targets are skipped, and Data sources says so. Only the *Check IP addresses* use case turns it on; in a custom profile, turn it on only if the profile is meant for IP lists. |
| Certificate API | Fetch CT log & certificate co-occurrence telemetry | On | Two extra API calls per Certificate API certificate. Turn off for faster runs on large targets. |
| Certificate API | Max certificates for CT/co-occurrence lookups | 10 | Caps the per-certificate lookups above. The newest certificates are looked up first, taking turns between domains so one busy domain does not use the whole budget. Each certificate costs two calls, so large values make runs on busy domains take minutes. |
| Certificate API | Certificate inputs: pre-select derived targets | 10 | How many domains / IPs found through certificate inputs are pre-selected (most certificates first). At most 100 can be analyzed per run. |
| Iris Investigate | — | — | No options: current hosting, registration, website and trackers are fetched for every domain. |
| All sources | Cache lifetime | 1 day | How long a successful lookup is reused: Off, 30 minutes, 6 hours, 1 day, 7 days or 30 days. The same domain, name, record type and limit looked up again, in this or a later run and also after an app restart, costs no API query: passive DNS and its TXT / CAA / CNAME supplements, CNAME chases and reverse lookups, IP pivots, certificate searches and events, Domain History, Risk, and Iris Investigate (per batch of domains). Results are kept in `dt_cache/` (local, git-ignored); *Settings → Lookup cache* shows how many and their size. Data Source Status notes *From cache (age old)* with its **Cached At** time, and Lookup Queries counts them as 0 requests and shows **Cached at**. Failed lookups are never cached. Saved in `dt_settings.json`. |
| All sources | Clear cache | – | *Settings → Lookup cache*: deletes every cached lookup now, without running anything. It also applies with an offline dataset (CNAME chases and reverse lookups use the cache). |
| All sources | Cached details (*Data sources* page) | – | How much of the run came from the lookup cache: cache lifetime, lookups from the cache vs API queries, age of the oldest cached result, when the first result expires, and the cache size on disk, plus one row per source (lookups, from cache, API queries, oldest / newest *Cached at*, first expiry, time left). **Re-run with fresh lookups** analyzes the same targets again with that run's collection settings, querying every source and refreshing their cache entries (other targets' cache is kept); **Re-run (use cache)** does the same but reuses what is still cached, like **Analyze**. Offline datasets re-run with their recorded settings. Certificate inputs are not searched again; their derived domains and IPs are re-run. |
| All sources | Force refresh on the next Analyze | Off | Deletes every cached lookup, then re-queries every source and reloads credentials. To refresh only the current targets, use *Re-run with fresh lookups* on the Data sources page. |

### 2. Analysis Window

**Show activity from** limits alerts, IOCs, risk scores, DIF fingerprints, charts and exports to records active in
the window. Presets: 7 / 14 / 30 (default) / 60 / 90 / 180 / 365 days, *All time*, or a custom range. See
[Analysis window](USER_GUIDE.md#analysis-window) in the User Guide for exactly what "active" means.

### 3. Timezone Alignment

Changes how timestamps are **displayed**. All detection runs on UTC.

### 4. Detection thresholds

*Settings → Detection thresholds* holds every detection threshold, grouped by the data it applies to (DomainTools
Risk; Passive DNS & Domain History; Iris Investigate & Domain Name; Certificate API) (dormancy periods, fast-flux counts, entropy,
certificate limits, ...). Changes re-run the engine on the data already collected, with no new API calls. The
full list with defaults is in [Detection thresholds](USER_GUIDE.md#detection-thresholds).

**Brand watchlist** (*Settings → Brand watchlist*): the brands you protect, one per line or comma-separated. A domain
entry (`acme.com`) also marks that domain as the brand's own. The *Lookalike / Brand* detections (typosquats,
homoglyphs, combosquats, the brand on another TLD) need it; without it only punycode domains are flagged. Saving re-runs
the detections, with no new lookups. Saved in `dt_settings.json`. Details and examples: [Brand
watchlist](REFERENCE.md#brand-watchlist).

### 5. View filters

Limit the views to selected domains and hostnames; *Record type filters* (Analyst mode) limit Domain History and
passive DNS record types.

#### Hostname focus

**Focus on hostnames** narrows the views to chosen hostnames, e.g. `api.domaintools.com` and `iris.domaintools.com`.
It starts with the hostnames ticked in the certificate preview and can be changed at any time. **No new lookups are
made**: the data was already collected for the whole domain.

| Data | With a hostname focus (focused domains only) |
| --- | --- |
| Passive DNS | Records of the hostname and names under it (`_acme-challenge.api.domaintools.com`); a wildcard focus `*.domaintools.com` keeps every subdomain |
| Certificates | Certificates naming the hostname or a name under it, or carrying the wildcard that covers it (`*.domaintools.com` for `api.domaintools.com`) |
| Certificate Events | Observations of the hostname and names under it |
| Domain History, Domain Risk, Iris Investigate | Unchanged: these describe the registered domain |

Hostnames can also be added from **Subdomain Triage** (*Focus on hostnames* button).

Other domains are not affected. Alerts, the risk profile and the DIF are recalculated from the focused data, and a
banner above the results lists the focus. A saved run records the focus that was active when it was saved.

**Gap-fill:** passive DNS, certificate search and certificate events cover every subdomain, but stop at their result
limits (DNSDB limit, 2,500 certificates, 2,500 events). When a domain with focus hostnames hits a limit, each focus
hostname is looked up on its own as well, so records the capped lookup missed are added. Data Source Status lists these
as *Hostname Gap-Fill* rows. Passive DNS gap-fill needs DNSDB Scout.

#### Hostname Inventory

The **Hostname Inventory** page lists every hostname under the selected domains that the run's certificates, passive
DNS or certificate events mention, over the full collected history. Service names such as `_dmarc` are left out. Per
hostname: certificates naming it (first, latest with its hash, expiry), passive DNS first and last seen, record types, current A /
AAAA / CNAME values, certificate event count, whether it is in the focus, and flags:

| Flag | Meaning |
| --- | --- |
| Certificate, never resolved | Named in a certificate but never seen in passive DNS: possibly prepared for later use. Not flagged for a domain whose passive DNS hit its result limit. |
| Resolves, no certificate | Seen resolving (A / AAAA / CNAME) but no collected certificate names or covers it |
| New | First seen (certificate or passive DNS) within the last 30 days |
| Sensitive name | A label below the registered domain contains a word often used for phishing or remote access (login, secure, vpn, sso, account, ...) |
| Wildcard | A wildcard certificate name |

Filter by flag, search by name, or show only focus hostnames. The inventory is not affected by the focus or the
analysis window.

**Certificates by hostname**, under the inventory, links each hostname to its certificates: one row per hostname and
certificate, with the certificate hash (SHA-256 from the Certificate API, SHA-1 from Domain History), hash type,
common name, issuer, validity and source. *Named* means the certificate lists the hostname; *Wildcard* means it covers
the hostname through `*.parent`. Select rows in the inventory to show only those hostnames' certificates; with nothing
selected it lists the certificates of every hostname shown. The hashes can be copied in one block for a lookup in
another tool, and the links are exported as *Certificate hashes by hostname* (see Data Export).

#### Subdomain Triage

The **Subdomain Triage** page ranks the subdomains of the Hostname Inventory (the domains themselves and wildcard names
are left out) by signals phishing and malware subdomains tend to show. It is built for shared platforms such as
`pages.dev`, `workers.dev` or free subdomain services like `eu.cc`, where thousands of strangers' subdomains sit under
one domain and the domain's risk score says nothing about them; a banner names the shared platforms found.

| Signal | Weight | Meaning |
| --- | --- | --- |
| Phishing word | 3 | A label contains a word used for credential phishing or remote access (login, verify, wallet, vpn, ...) |
| Brand name | 3 | A label contains a commonly impersonated brand (paypal, microsoft, zoom, dhl, roblox, ...) and the domain itself is not that brand |
| Embedded domain | 3 | Another domain is written into the name: `support.zoom.us.vip1.example.eu.cc`, `paypal-com-verify.pages.dev` |
| Punycode | 3 | A label is internationalized (`xn--`): may imitate another name with look-alike characters |
| Random-looking | 2 | A name part of 8+ characters that mixes letters and digits or has long consonant runs (generated names; also some deploy previews) |
| New | 1 | First seen within the last 30 days |
| Burst | 1 | First seen in the same hour as at least 4 other hostnames of the same domain |
| Never resolved | 1 | Named in a certificate but never seen in passive DNS |
| Long or deep name | 1 | Three or more labels below the domain, or 40+ characters before it |

The score is the sum of the weights. **High**: score 6 or more with at least one of the four name signals (phishing
word, brand, embedded domain, punycode). **Medium**: one of those name signals, or a score of 4 or more. **Low**: any
other signal. Lifecycle signals alone (new, burst, never resolved) never make a name High, since whole platforms issue
certificates for new names every hour.

The table shows High and Medium by default, highest score first, then newest; filter by level, signal, domain or text.
Select rows and click **Focus on N hostname(s)** to add them to *Focus on hostnames*, so every page shows only their
passive DNS, certificates and certificate events (no new lookups); or copy the hostnames in one block. The brand and
platform lists are in `core/intel_data.py` (`IMPERSONATED_BRANDS`, `SHARED_PLATFORMS`), the weights in
`core/subdomain_triage.py`, and the burst size in `config.py` (`TRIAGE_BURST_MIN`).

#### CNAME Chains

The **CNAME Chains** page maps where each hostname's CNAME redirects lead, as in DNSDB Scout's CNAME chasing. It lists
every CNAME of the analysis window (and the hostname focus): hostname, target, whether it is the hostname's current
target, the target's **service type** (dynamic DNS / tunnel, takeover-prone, free hosting, CDN), the full **chain**,
the number of hops, the **outcome** and the final addresses.

| Outcome | Meaning |
| --- | --- |
| Resolves | The chain ends at A / AAAA records (in the collected data or in DNSDB) |
| Dead end | A name in the chain has no CNAME, A or AAAA record in DNSDB: possible dangling CNAME (subdomain takeover) |
| Incomplete | The chain ends at a CDN name DNSDB has no address for (DNSDB Scout: *Chasing incomplete*). CDN edges answer per client and passive DNS often misses them; not a dangling sign |
| Loop / Step limit | The chain comes back to a name it passed, or is longer than 10 steps |
| Lookup failed | A DNSDB lookup of the chase failed |
| Not chased | The chain leaves the collected data and has not been chased yet |

Metric tiles count hostnames with a CNAME, current external CNAMEs, dead ends, takeover-prone and dynamic DNS / tunnel
targets. Filter by domain, service type, outcome or text. Every CNAME a hostname ever had is shown;
*Current only* hides the earlier ones (a hostname that moved from `line.cdn-line.xyz` to `line.txcdnline.com` shows
both, the earlier one unticked in **Current**). The table has one row per hostname and target. **Count** is how often
DNSDB saw that CNAME record; **Order rows by** sorts by *Domain, then count* (default: grouped by domain in the order
of the target list, most seen CNAMEs first), *Count* (across every domain) or *Last seen*.

Four columns show how fresh a chase is: **From cache** (every DNSDB lookup of the chase came from the lookup cache),
**Cached at** (for those, when the cached lookups were made), **Chased at** (when its DNSDB lookups were made; for cached ones, when they were first fetched) and **Chase age**
(how long ago). They are empty for chains that resolved in the collected passive DNS. Use them to decide whether to
re-chase.

Chases are not lost between runs: when a run finishes or a dataset (offline or from run history) is loaded, every
chase whose DNSDB lookups are still in the lookup cache is replayed from it, with no query, so those rows come back
chased with **From cache** ticked and their original **Chased at**. Data Source Status gets one *DNSDB CNAME Chase*
row saying how many were restored. Chases older than the *Cache lifetime*, or deleted with *Clear cache* / *Force
refresh*, are not restored; chase them again.

Chains are filled in only once you chase them (**Chased** ticked). **Chain** then reads from the analyzed domain to
the end: `designsolu.xyz → line.designsolu.xyz → line.cdn-line.xyz → 103.176.90.137`, or the outcome in brackets when
the chain does not reach an address (`(Dead end)`, `(Not chased)`). Rows a DNSDB chase already reached (another
hostname with the same target was chased) are filled in too.

**Service Type** says what kind of service the target runs on, from the lists in `core/intel_data.py`: *Dynamic DNS
/ tunnel*, *Takeover-prone*, *Free hosting*, *CDN* or *Parking*. **Other** means the target is on none of them: an ordinary
domain, often the operator's own or a parking or hosting provider not on the lists; **Service** (the provider name)
is then empty.

- **Chase CNAMEs of N selected hostname(s) – up to 10 queries per domain** (or *of all N hostname(s) shown* with
  nothing selected) fills in the chains of those hostnames. Where the collected passive DNS already knows the rest of
  a chain it is shown with no query. Elsewhere each chain is followed in DNSDB from where it stops, one exact-name
  lookup per step (`name/CNAME`, at the end `name/A` and `name/AAAA`, at most 10 steps), until the domain has made
  **10 DNSDB queries** in this click. Within a domain, dynamic DNS / tunnel, takeover-prone and free hosting targets
  go first, then other external targets, CDN and parking, then names inside the domain, current before earlier
  targets, and the name most hostnames share first. Lookups from the cache are free and do not count. A chase cut off
  by the limit keeps its path and continues from there on the next click; names not reached wait for the next click
  (the toast says how many). The caption under the button says how many names need DNSDB. Turn on **Re-chase (skip
  cache)** to chase already chased rows again with fresh DNSDB lookups; the new results replace the old ones. Domains are chased in
  parallel. The detections are re-run with the results, and the lookups appear in Data Source Status and Lookup
  Queries. Uses DNSDB quota, also when an offline dataset is loaded; chases made here are not written back into the
  offline dataset.
- **Chase results** groups the chased rows like the chain map: one row per domain and chain, with how many hostnames
  lead into it and some of them, their summed **Count**, the chain from the target to its final addresses, outcome,
  whether it came from the cache and when it was chased, and when the addresses and the CNAMEs were last seen. Chains
  most hostnames share come first, then the largest count.
- **Chain map** is drawn open as soon as any of the rows shown (or selected) is chased; before that it only offers
  *Show the map anyway*. *How to read the chain map* explains the colors and arrows. It draws the chains (the selected ones, or the first 40 shown, every domain's first chains before any
  domain's later ones) in a compact diagram, one dashed box per analyzed domain: the domain (dark blue) → its
  hostnames, grouped per target (e.g. `catalog.hyperiptv.net +155 more`) → targets colored by service type →
  addresses (green) or a dead end / loop / incomplete chase (red). Not chased rows stop at their target.
  **Every hostname in the map** draws each hostname as its own node instead of `+N more`; to open one group only,
  select its hostnames in the table, and the map draws just the selected rows (Graphviz maps in Streamlit cannot be
  clicked).
  - **Solid arrow** from a hostname: its current CNAME, the target it pointed to most recently (seen within a day of
    its latest CNAME record) and not replaced by A / AAAA records since. Current is the latest in the data, not
    necessarily still live: check **Last Seen**.
  - **Dashed grey arrow labelled *until YYYY-MM-DD***: an earlier CNAME, replaced by a newer target or by A / AAAA
    records more than a day later; the date is when passive DNS last saw it (display timezone).
  - **Solid arrows after the target**: the rest of the chain, each name's most recent CNAME.
  - **Dotted arrow** into the end: the last name's latest addresses, or how the chain stopped.

  Current and earlier are judged within the analysis window: with *Last 30 days* only CNAMEs seen in that window are
  drawn and the latest of them is current; *All time* shows the full history.
- **Copy chains** gives every chain as text, from the analyzed domain, e.g.
  `example.com → www.example.com → example.map.fastly.net → 151.101.1.1`.
- **Cross-domain links** compares every name and final address in the chains across the analyzed domains: a
  hostname of one analyzed domain aliasing into another (*CNAME into analyzed domain*), a name outside them all
  that several reach (*Shared CNAME*), or the same final IP (*Shared final address*). Reverse CNAME results add
  analyzed domains the collected passive DNS missed. Links through a CDN are marked and listed last. **Link map**
  (drawn open whenever there is a link outside CDN and parking services) draws the analyzed domains and what connects
  them. A link needs two analyzed domains on the same name or address, so with few domains, a short analysis window
  or unchased chains there may be none.
- **Related domains (reverse CNAME)** runs **reverse CNAME** lookups in DNSDB (`rdata/name/{target}/CNAME`, up to
  5,000 records each, 10 names per click). In **Names to look up**, pick chain targets or type any name (e.g.
  `line.txcdnline.com`, also one outside the analysis window); with none picked, *Look up suggested targets* takes the
  external names of the chains, one per domain first and without CDN and parking targets (their reverse lookups only
  list unrelated customers). The results show:
  - counts: other domains, names, targets looked up, and analyzed domains pointing to them (in DNSDB or in their own
    chains);
  - one row per target looked up, with its number of other domains and names, and **Truncated** when DNSDB stopped at
    5,000 records (the target is widely shared and the lists are incomplete);
  - the domain list: other domains first, those pointing to several of the targets first, then those on the most
    dedicated target (**Target shared by**: how many domains share it), with a copyable list of the other domains and
    every name found (one row per name).

  Other domains on a dedicated target are candidates for the same operator; on a parking or hosting service they are
  usually just other customers.

The detections built on the chains (dangling CNAME, takeover-prone service, dynamic DNS / tunnel, free hosting,
retargeted CNAME, long chain / loop, CNAME target shared by several analyzed domains) are explained in
[CNAME chains](USER_GUIDE.md#cname-chains) in the User Guide. The service lists are in `core/intel_data.py`.

#### Pivot Ranking

The **Pivot Ranking** page lists every value in the run's Iris Investigate records that other domains can share, with
the number of domains in Iris that share it (the Iris pivot count). Rare values usually lead to the same operator;
values shared by millions are infrastructure everyone uses.

| Types | Iris Investigate fields |
| --- | --- |
| Hosting | IP address, name server and its IPs, mail server and its IPs, redirect domain |
| Registration | Registrant name and organization, contact emails, phones and streets, WHOIS and SOA emails, email domains |
| Certificates | SSL certificate SHA-1, subject, organization and email |
| Web trackers | Google Analytics (UA and GA4), Tag Manager, AdSense, Facebook Pixel, Yandex Metrica, Baidu, Hotjar, Matomo, StatCounter |

| Signal | Domains sharing the value in Iris |
| --- | --- |
| Strong | 2 to 500: few enough to review every domain, often one operator |
| Useful | 501 to 10,000: combine with another pivot or filter (create date, TLD, risk) |
| Weak | More than 10,000: CDN, large hosting provider or registrar; rarely useful alone |
| This domain only | No other domain shares it |
| Count unknown | Iris returned no count for it |

Rows are sorted by signal, then by how many of the run's domains share the value (*Run Domains*, *Shared With*), then
by the Iris count, smallest first. A strong value that two or more of your targets share is the best lead: they are
probably run by the same actor. The table shows Strong and Useful by default; filter by signal or type, search by value
or domain, or keep only values shared within the run. The limits are `PIVOT_STRONG_MAX` and `PIVOT_USEFUL_MAX` in
`config.py`.

Select rows to pivot:

- **Add to targets** puts the selected IPs, certificates (`sha1:`, `cn:`, `org:` lines) and redirect domains in the
  sidebar target box and switches to live lookups; click **Analyze** to run them. Emails, name servers, registrant
  details and trackers cannot be targets; use *Find domains in Iris*.
- **Find domains in Iris** runs one Iris Investigate search per selected value (up to 5 per click, first 500 domains
  each) and lists the domains found with their Iris risk score, create date, first seen, registrar and IPs, highest
  risk first. **Add N domains to targets** puts them in the target box for a full run. These searches use API quota,
  also when an offline dataset is loaded, and need the DomainTools API credentials.
- *Iris searches for the selected values* shows the search parameters (`email=actor@example.com`) and the same
  searches as `curl` calls to the Iris Investigate API.

#### Lookup Queries

The **Lookup Queries** page lists every lookup the run made, rebuilt as a query you can run again by hand, e.g. to
check a finding or to widen a search past the app's limits. It works for live runs, saved runs and offline datasets.

| Tool | Query | Command |
| --- | --- | --- |
| IrisQL | The IrisQL query the run's targets were picked from (only for a run started from the IrisQL page); Requests counts one per page of results | `domaintools iris_investigate --irisql …` and the `curl` request with the query as the body |
| CertsQL | The CertsQL query the run's targets were picked from (only for a run started from the CertsQL page); Requests counts one per page | The Certificate Search `curl` request (`$DT_CERT_API_KEY`, else `$DT_API_KEY`) |
| Iris Investigate | Domain list to paste into the search box | `domaintools iris_investigate --domains …` |
| DomainTools API | Domain (Domain History, Risk Evidence) | `domaintools domain_history --query …` / `domaintools risk_evidence --domain …` |
| DomainTools Certificates | CertsQL for certificate search; JSON body for Certificate Events (hostname, IP, SHA-256, CT log) with the run's `start_time` | `curl` using `$DT_CERT_API_KEY` |
| DNSDB Scout | Names and record type, e.g. `*.example.com`, type ANY (plus `example.com` when that lookup hit its limit); TXT / CAA / CNAME supplements with their type; CNAME chase steps as the exact name with type CNAME, A or AAAA; IPs as Rdata IP | `curl` to the DNSDB v2 API (one request per name) using `$DNSDB_API_KEY` |
| Iris pDNS | Query and search type, e.g. `*.example.com`, RRName (supplements with their record type) | Request body as sent |
| VPNDB | Endpoint (`POST /bulk`, `GET /ip/{ip}`, `GET /ip/{ip}/history`, `GET /prefix/{cidr}`, `GET /prefix/{cidr}/addresses`, `GET /asn/{asn}`, `GET /tor`) and the path, or for a bulk request the IPs it sent, one per line | `curl` to the VPNDB API using `$VPNDB_API_KEY` |

The `domaintools` commands use the CLI that comes with the DomainTools Python SDK (`domaintools_api` in
`requirements.txt`). They pass `$DT_API_USERNAME` / `$DT_API_KEY`; when those are not set, the CLI reads `~/.dtapi`. The
DNSDB curl commands are the requests the app sends, including the result limit used in the run.

**Lookups by tool** shows one tool at a time: pick Iris Investigate, DomainTools API, DomainTools Certificates,
DNSDB Scout, Iris pDNS or VPNDB (each shows its number of requests). Each lookup is one table row with its search type, target,
query on one line (Certificate Events bodies as `key=value` pairs), the number of requests, and the status and record
count from Data Source Status. A DNSDB lookup that hit its limit counts 2 requests: after `*.example.com` the app also
looked up `example.com`, so the row holds both names and both curl commands. The table can be filtered by source and text. Select rows to copy only their queries and commands under
*Queries to copy* and *Commands*; with nothing selected these hold every row shown, in the tool's own layout (grouped
by search type). **Download all lookups (CSV)** saves every tool's lookups with the full queries and commands. Paging is
left out of the commands. Gap-fill and certificate-input searches are included; lookups run once per certificate
(SHA-256 events, CT logs) get one row each.

#### Data Export

The **Data Export** page downloads the run's data for sharing with other teams, without charts. Tick what to export:

| Group | Items |
| --- | --- |
| IOCs | Indicators (domains, IPs, name servers, certificate hashes), Certificate hashes by hostname |
| Tables | Detections (with structured evidence), Risk profiles, Hostname inventory, CNAME chains, Reverse CNAME, VPN / proxy / Tor (VPNDB), CIDR ranges, CIDR addresses and CIDR IPs (VPNDB), Exit history, Neighbouring ranges and Hosting networks (VPNDB), Other domains on dedicated exits, Data source status, Lookup queries |
| Raw data | Passive DNS records, Domain History changes, Certificates, Certificate events, CT log events, Certificate co-occurrence, Iris Investigate responses, VPNDB responses |

Choose **CSV** (opens in a spreadsheet; lists and nested values are written as JSON text) or **NDJSON** (one JSON object
per line, nested values kept; loads into SIEMs and `jq`). Iris Investigate and VPNDB responses are nested, so they are always
NDJSON. One item downloads as a single file; several download as a ZIP with one file per item plus `manifest.json`
(targets, selected domains, analysis window, row counts). Items without rows are left out.

Timestamps are UTC. Raw data follows the analysis window and the view filters; the hostname inventory and its
certificate links cover the full collected history; detections leave out suppressed alerts. Offline datasets
(*Save offline copy*) are a different thing: they hold everything a run collected, in the app's own format, so the run
can be re-analyzed later.

### International domains

DNS, passive DNS (DNSDB), certificates (Certificate API and Iris), Iris Investigate and Domain History all store
internationalized names in their ASCII **punycode** form: `bücher.de` is `xn--bcher-kva.de`, and a certificate for it
lists `xn--bcher-kva.de` and `*.xn--bcher-kva.de`. So every lookup uses that form.

- **Input:** type a name either way. A Unicode name (`bücher.de`, `shop.münchen.de`, `*.bücher.de`, or after `cn:` /
  `san:`) is converted to punycode before the lookups; the sidebar lists each conversion
  (`bücher.de` → `xn--bcher-kva.de`). Look-alike characters are converted too: `аpple.com` with a Cyrillic `а` becomes
  `xn--pple-43d.com`, which the lookalike rules then flag.
- **Reading:** the Summary's domain table adds a **Unicode** column whenever a domain is internationalized, and the
  Domain profile's domain list shows both forms (`xn--bcher-kva.de (bücher.de)`). Turn on **Show international
  domains in Unicode** (sidebar, under *Save offline copy*) to show every `xn--` name in Unicode on every page: tables,
  raw records, text, chart labels, legends and the domain filter.
- **What stays ASCII:** the data itself. Filters and searches match the ASCII form (type `xn--` to find every
  internationalized name), and exports, downloads, the copyable queries and commands (*Lookup Queries*, Iris searches)
  and editable tables keep the punycode the APIs and other tools need. The documentation shows its examples as written.


## VPN, residential proxy and Tor (VPNDB)

VPNDB answers which VPN or proxy provider operates behind an IP, prefix or ASN. With a VPNDB key ([Credentials](INSTALLATION.md#credentials)) every live run asks VPNDB which VPN, residential
proxy or Tor operator is behind the IPs the analyzed domains use: the IP targets, then each domain's current Iris IPs
and its passive DNS addresses, most recently seen first (public IPv4 only, no CDN addresses). It runs in one bulk
request after passive DNS, then fetches the full verdict and weekly history of the exits it finds. The verdicts are
saved with the run and with *Save offline copy*, so offline datasets keep them.

The check is on in every use case, each with its own budget (Settings → Collection options → VPNDB, and per use case
on Settings → Use cases & profiles):

| Use case | Hosting IPs per run | Full verdicts | Neighbourhood and leads |
| --- | --- | --- | --- |
| Map related infrastructure, Hunt C2 infrastructure, Report & export evidence | 500 | 50 | on |
| Triage a suspicious domain | 100 | 20 | on |
| Phishing & lookalikes, Monitor changes | 200 | 20 | off |
| Subdomain takeover check | 100 | 10 | off |
| Check IP addresses (VPN, proxy, Tor) | IP targets | 100 | (VPNDB only) |

Each hosting IP is one VPNDB query, each full verdict two (verdict and history), each neighbouring range or network
one; a demo account allows 30,000 queries a day. The sidebar shows the budget of the next run, e.g. *VPNDB 500/50*.

After the verdicts the run combines VPNDB with the other sources (same VPNDB key, small extra quota):

| Combination | What is looked up | What it answers | Cost per run |
| --- | --- | --- | --- |
| Passive DNS × VPNDB history | The weekly history of each anonymizer exit (`/ip/{ip}/history`) | Was the address an exit *while* the domain resolved to it? An address that became an exit after the domain left it is reused hosting: it is shown, but raises no exit alert | 1 query per exit, up to 50 |
| Iris × VPNDB | Nothing extra: Iris already reports how many domains sit on each IP | *Iris cross-check*: a dedicated exit with few Iris domains is a **strong pivot**, a shared one with thousands is noise; network or country disagreements between Iris and VPNDB | none |
| Iris / passive DNS × VPNDB ranges | The /24 around each hosting IP that is not an exit, and each current Iris hosting network (ASN) | Is the domain hosted among VPN or proxy exits, or on a VPN provider's own network? | 1 query per /24 (up to 30) and per ASN (up to 20) |
| VPNDB × passive DNS (DNSDB) | DNSDB reverse lookup (`rdata/ip`) on each **dedicated** exit | Other domains on the same customer's exit: leads to analyze. Shared exits are skipped | 1 DNSDB query per dedicated exit, up to 10 |
| Tor network (VPNDB `/tor`) | The Tor overview: relays, exit addresses and each network's, country's and prefix's share of Tor exit traffic | Do the run's hosting networks carry Tor exit traffic? Where does an IP sit in the Tor network? | one call, not counted against the quota |

The Tor overview is network-wide context, fetched once per run whether or not an IP is in Tor. A Tor IP needs no
extra lookup: the bulk request marks it Tor, and its full verdict (`/ip/{ip}`, fetched for every exit within the
budget) carries its Tor data from the Tor Project's lists: exit first and last seen and whether it exits now, each
relay at the address (nickname, role, flags, first seen, share of Tor exit traffic, operator family size), and the VPNs
whose Tor feature leaves through it. These are columns of the verdict table and lines of the IP card. The app does not
page through the whole relay list (`/tor/relays`).

- **VPNDB** (Infrastructure menu) is the page for all of it, in tabs. Each tab starts with **How to read this**: a
  few plain-language points on what the tab shows and what to look for.
  - *Overview*: counts per category, a **domain → provider → exit** flow, a **domain × category** heatmap, exits per
    provider, a map of exit countries, and the exits table (select a row for the IP in full, see below), with *VPNDB
    alerts* and *Download the verdicts*; *Show every checked IP* lists all of them.
  - *Exposure timeline*: answers *was the IP already a VPN / proxy exit while the domain used it?* One bar per
    domain and exit IP for the time the domain pointed to it (passive DNS, whole history); yellow diamonds are the
    weeks VPNDB saw the IP working as an exit. A **red** bar: yes, used while it was an exit (what the exit alerts are
    based on). A **green** bar: no, the IP was an exit only before or after (the address was reused), so no exit
    alert. **Grey**: unknown, no weekly history.
  - *Iris cross-check*: the IPs the domains use today that VPNDB also knows. *Iris domains* is how many domains share
    the IP: few on an exit means one owner, so its other domains are worth checking (**strong pivot**); thousands
    means a busy shared VPN exit whose other domains belong to strangers (**noise**). *Disagreement*: Iris and VPNDB
    put the IP in a different network or country, usually because the VPN shows a fake location or the IP changed
    owner.
  - *Neighbourhood*: the /24 ranges around the hosting IPs and the hosting networks, with their known exits.
  - *Leads*: the other domains on dedicated exits, each with *Analyze*.
  - *Tor network*: relays, exit relays and addresses, exit networks, new exits in 30 days, how concentrated Tor exit
    traffic is, the run's hosting networks that carry Tor exit traffic, and the largest exit networks, countries and
    prefixes.
  - *CIDR ranges*: one grid per range (one cell per address: measured exit, interpolated, none), then the range cards.
- **One IP in full.** Selecting a row in any VPNDB table (VPNDB page, Summary, Domain profile, the IP check cards)
  opens a card with five tabs:
  - *Verdict*: category, provider, every provider with its share, confidence and how it was reached, Tor role,
    sharing, IOC value, infrastructure, network, ASN, country, location mismatch, last seen, method, public lists,
    and a *Profile of …* button for each domain on it;
  - *Full VPNDB answer*: VPNDB's whole `/ip` answer as tables (fields, attribution, evidence, tunnel, Tor relays,
    feeds ...) and as JSON. An IP the run only has the bulk summary of has **Fetch the full verdict and weekly
    history** (2 VPNDB queries, shown for the session);
  - *Weekly history*: first and last week, the weeks with exit evidence (probe, scan, interpolated) as a chart, and
    the providers seen on the address;
  - *In this run*: the domains that resolved to it with names and first / last seen (full history), Iris
    Investigate (domains on the IP, ASN, ISP, country), its /24 and network with their known exits, and the CIDR
    targets it is in;
  - *Tor network*: its network's, prefix's and country's share of Tor exit traffic.
- **DNS & Hosting** opens with a one-line VPNDB summary and a link to the VPNDB page.
- **Summary**: a *VPNDB* column in the Domains table and a *VPNDB* row in Analysis Details
  (see the Summary walkthrough above).
- **Domain profile**: its own *VPNDB* card, apart from the Iris Investigate cards:
  every checked IP of the domain, exits first, with **Seen in** (*Iris (now)*, *passive DNS* in the window, or
  *passive DNS (before the window)*) and VPNDB's category, provider, confidence, sharing, IOC value, Tor role,
  network, country, last seen, location mismatch and how the confidence was reached.
- **Alerts** (category *Hosting & DNS Providers*), for IPs the domain resolved to in the analysis window or resolves
  to now (Iris); an IP only seen before the window is listed but does not alert:
  - *Domain on Tor Relay / Exit Node*: High for a Tor exit, Medium-High for a guard or middle relay that does not
    exit traffic; always High confidence (Tor Project data). It counts only when the Tor exit lists date the address
    as an exit while the domain used it, and calls out exits that started in the last 30 days. The IOCs list the
    relays, the exit dates, the share of Tor exit traffic, the operator's family size and the VPNs whose Tor feature
    exits there.
  - *Domain on Residential Proxy Exit* (High) and *Domain on VPN / Proxy Exit* (Medium-High): the domain resolves to
    that kind of exit. Confidence is VPNDB's for the IP.
  - *Domain on Dedicated Anonymizer Exit* (High): an exit few customers share (VPNDB sharing LOW or IOC value HIGH),
    such as a dedicated VPN IP: unlike a shared exit it points to one customer, so it is worth pivoting on.
  - *Hosting Moved onto Anonymizer Exit* (Medium-High): the domain used ordinary hosting first and its newest
    addresses are exits.
  - *Domain Rotates Across Anonymizer Exits* (Medium-High): three or more exits, or exits of two or more providers.
  - *Newly Registered Domain on Anonymizer Exit* (High): a Newly Registered Domain already on an exit.
  - *Anonymizer Exit Shared by Analyzed Domains* (Medium-High): two or more of your domains on the same exit, one
    that is not a shared exit (shared exits are left out: unrelated customers use them too).
  - *Hosted Among Anonymizer Exits* (Medium): the domain's own IPs are not exits, but their /24 holds known exits, or
    the hosting network is one VPN provider's (single tenant with 25 or more known exits).
  - *Hosted Among Tor Exits* (Medium): the domain's own IPs are not Tor relays, but sit in a Tor exit prefix (Medium
    confidence) or on a network carrying 0.5 % or more of Tor exit traffic or 10+ exit addresses (Low), by the Tor
    overview.

  With VPNDB's weekly history of an exit, these alerts only count it when it was an exit while the domain used it.

  All of them count towards the *App & C2 Footprint* risk vector. See [How the VPNDB rules
  work](USER_GUIDE.md#vpndb-anonymizer-rules).
- **Confirmed indicators** show each IP's VPNDB verdict. A **shared exit** (VPNDB rates its IOC value LOW or its
  sharing HIGH: many people leave through it) identifies the service, not the actor, so it is left out of the CSV, MISP
  and STIX downloads unless you tick *Include shared VPN / proxy exits*; included, MISP marks it `to_ids: false`.
- **Raw Records** ends with *VPNDB Responses*: every VPNDB answer of the run as received, one row per lookup
  (endpoint, target, status, records, cached at). Select one to see it as tables: its fields flattened
  (`asn.number`, `sharing.level`), then each list it holds (the bulk `results`, a range's `addresses`, an exit's
  weekly history, the attribution), the JSON as received, and a JSON download.
- **Lookup Queries** has a *VPNDB* tab (and an *IrisQL* or *CertsQL* tab for a run started from those pages): each VPNDB request with its endpoint, the path or the IPs sent, and the curl
  command to send it again.
- **Data Export** has the VPNDB table, *Exit history*, *Neighbouring ranges*, *Hosting networks* and *Other domains on
  dedicated exits*, and **Data sources** lists every VPNDB and DNSDB lookup.

### Checking IP addresses only

**Check IP addresses (VPN, proxy, Tor)** (Start page) turns on *Only the VPNDB IP check*: VPNDB is the only source,
for IP addresses and CIDR ranges. Enter IPv4 or IPv6 addresses (and ranges, see below) and click **Analyze**; domain
targets on the list are skipped and Data sources says so. The run makes one bulk request for every IP target, then
fetches the full verdict of each IPv4 target (up to 100).

- **Summary** shows one card per IP: category and provider, every provider VPNDB attributes it to with its share,
  VPNDB's confidence and how it was reached, Tor role, sharing and IOC value, network, ASN, country and a
  claimed-vs-real location mismatch, with a button to its alerts and to Data Export.
- **VPNDB** has the same verdicts as charts and tables, and *CIDR ranges* the range grids.
- **Alerts**: the VPN / proxy / Tor alerts are raised on the IPs themselves (there is no domain to weigh, so the
  compound rules and the exit history do not apply).
- **Raw Records** and **Lookup Queries** list every VPNDB answer and request.

IPv6 addresses are answered *not collected* (VPNDB gathers IPv4 only). In any other use case, IP targets are looked
up in every source (Iris, passive DNS, certificates) and in VPNDB.

### CIDR ranges

A target in CIDR notation (`104.21.59.0/24`, `2a00:1450::/32`, also defanged or not aligned: `104.21.59.7/24` is read
as `104.21.59.0/24`) is a range, not an address. Iris, passive DNS and certificates take single addresses, so a range
is looked up in **VPNDB only** (Data sources says so), in any use case with the VPNDB check on and in *Check IP
addresses*:

- **the range's verdict** (one query): which VPN or proxy providers have exits in it and their share, how many exits
  VPNDB knows there and what share of the range that is, whether one provider holds it (single tenant), the announced
  prefix around it, ASN, countries and the public lists that name it;
- **the addresses VPNDB exited through in it** in the last 30 days (observed only: VPNDB can also fill the rest of a
  range in from its prefix, which would only repeat the range's providers), up to 200 per range (each row counts as a
  query, and a demo account allows 2,000 list rows a day): each with its providers, pool (residential / datacenter),
  tunnel protocol, first and last seen. VPNDB lists addresses for IPv4 ranges of /12 or smaller;
- **every address of the range, one row per IP**, for IPv4 ranges VPNDB knows exits in, up to 1,024 addresses per
  range (a /22) and 4,096 per run, in one bulk request: category, provider, confidence, method, ASN, country, the
  lists that name it, plus pool, tunnel and probes for the addresses VPNDB's probing exited through. VPNDB marks
  the addresses it did not see itself *interpolated*: attributed from the range's measured share (e.g. 46 of 256
  measured gives the other 210 medium confidence); the card counts measured and interpolated exits apart and lists
  the measured ones first. Each address
  counts as one VPNDB query (a /24 is 256). Ranges VPNDB knows no exit in are not expanded, and neither are IPv6
  ranges (VPNDB does not collect IPv6).

The bulk answer is a summary per IP; sharing, IOC value and Tor role come from the full single-IP verdict, so enter an
address on its own for those.

At most 20 ranges are looked up per run. The Summary and the VPNDB page (*CIDR ranges*) show a **CIDR ranges** table with one card per
range holding its per-IP table (exits first), and Data Export has *CIDR ranges*, *CIDR addresses* and *CIDR IPs*. A single-address range (`/32`, `/128`) is a plain IP.

*Not observed* is not an all-clear: VPNDB only knows the exits it measured or that public lists name, and it does not
collect IPv6, so IPv6 addresses are not sent.

## Certificate inputs

Besides domains and IPs, the target box accepts certificates. They are looked up first, and the domains and IPs their
certificates cover can then be analyzed like any other target.

| Input | Recognized as | Looked up with |
| --- | --- | --- |
| 64 hexadecimal characters (colons allowed, e.g. `AB:CD:…`) | Certificate SHA-256 | Certificate Search (`sha256`) and Certificate Events for the fingerprint. If no certificate matches, it is retried as a public key SHA-256. |
| 40 / 32 hexadecimal characters | Certificate SHA-1 / MD5 **or** serial number: a 20- or 16-byte serial has the same length | One Certificate Search matching either field (`sha1` / `md5` or `serial_number`); the results note when it matched as a serial |
| Other hexadecimal values of 8–42 characters (`0x` and colons allowed) | Serial number | Certificate Search (`serial_number`) |
| `sha256:` / `sha1:` / `md5:` + value | The same, stated explicitly | As above |
| `spki:` + 64 hex | Public key SHA-256 | Certificate Search (`public_key_sha256`): every certificate reusing the key |
| `serial:` + value | Serial number (colons and spaces ignored) | Certificate Search (`serial_number`) |
| `cn:` + text | Subject common name, exact | Certificate Search (`subject_common_name equals`) |
| `cn~:` + text (3–63 characters) | Subject common name containing the text | Certificate Search (`subject_common_name contains`) |
| `san:` + hostname, wildcard or IP; or a bare `*.example.com` | Subject Alternative Name | Certificate Search (`san_dns` / `san_ip_v4` / `san_ip_v6`) |
| Text that is not a domain, IP or hash, e.g. `DomainTools LLC` | Subject organization containing the text (exact when shorter than 3 or longer than 63 characters) | Certificate Search (`subject_organization contains`) |
| `org:` + text | Subject organization, exact | Certificate Search (`subject_organization equals`) |
| `org~:` + text (3–63 characters) | Subject organization containing the text | Certificate Search (`subject_organization contains`) |
| `issuer:` + text | Issuer common name or organization, exact | Certificate Search (`issuer_common_name` or `issuer_organization`) |

A prefixed line is read whole, so values may contain spaces (`cn: Kubernetes Ingress Controller Fake Certificate`).
Without a prefix, words that are not domains (no dot), IPs or hashes are kept together as one organization search:
`DomainTools LLC` finds certificates issued to *DomainTools LLC*, and `DomainTools` also finds *DomainTools LLC*.
Text matching is case-insensitive; fingerprints, keys and serials are queried in lower and upper case. How each
value is searched can be changed before any API call (see step 1 below), so prefixes are optional. Plain domains already
search certificates by SAN, including subdomains, so `san:` is only needed for an exact hostname, a wildcard or an IP.

**How it runs**

1. **Review the searches** (no API calls yet). **Analyze** shows each recognized certificate detail with a
   **Search as** choice, e.g. a 32-character value defaults to *MD5 or serial* and can be switched to *Serial* or
   *MD5*, and a company name defaults to *Organization contains* and can be switched to *Organization* (exact),
   *CN contains* or *Issuer*. Values can be edited (e.g. shorten `DomainTools LLC` to `DomainTools`). Untick rows to skip them; the CertsQL for each search is shown under *CertsQL for N search(es)*. Values
   that don't fit the chosen field (e.g. a 64-character value searched as MD5) are flagged and block the search.
   Domains and IPs entered alongside are kept as entered. Click **Search certificates**.
2. **Choose the targets.** The searches run (up to 200 certificates per input). A table shows, per input, how many
   certificates and observations were found and how many targets they lead to. **Certificates found** lists each
   certificate (common name, organization, issuer, validation level, validity, SANs, SHA-256). **Derived targets** lists
   every domain and IP found:

   | Column | Meaning |
   | --- | --- |
   | Analyze | Tick to include the target; the first 10 (by default) are pre-selected, most certificates first |
   | Via | *SAN DNS* / *SAN IP*: named in a certificate's SANs. *CN*: the common name of a certificate without SANs. *Observed domain / hostname / IP*: where Certificate Events saw the fingerprint. |
   | Hostnames | How many full hostnames under the domain the certificates name (listed under **Hostnames**) |
   | Certificates | How many of the found certificates name the target |
   | Seeds | The certificate inputs that led to it |

   Targets are registrable domains. Shared CDN certificate names (e.g. Cloudflare's `sni.cloudflaressl.com`), private
   IPs and non-hostname common names are never offered.

   **Hostnames** (optional) lists every full hostname the certificates name, including wildcards, with its apex.
   Ticking **Focus** sets the run's starting [hostname focus](#hostname-focus), and analyzes the hostname's domain
   even if it is not ticked above. Domains are always looked up in full (every subdomain), so the focus loses no data
   and can be changed after the run.
3. **Analyze selected** runs the normal analysis on the entered and selected targets (at most 100 derived targets).
   **Cancel** at either step discards the certificate inputs; so does opening another page from the top menu.

The certificate records found in step 2 are complete (every field), and they are reused: they are added to the run's
certificate data, so a seed certificate is analyzed even when a domain's own certificate search would not return it.
Lookups repeated with identical parameters within the *Cache lifetime* (for example the SHA-256 events of a seed
certificate) come from the cache, not the API. Each analyzed domain still gets its own certificate search, because that answers a
different question: every certificate naming the domain.

Domains that share a found certificate are linked by the cluster logic as a **Strong** cluster, so *Group by:
Campaign Cluster* shows them as one incident. After the run, **Certificate inputs** (under Data Source Status) lists
each input with what it found and which analyzed targets came from it. Runs and offline datasets store their
certificate inputs and hostname focus: run history shows them as `cn:Acme VPN → a.com, b.com`, and a run with certificate inputs is
compared only with earlier runs of the same inputs and targets.

## IrisQL

**IrisQL** starts from a question instead of a target list: which domains match these registration,
hosting, certificate or web details? It runs an [IrisQL](https://docs.domaintools.com/api/iris/investigate/irisql/)
query on Iris Investigate (the same search as `domaintools iris_investigate --irisql ...`), lists what matches, and
analyzes the domains and IPs you pick. Open it either way:

- **IrisQL** in the top menu, between Start and Overview;
- **Data source → IrisQL** in the sidebar, on any page.

While the page is open, the sidebar's Data source shows *IrisQL*; another page switches it back to *Live lookups*. The
query, its options and the last results are kept when you leave the page and come back.

**Autocomplete in the query editor**

The query box suggests what can come next as you type (or press Ctrl+Space):

| Where the cursor is | Suggested |
|---|---|
| Start of a line | The fields, with their kind (text, date, number, ...); `AND` after a condition |
| After a field | Only the operators that field accepts (e.g. `NAMESERVER_DOMAIN` offers `MATCHES`, not `EXACTLY_MATCH`) |
| After an operator | What the value goes in, with the cursor inside and nothing to delete: `""` for text and dates, `[""]` for lists, nothing for a number. Where there are only a few values it opens a list to pick from instead: `true` / `false`, or `"The last 7 days"` / `"The last 30 days"` for `WITHIN`. CertsQL `exists` / `does_not_exist` take only `true`, so that one is written for you |

Enter or a click picks a suggestion, Esc closes the list, and Tab jumps past the closing quote or bracket. Fields, operators,
values, `AND` and comments are colour-coded; an operator the field doesn't accept is underlined in red. A line that a
warning below the box is about gets a marker in the margin (hover it for the warning). The query is taken when you
click outside the box or press Ctrl+Enter (⌘+Enter on a Mac). The editor is bundled with the app, so it works
without internet access.

**Step 1: search**

1. Write the query in **IrisQL query**, or pick one under **Start from an example** (it replaces the query). One condition per line,
   `FIELD OPERATOR value`, with `AND` on its own line between conditions; conditions on the same field without `AND`
   are OR'ed. Values are JSON: `"text"`, numbers, `true` / `false`, `["a", "b"]`. The `# IrisQL-1.0` line is added
   when missing.

   ```text
   # IrisQL-1.0
   domain contains "domaintools"
   ```

   ```text
   # IrisQL-1.0
   DOMAIN CONTAINS "bank"
   DOMAIN CONTAINS "finance"
   AND
   CREATE_DATE WITHIN "The last 30 days"
   AND
   RISK_SCORE GREATER_THAN 75
   ```

   Each field takes its own operators, and Iris answers *HTTP 400: Operator "…" is not supported for this field* for any
   other. The page checks this before you search and names the allowed ones. The common catches:

   | Field | Exact match | Not accepted |
   | --- | --- | --- |
   | `ACTIVE`, `NAMESERVER_DOMAIN`, `NAMESERVER_HOST`, `MAILSERVER_*`, `TLD`, `EMAIL*`, `IP`, trackers (`GA4`, `GOOGLE_ANALYTICS`, …) | `MATCHES` | `EXACTLY_MATCH`; `CONTAINS` (except `TLD IN`) |
   | `ISP_NAME` | `EXACTLY_MATCH` | `MATCHES` |
   | `DOMAIN`, `REGISTRANT_ORG`, `REGISTRAR`, `WEBSITE_TITLE`, `SSL_ORG` | `EXACTLY_MATCH` or `MATCHES` | — |
   | `TAGS` | `CONTAINS ["tag"]` | `MATCHES`, `EXACTLY_MATCH` |

   Absence is `FIELD EXISTS false`. Iris doesn't take CIDR ranges: list the IPs (`IP IN ["1.2.3.4", "1.2.3.5"]`) or
   use `IP GREATER_THAN_OR_EQUAL "1.2.3.0"` and `IP LESS_THAN_OR_EQUAL_TO "1.2.3.255"` on two lines with `AND` between them.
   A query that matches more than 10,000 domains returns nothing (*Limit Exceeded Maximum 10000*), so narrow it, for
   example with `CREATE_DATE WITHIN "The last 30 days"` or `RISK_SCORE GREATER_THAN 75`.

   Common mistakes are flagged before anything is sent: no condition, `AND` at the start or end, or two conditions
   on one line (Iris answers those with an error).
2. Set **Domains to fetch** (default 500, at most 5,000). Pages of 500 are requested until that many, one Iris
   Investigate query each. Set **Sort by** (Iris sorts before paging, so it decides which domains you get when more
   match), and **Pre-select the riskiest** (default 10).
3. Click **Search**. The same search within the cache lifetime costs no query. *The same search outside the app*
   gives it as a DomainTools CLI line, a curl command and Python SDK code, without credential values (taken from
   `$DT_API_USERNAME` / `$DT_API_KEY`). The curl answer is piped to `jq .` and the Python prints it indented; without
   `jq`, drop ` | jq .` from the curl line. Each block has a **Copy** button.

**Step 2: pick and analyze**

The results show how many domains match in Iris, how many were fetched, their hosting IPs and the queries used, and
say so when Iris has more matches than were fetched.

| Tab | Shows |
| --- | --- |
| Domains | Each domain with its risk score, active flag, create / first seen / expiration dates, registrar, registrant organization, TLD, IPs, ASNs, countries, name servers, website title and tags. Tick **Analyze** on the rows to look into; *Tick: 10 riskiest*, *All* (the first 100) and *None* set the ticks; with *Sort by* left on the Iris default the riskiest come first |
| IPs | The domains' current hosting IPs: how many listed domains use each (*Result Domains*), how many domains Iris has on it in total (*Iris Domains*; a large number is shared hosting), ASN, ISP, country and the domains. Tick the IPs to analyze as IP targets |
| Breakdown | Risk score histogram, top registrars, TLDs, ASNs and countries |
| Raw JSON | The Iris answer as received, with a download |

Under **Analyze the selection**, choose **What to analyze**: **Domains**, **IPs** or **Domains & IPs** (each shows
how many are ticked). Only the ticks of the chosen tab(s) are used, so IPs pre-selected on the IPs tab stay out of a
domain run unless you choose them; the other tab keeps its ticks. Then pick the **Use case** (as on the Start page: it
sets the collection options and the analysis window) and click the Analyze button, which says what the run takes
(e.g. *Analyze 10 domains*). The chosen targets (at most 100) become the sidebar targets and are analyzed as a new run, which opens on the Summary (the sidebar switches back to *Live lookups*); Run History notes it as *via IrisQL: …* with the query's
first condition. **Add to the sidebar targets** adds the same chosen targets to the target box without analyzing, to combine them with
other targets first.

The analysis looks the domains up again (Iris Investigate in batches of 100, plus the use case's other lookups), so
the run has the same data as one started from the sidebar.

## CertsQL

**CertsQL** works like [IrisQL](#irisql) but starts from certificates. It runs a CertsQL query through the
DomainTools Certificate Search API (technology preview), lists the matching certificates and the domains, IPs and
hostnames they name, and analyzes the ones you pick with a use case. It uses the certificate key
(`DT_CERT_API_KEY` / `[cert_api]`), and falls back to the DomainTools API key. To open it, use either of these:

- **CertsQL** in the top menu, after IrisQL;
- **Data source → CertsQL** in the sidebar, on any page.

While the page is open the sidebar's Data source shows *CertsQL*; opening another page switches it back to *Live lookups*.

**Step 1: search**

1. Write the query in **CertsQL query** (with the same [autocomplete](#irisql) as IrisQL: fields and dotted subfields, each field's operators, then `["", ""]` for `between` on a date, to fill in as `"YYYY-MM-DD"`), or pick one under **Start from an example**. One predicate per line,
   `field operator value`, all lowercase. Lines in one clause are OR'ed, and a line with only `AND` starts the next
   clause. Values are single-line JSON: `"text"`, numbers, `true` / `false`, `["a", "b"]`, and dates as
   `"YYYY-MM-DD"` (UTC). Comments start with `#` or `//`. The `# CertsQL-1.0` line is added when it's missing.

   ```text
   # CertsQL-1.0
   san_dns contains "login"
   AND
   issuer_organization in ["Let's Encrypt", "ZeroSSL", "Google Trust Services"]
   AND
   validity_not_before greater_than "2026-10-05"
   ```

   The examples include a domain and its subdomains, brand look-alikes on new certificates, login hostnames from free
   CAs, certificates expiring in the next 30 days, key reuse (same public key), self-signed certificates, weak RSA
   keys, long validity, non-CA certificates with critical basic constraints, brand names not issued to the brand, and
   DV policy without a subject organization. Their dates are counted from today.

2. The page checks the query against the CertsQL field catalog before you search, and names the problem and the
   allowed operators. The API would answer each of these with *HTTP 400*:

   | Rule | Example of what is caught |
   | --- | --- |
   | Every field takes `equals`, `does_not_equal`, `in`, `not_in`, `exists`, `does_not_exist` | `issuer_contry equals "US"`: unknown field (did you mean `issuer_country`?) |
   | Booleans (`is_self_signed`, `is_precertificate`, `has_wildcard_san`, `has_embedded_scts`) take no `in` / `not_in`, and `true` / `false` without quotes | `is_self_signed equals "true"` |
   | Text operators (`begins_with`, `ends_with`, `contains`, and their `does_not_` forms) only on names and organizations: `san_dns`, common names, organizations, organizational units, Kerberos / permanent identifier / XMPP SANs; locality, state and DC take only `begins_with` / `ends_with` | `sha256 contains "ab12"` |
   | `contains` takes 3 to 63 characters, and matches within one DNS label | `san_dns contains "lo"` |
   | Range operators (`greater_than`, `less_than`, `…_or_equal`, `between [min, max]`) only on dates, `validity_duration_days`, `public_key_bits`, `san_count`, `san_ip_v4`, `san_ip_v6` | `public_key_bits less_than "2048"` (a number goes without quotes) |
   | Nested objects (`basic_constraints`, `certificate_policy`, `name_constraints`, `signed_certificate_timestamp`) take only `exists true` / `does_not_exist true`; query a subfield with a dotted name | `basic_constraints.is_ca equals false` |
   | `exists` / `does_not_exist` take `true`; negative operators only match a field that is present | `subject_organization does_not_exist true` finds certificates without one |
   | Limits: 32 clauses, 256 lines in a clause, 1,024 lines, 1,000 values in an `in` array, 64 KB | |

   Two forms in the CertsQL overview aren't accepted by the API yet: it answers both with *UNKNOWN_KEYWORD*, and the
   page flags them. Instead of `within "the next 30 days"`, use `between ["2026-11-04", "2026-12-04"]`. Instead of
   `matches_element ( … )`, use dotted subfields, one per clause.

3. Set **Certificates to fetch** (pages of 500, up to 5,000), **Sort by** and **Order**, and **Pre-select the most
   named**. Then click **Search**. The
   total is exact up to 10,000; *10,000+* means at least that many match. *The same search outside the app* gives
   the request as curl and Python code, without the key value (taken from `$DT_CERT_API_KEY`, else `$DT_API_KEY`).
   As on the IrisQL page, the curl answer is piped to `jq .` and the Python prints it indented.

   **Sort by** is a field of each certificate, not a date in your query: the API orders every matching certificate by
   it before paging, so when more match than you fetch it decides which ones you get. **Order** is the direction, worded
   for the field (sent as `"order": "desc"` or `"asc"`):

   | Sort by (`field`) | Descending (`desc`) | Ascending (`asc`) |
   | --- | --- | --- |
   | Issue date (`validity_not_before`) | Newest first: the most recently issued (default) | Oldest first |
   | Expiry date (`validity_not_after`) | Latest expiry first | Soonest expiry first: expiring or expired soonest |
   | Validity length (`validity_duration_days`) | Longest first | Shortest first |
   | Key size (`public_key_bits`) | Largest first | Smallest first: weak keys |
   | SHA-256 (`sha256`) | f → 0 | 0 → f (API default): the API’s own order, sent as no `sort` |

**Step 2: pick and analyze**

| Tab | Shows |
| --- | --- |
| Domains | Registered domains the certificates name (SAN DNS, or the common name when a certificate has no SANs), with how many certificates name each and how many hostnames they have. Shared CDN names (Cloudflare SNI, Akamai, Fastly, …) are left out. The most named are ticked; *Tick* buttons change that |
| IPs | Public IPs in the certificates' SANs, to analyze as IP targets |
| Hostnames | Every hostname, wildcards included, with its registered domain. Analyzing a domain covers all of its subdomains |
| Certificates | Each certificate: common name, SANs, issuer, validation level, validity dates and days, key, self-signed flag, SHA-256 and public key SHA-256. Untick **Use** to leave a certificate's names out of the Domains, IPs and Hostnames tabs |
| Breakdown | Certificates issued per month, top issuers, validation levels, keys and domains |
| Raw JSON | The certificate records as received, with a download |

Under **Analyze the selection**, choose **Domains**, **IPs** or **Domains & IPs**, pick the **Use case** and click
the Analyze button, or click **Add to the sidebar targets**, as on the IrisQL page. Run History notes the run as *via CertsQL: …*, and **Lookup Queries → CertsQL**
shows the query and its curl request.

## Account

The **Account** page asks the DomainTools Account Information API about the account of the configured API
credentials. It runs one query the first time you open the page in a session; **Refresh** runs it again. The query
counts against the *account-information* product, not against any lookup product.

- The first line: API username, whether the account is active, how many products it has and the earliest expiry date.
- **Products this app uses**: those of Iris Investigate, Domain History, Risk evidence, Certificate search,
  Certificate events and Account information that your account has (the products the app's lookups count against), with what in the app uses each, what is
  left this month, the share used, this month's and today's queries and the rate limit per minute.
- A note lists what the app needs but the account lacks (Iris Investigate, either plan; Domain History; Risk
  evidence; Certificate search; Certificate events) and which lookups fail or are skipped without it.
- A warning names any product with 80% or more of its monthly limit used.
- **Products**: every product with today's and this month's queries, the monthly limit, what is left, the share used,
  the hour and minute rate limits and the expiry date. *Show* → *Used this month* narrows it to the products with
  queries this month. An empty monthly limit means the product only has hour or minute limits (e.g. Iris Detect).
- Both tables list only the products in the API response, so they follow each account's subscription.
- **Endpoints of file downloads** lists the feed files your account can download; **Raw response** has the full JSON.

Usage is counted by DomainTools across every client of the account (other scripts, the Iris UI, the MCP server), not
only this app. Lookups served from the cache cost no query and so do not show here.

## Offline datasets

1. Save a live run, either way:
   - before it: in **Live lookups** mode, tick **Save offline copy** in the sidebar, then click **Analyze**;
   - after it: click **Manage Data → Save offline copy** in the top menu, or **Save offline copy** on the status line at the top of any
     page. It saves the run on screen with the lookups made since (CNAME chases ...), with no new API calls, and
     links it to the run in Run History. From the top menu, **Run History → Offline Datasets** then opens with the new
     copy selected, where you can rename it (e.g. after the case or the question it answers). A run that is
     already saved, or a loaded offline dataset, just opens there. The status line then reads *Offline copy saved*.
2. Later, switch **Data source** to **Offline dataset** in the sidebar (or open **Manage Data → Run History →
   Offline Datasets**). Pick the dataset (its targets, passive DNS source and record counts are shown under it) and
   click **Load offline dataset**. The analysis opens on the Summary.
3. Change the window, thresholds or filters to re-analyze it. **No API calls are made** and no new run is saved.

Every copy is named automatically when it is saved: `dt_analysis` with the date and time, e.g. `dt_analysis
2026-11-04 09:30 UTC`. Change it with **Name** and **Save name**.

Under the selected dataset, **What's in this dataset** lists every part with:

| Column | Meaning |
| --- | --- |
| Data / Source / Holds | The part (e.g. *Passive DNS*, *VPNDB verdicts*), the service it came from and what it contains |
| Records | Rows, domains or answers it holds (0: looked up, nothing found) |
| Size | Compressed size on disk; the largest parts come first |
| Limit applied | The limit its lookups ran with, from the run's collection options, e.g. *Up to 5,000 records per domain; TXT supplement: latest 10 per domain*; *Off* when that lookup was not on |

**Lookups that stopped at a limit** lists the lookups that returned as many records as their limit allows, so there
may be more: raise the limit under *Settings → Collection options* and analyze again to fetch them.

Datasets are gzipped JSON (never pickle), stored with owner-only permissions and linked to the run they came from.
Manage them under **Manage Data → Run History → Offline Datasets**: rename, delete (with confirmation), and set how
many are kept (default 20).

## Where local data is stored

Everything below lives in the project folder and is git-ignored.

| Path | Contents |
| --- | --- |
| `dt_runs/` | Saved runs per target list: alerts, risk, DIF and infrastructure (default: last 10 per list) |
| `dt_offline/` | Offline datasets (default: last 20) |
| `dt_suppressions.json` | Alert suppressions |
| `dt_triage.json` | Triage status of alerts and domain verdicts, with notes |
| `dt_settings.json` | Saved settings, such as retention limits and watched target lists |
| `dt_token.json`, `dt_session_data/` | Iris pDNS browser session |

Credentials are not stored in the project folder.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| A data source returns nothing | Open **Data Source Status** (collapsed under the analysis window banner). Each lookup shows OK / Partial / No data / Error with the reason: authentication failure, rate limit, timeout or truncated results. |
| "Credentials not found" errors | Open *Settings → API credentials* and **All options**: every option shows whether it is set and used, and why not. Missing keys can be entered there under **Enter API keys**. |
| Environment variable changes are ignored | Restart the app; variables are read at start. |
| A domain has no alerts and an info box says it was skipped | Its known DomainTools risk score is below **Min Risk Score**. Lower the threshold to evaluate it. |
| "N older detection(s) fall outside this window" | Choose a longer analysis window or *All time*, or expand **Detections outside the window**. |
| Iris pDNS asks for login every run | Log in through the browser window that opens and close it once Iris has loaded; the session is reused afterwards. |
| The page dims for a moment after a change | Streamlit reruns the page after each change. Page switches reuse the data already prepared, and filters inside Hostname Inventory, Subdomain Triage, Pivot Ranking, CNAME Chains, Lookup Queries and Data Export rerun only that section. Changing the domains, record types, analysis window, timezone or hostname focus rebuilds the data, which takes longer for runs with many domains or records. Data Export builds its files only when you click **Download**. |
| Results marked *Partial* | The source hit its result limit (Iris pDNS: 500 records; DNSDB: your limit). Raise the DNSDB limit or rely on the supplemental TXT / CAA / CNAME lookups. |
| CNAME Chains shows *Not chased* everywhere | Chains are filled in on demand. Select hostnames (or none for all shown) and click **Chase CNAMEs**; click again when the toast says names wait for the next click. A DNSDB key is needed for chains that leave the collected data. |
| No or few CNAME records for a busy domain | The main passive DNS lookup hit its limit with A / NS records. Keep *Supplemental CNAME lookup* on and re-run, and pick a longer analysis window (*All time*) to see older CNAMEs. A domain with thousands of CNAME hostnames can still fill the 5,000-record supplement. |
