# DomainTools Analytics and Detection

An unofficial Streamlit tool that combines several DomainTools data sources (Iris Investigate with its risk scores,
Domain History, passive DNS from DNSDB Scout or Iris pDNS, and the Certificate API with search, hostname / IP /
SHA-256 events and CT logs) with VPNDB's VPN, residential proxy and Tor attribution of IPs, and runs a behavioral
threat engine over the combined telemetry.

## Documentation

| Guide | Covers |
| --- | --- |
| [Workflows](docs/WORKFLOWS.md) | **Start here if you are new:** what happens after *Analyze*, the order and logic of every data collection (with diagrams), and what each source is used for |
| [Use Cases](docs/USE_CASES.md) | The investigations the tool supports: what to enter, where to look in the results, and what each one surfaces |
| [Installation](docs/INSTALLATION.md) | Requirements, install, **credentials** (entering keys in the app, environment, `credentials.toml`, files, the API Credentials panel), starting the app, development |
| [Usage](docs/USAGE.md) | Running an analysis, every option, offline datasets, where local data is stored, troubleshooting |
| [Reference](docs/REFERENCE.md) | Everything preconfigured: what each **use case** looks up, the **brand watchlist**, every **collection limit**, the **built-in lists** (hosting watchlist, impersonated brands, takeover-prone services, ...) and the files the app keeps |
| [User Guide](docs/USER_GUIDE.md) | Reading the results: alerts and grouping, **severity / confidence / category**, the full **detection catalogue**, **MITRE ATT&CK mapping**, **Unified Risk** vectors, **DIF fingerprints**, clusters and domain hopping, thresholds, run history, suppressions and exports |

## What it does

- **Collects** domain, DNS, certificate and enrichment data per target, with per-source status so errors and
  truncated results are never silent. Targets can be domains, IPs, or certificates (fingerprints, CN, SAN,
  public key, serial, organization, issuer), which are resolved to the domains and IPs they cover. Where passive DNS
  stops at its limit, TXT, CAA and CNAME lookups fill in what the detections need.
- **Detects** 72 behaviors (fast-flux, parked-to-weaponized, CAA breaches, abnormal certificate rotation, DNS tunneling,
  dangling CNAMEs, shared infrastructure, domain hopping, lookalikes, ...), each with a severity, a confidence, a
  category and a MITRE ATT&CK technique.
- **Chases CNAME chains** like DNSDB Scout: every alias followed to its final addresses, with the target service
  (dynamic DNS / tunnel, takeover-prone, free hosting, CDN), dead ends that point to subdomain takeover, and the
  names and addresses that link the analyzed domains through their chains; reverse CNAME (RDATA) lookups find
  other domains pointing to the same targets.
- **Attributes anonymizers** with VPNDB: which hosting IPs are VPN, residential proxy or Tor exits and whose, whether
  an exit is shared (it identifies the service, not the actor) or dedicated, whether the IP was an exit while the
  domain used it, the ranges and networks around the hosting, and other domains on dedicated exits. Every use case
  checks VPNDB within its own query budget; *Check IP addresses* looks up IPs and CIDR ranges in VPNDB only, with
  every address of a range checked.
- **Finds targets with IrisQL**: an Iris Investigate query in IrisQL (`domain contains "domaintools"`) lists the
  matching domains with their risk, dates, registrar and hosting (menu *IrisQL*, or Data source *IrisQL* in the
  sidebar); tick domains and IPs, pick a use case and analyze them. The query editor suggests the fields, then only
  the operators each field accepts, then the value in the right form.
- **Finds targets with CertsQL**: a Certificate Search query in CertsQL (`san_dns contains "login"`) lists the
  matching certificates with the domains, IPs and hostnames they name (menu *CertsQL*, or Data source *CertsQL*); the
  query is checked against the CertsQL field catalog before it is sent, with the same autocomplete as IrisQL. Tick
  domains and IPs and analyze them.
- **Ranks pivots**: every IP, name server, email, registrant, certificate and tracker in Iris Investigate, by how many
  domains share it, so rare links to the same operator come first; one click finds their other domains in Iris.
- **Triages subdomains** on shared platforms (pages.dev, workers.dev, free subdomain services) by phishing words,
  brands, embedded domains, generated names and bursts of new names.
- **Groups** alerts by finding, campaign cluster, domain or ATT&CK technique, with every related event in time
  order and pivotable artifacts (certificate hashes, IPs).
- **Scores** each domain with a Unified Risk score and a Domain Infrastructure Fingerprint (DIF) that exposes shared
  setups across domains.
- **Inventories hostnames** from certificates, passive DNS and certificate events, with lifecycle flags and each
  hostname's certificate hashes; a hostname focus narrows every view to chosen hostnames.
- **Tracks** runs over time: changes since the last run, first-detected alerts, trends, per-domain history,
  offline re-analysis without API calls; with *Monitor changes*, re-runs fetch only new passive DNS records.
- **Watches API usage**: the sidebar estimates each run's queries per product against what the account has left,
  every lookup records the queries it made (Data sources, Runs & Diffs), sources missing from the account are
  skipped, and the Account page shows DomainTools, DNSDB and VPNDB quotas. Independent sources are collected at the
  same time, each source keeps cached results for its own lifetime, and failed lookups can be retried on their own.
- **Rebuilds every lookup** as a query or `domaintools` / curl command to re-run in the DomainTools, DNSDB and VPNDB
  tools, and keeps every VPNDB answer as received.
- **Exports** detections, IOCs (CSV / JSON), STIX 2.1 bundles and HTML / Markdown evidence reports, and hands IOCs,
  tables and raw records to other teams as CSV / NDJSON.

## Quick start

```bash
python3 -m venv ~/.venv/dt_analytics_detection
source ~/.venv/dt_analytics_detection/bin/activate
pip install -r requirements.txt
```

For the optional Iris pDNS provider, also run `playwright install chromium`. Then start the app:

```bash
streamlit run app.py
```

**Add your API credentials in the app.** Open *Settings → API credentials → Enter API keys* (the sidebar links there
while a key is missing; the form opens by itself), enter the keys and click **Save to credentials.toml**:

| Key | Needed for |
| --- | --- |
| DomainTools API username and key | Iris Investigate (with the risk scores), Domain History, IrisQL, the Account page; also the Certificate API |
| DNSDB API key | Passive DNS through DNSDB Scout, CNAME chasing and IP pivots (optional with Iris pDNS) |
| Certificate API key | Optional: only if it differs from the DomainTools API key |
| VPNDB API key | Optional: the VPN, residential proxy and Tor check of hosting IPs |

The keys are saved to `~/.config/dt-analytics/credentials.toml`, outside the project folder (so they cannot be
committed), readable only by your user; they are never shown again. The panel above the form shows which source each
service uses. Environment variables and the `~/.dtapi` / `~/.dtdnsdb` files work too, and environment variables win
over the file; see [Credentials](docs/INSTALLATION.md#credentials).

Pick a use case on the **Start** page (optional), enter target domains, IPs or certificate fingerprints (or `cn:`,
`san:`, `spki:`, ... lines) in the sidebar and click **Analyze**: the **Summary** opens with what to check next. The
top menu groups every page (Overview, Infrastructure, Hunt, Evidence, Settings, Account, Help); see
[The app at a glance](docs/USAGE.md#the-app-at-a-glance) and [Certificate inputs](docs/USAGE.md#certificate-inputs).

## Project structure

```
app.py                         Streamlit entry point: top navigation, sidebar, collection, filtering, page functions
config.py                      Branding, paths, collection limits, threshold registry (ThresholdSpec)
docs/                          Workflows, Use Cases, Installation, Usage, User Guide and Reference

core/
  helpers.py                   Refanging, target parsing, registrable domains, IP extraction, safe booleans, markdown escaping
  idn.py                       International domain names: Unicode to punycode (xn--) for lookups, and back for display
  caa.py                       CAA (RFC 8659) policy parsing and issuer authorization
  intel_data.py                Reference data: CDN ranges, parking/large DNS providers, hosting watchlist, impersonated brands, shared platforms, takeover-prone and dynamic DNS CNAME services, ATT&CK tactics, rule metadata
  cert_inputs.py               Target input recognition, certificate-input CertsQL queries, derived targets
  certsql.py                   CertsQL page logic: field catalog checks, examples, certificate / domain / IP tables
  account.py                   Account Information rows: product names, usage, limits and what is left, expiry; the products each collection stage needs
  api_usage.py                 API usage: service / product of each lookup, queries per run, failed lookups, what is left, Data sources statistics
  query_assist.py              IrisQL / CertsQL editor suggestions: fields, each field's operators, value templates, flagged lines
  hostnames.py                 Hostname focus filter, Hostname Inventory (lifecycle, flags) and hostname-certificate links
  pivots.py                    Pivot Ranking: shared Iris Investigate values ranked by Iris pivot count
  subdomain_triage.py          Subdomain Triage: name and lifecycle signals, score and level per subdomain
  cname.py                     CNAME chains: target service types, chains through collected data and DNSDB chases, per-domain chase plan, cross-domain links
  use_cases.py                 Use cases and custom profiles: collection options, window, plan, lookups and limits
  next_steps.py                Summary's "What to check next": findings turned into steps that point at a page
  hunt_stats.py                Summary statistics: analysis details, alerts by category, shared infrastructure, weekly activity, lifecycle, data health, cluster callouts
  hunt_tree.py                 Hunt tree: which run a run was started from, the trail to any run and every hunt as a tree
  triage.py                    Triage status of alerts and domain verdicts (New, Investigating, Benign, Malicious), kept in dt_triage.json
  self_signed.py               Self-signed certificates rated Critical to Low, with the reasons and what to do
  lookup_queries.py            A run's lookups rebuilt as queries and commands for the DomainTools and DNSDB tools
  rule_catalog.py              Detection reference: per-rule trigger, rationale, severity and confidence levels
  alert_grouping.py            Merging repeated alerts; grouping by finding, cluster, domain, ATT&CK technique; related events
  anonymizers.py               VPNDB verdicts of the run's hosting IPs: which IPs are checked, one row per IP, shared exits,
                               Iris cross-check, exit history overlap, neighbouring /24s, hosting ASNs, exit neighbours
  network_intel.py             CDN attribution, ASN-aware network keys, hosting watchlist, origin-IP discovery
  lookalike.py                 Typosquatting, homoglyph/IDN, combosquatting, and brand-in-subdomain analysis
  correlation.py               Shared-infrastructure clusters (IPs, name servers, CNAME targets, certificates, trackers) and domain hopping
  timeline.py                  Per-domain story timeline events
  window.py                    Analysis window (presets / custom range) and record filters
  persistence.py               Suppressions, saved settings, watched target lists, run snapshot store (save, list, rename, delete, retention, export)
  run_history.py               Snapshot normalization, run comparison, alert lifecycle, trends, per-domain history
  offline.py                   Offline datasets: save / load / manage collected data (gzipped JSON, no pickle)
  export.py                    IOC lists, confirmed indicators, STIX 2.1 bundles, MISP events, HTML/Markdown evidence reports
  data_export.py               Data Export page: IOCs, tables and raw records as CSV / NDJSON, zipped with a manifest
  cert_utils.py                Certificate helpers (weak keys, duration, self-signed, IP names)
  pdns_features.py             Shared pDNS / Domain History feature engineering (gaps, lifespans, tempo)
  timezone.py                  Timezone shifting for display frames
  dataset.py                   Builds filtered, merged, timezone-shifted frames for the views
  risk_profile.py              Unified risk vectors and their drivers, Domain Infrastructure Fingerprints (DIF) and their decoding
  threat_detection/
    engine.py                  detect_threat_flags(): per-domain contexts, rule execution, alert merging, ThreatResult
    context.py                 DomainContext, alert builder and structured evidence shared by all rules
    dns_rules.py               DNS / pDNS / Domain History rules (fast-flux, parked-to-weaponized, SPF, TXT, ...)
    anonymizer_rules.py        VPNDB rules (Tor / residential / VPN exit, dedicated exit, moved onto or rotating across exits,
                               new domain on an exit, exit shared by analyzed domains, hosted among exits; exit
                               history decides whether an exit counted while the domain used it)
    cname_rules.py             CNAME rules (dangling / takeover-prone, dynamic DNS, free hosting, retargeting, long chains, cross-domain CNAME links)
    ssl_rules.py               Certificate rules (CAA, Mega-SAN, bare-IP, churn, CA/B validity, short-lived, ...)
    enrichment_rules.py        Iris rules (piracy panels, shared trackers, current MX / SPF) and lower confidence for popular domains
    intel_rules.py             Registration age, hosting watchlist, redirects, parking, ASN-aware flux, volume anomalies,
                               CDN origin exposure, lookalikes
    txt_fingerprints.py        TXT SaaS fingerprinting and encoded-payload detection

integrations/
  collector.py                 Runs all collection stages (parallel where safe), pDNS record-type lookups, on-demand CNAME chases (per-domain query budget), and records per-source status
  http.py                      Shared requests session with retry/backoff, DomainTools SDK retries, per-lookup query count, FetchResult, StatusLog
  cache.py                     Lookup cache (memory and dt_cache/ on disk) with the analyst's lifetime and each source's own
  credentials.py               Credential resolution (environment, credentials.toml, files), source overview, saving keys entered in the app
  certificates.py              Certificate Search (incl. CertsQL searches) / Events / CTL APIs and X.509 normalization
  dnsdb.py                     DNSDB v2 (SAF/NDJSON streaming, incremental lookups), Scout-style CNAME chasing, the key's quota
  vpndb.py                     VPNDB API: VPN / residential proxy / Tor attribution of IPs, prefixes, ASNs; every operation, paging, bulk, quota
  domain_history.py            Domain History (SDK) parsing and lifespans
  risk.py                      DomainTools risk scores from the Iris Investigate records
  account.py                   Account Information (SDK): products, limits and usage, kept for an hour and shared
  estimate.py                  Cost estimate of the next Analyze (no query; cached lookups left out)
  enrichment.py                Iris Investigate (SDK, batched), pivot searches, IrisQL searches (JSON POST) and web tracker extraction
  iris.py                      Iris pDNS via an authenticated Playwright session: one session check, then parallel workers, cached

views/                         One module per page + sidebar, alert tools, certificate-input preview, data export, shared helpers:
  navigation.py                Top menu (page groups, Analyst mode), links and filtered jumps between pages
  home_view.py                 Start page (use cases)
  analyze_selection.py         IrisQL / CertsQL step 2: analyze the ticked domains, IPs or both with a use case
  certsql_view.py              CertsQL page (menu, or Data source CertsQL): Certificate Search query, pick certificates / domains / IPs, analyze them
  irisql_view.py               IrisQL page (menu, or Data source IrisQL): query Iris Investigate, pick domains / IPs, analyze them with a use case
  query_editor.py              IrisQL / CertsQL query editor with autocomplete (CodeMirror 5, bundled in views/assets/codemirror)
  summary_view.py              Summary: KPIs, domains, analysis details, top alerts, hunt status, plan, what to check next, leads, linked domains, run statistics, what's new
  hunt_actions.py              Hunt buttons shared by pages: analyze a value as a new linked run, find a value's domains in Iris
  idn_display.py               "Show international domains in Unicode": decodes xn-- names where tables, text and charts are drawn
  profile_view.py              Domain profile: one domain on one screen
  history_cap.py               Domains whose Domain History stopped at Max changes: notice and Fetch the rest
  vpndb_page.py                VPNDB page (which VPN or proxy provider operates behind an IP, prefix or ASN): flow,
                               heatmap, providers, countries, exposure timeline, Iris cross-check, neighbourhood, leads
                               on dedicated exits, CIDR address grids
  tor_page.py                  Tor network page (Infrastructure): network-wide Tor statistics from VPNDB's /tor overview
  ip_card.py                   One IP in full: VPNDB verdict and whole answer, weekly history, where the run saw it,
                               Iris, its /24 and network, Tor share; fetches a full verdict on demand
  anonymizer_view.py           VPNDB building blocks shared by the pages: tables, verdict cards, links, CIDR range cards
  settings_view.py             Settings: collection options, use cases & profiles, thresholds, brand watchlist, cache, credentials
  account_view.py              Account: DomainTools account, product limits, usage this month and today, expiry; DNSDB and VPNDB quotas
  api_usage_view.py            What each service has left, skipped products
  sources_view.py              Data sources: the run in numbers, lookups per source by status, by source / target, needs attention, API queries, all lookups
  docs_view.py                 In-app documentation (Help → Documentation, /docs)
visualizations/sankey.py       Hostname ➔ Cert ➔ IP Sankey with step navigation
visualizations/network_graph.py Infrastructure graph (numpy force-directed layout)
scripts/generate_docs_tables.py Regenerates the User Guide and Reference tables from the code
tests/                         pytest suite (pure functions, parsers, threat rules, reference tables, docs)
.streamlit/config.toml         Streamlit theme
```

## Development

```bash
pip install -r requirements-dev.txt
pytest
ruff check .
```

The detection catalogue in [core/rule_catalog.py](core/rule_catalog.py) is checked against the rule code by the
tests, and the User Guide is checked to list every rule and threshold. After changing a rule, threshold, DIF code,
collection limit, use case or built-in list, regenerate the User Guide and Reference tables with
`python scripts/generate_docs_tables.py`; the tests fail while they are out of date.
