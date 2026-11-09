# Reference

Everything the app has preconfigured: what each use case looks up, the limits of every lookup, the built-in lists the
detections match against, your brand watchlist, and the files the app keeps. The tables are generated from the code
(`python scripts/generate_docs_tables.py`), so they always match what the app does.

## Contents

- [Use cases and profiles](#use-cases-and-profiles)
- [Brand watchlist](#brand-watchlist)
- [Collection limits](#collection-limits)
- [Other built-in values](#other-built-in-values)
- [Built-in lists](#built-in-lists)
- [Files the app keeps](#files-the-app-keeps)

## Use cases and profiles

A use case is a full set of **collection options** (which lookups a run makes and their limits) plus an **analysis
window**. They build on one set of **global defaults**, the options the app starts with:

- **Global defaults**: the *Global default* column below. They are also what *Settings → Collection options* shows in a
  new session.
- **Use cases**: the six cards on the Start page. Each one is the global defaults with a few changes that suit it
  (the other columns). **Use this** copies its options into *Settings → Collection options* and sets the window in the
  sidebar; **Analyze** then runs with them.
- **Your changes to a use case**: on *Settings → Use cases & profiles* pick a use case, change its options and
  **Save**. From then on the Start page applies your version (its card says *changed on Settings*). **Reset to
  default** brings back the built-in options.
- **Custom profiles**: your own named sets of options for investigations the six use cases do not cover. Create one on
  *Settings → Use cases & profiles* (starting from the current options or from a use case), change it, **Save**. It
  appears on the Start page under *Your profiles*. Profiles have no page plan.
- **Collection options** (*Settings → Collection options*) are what the **next Analyze** uses. Changing them there
  lasts for this browser session only; the sidebar shows the selected use case and *(options changed since)* when they
  no longer match it.

Use case changes and profiles are saved in `dt_settings.json`, so they survive a restart.

**What each option looks up**, per target domain (the same table is shown on each Start page card and on the Settings
tabs for the options being edited):

| Option | Lookup | Limit |
| --- | --- | --- |
| *(always)* | Iris Investigate: registration, current hosting, risk score and its evidence, website and trackers | batches of 100 domains |
| *(always)* | Domain History: registration, DNS and certificate changes | 1,000 changes (Max changes) |
| Domain History period, Max changes | Domain History: the latest changes (default), only those of the analysis window, or of a custom number of days, each up to *Max changes*; or all time with no limit. Paging stops at the first older change or at *Max changes*; a domain that reaches it is reported as having more changes | 100 changes per query; Max changes 100–20,000; no limit stops at 50,000 |
| *(always)* | Certificate API: certificates naming the domain, and certificate events | 2,500 each |
| Passive DNS provider, DNSDB result limit | DNSDB Scout: the domain and every subdomain, all record types (Iris pDNS: 500 records) | the limit you pick |
| TXT lookup | DNSDB TXT records, only when the main lookup hit its limit | 500 fetched, latest N kept |
| CAA lookup | DNSDB CAA record of the domain, only when the main lookup hit its limit | 100 records |
| CNAME lookup | DNSDB CNAME records of the domain and its subdomains, only when the main lookup hit its limit | 5,000 records |
| Pivot on hosting IPs | DNSDB: other domains seen on each current hosting IP (DNSDB Scout only) | the max IPs per run, 2,000 records each |
| Incremental passive DNS | DNSDB: only records seen since a day before the last offline copy of the same targets, plus that copy's older records (DNSDB Scout only; a full lookup without a copy) | the limit you pick |
| VPN / proxy / Tor check (VPNDB) | VPNDB: verdict of the run's public IPv4 hosting addresses and of CIDR targets (only with a VPNDB key); full verdict and weekly history of the exits | *Hosting IPs per run* in one bulk request (500 by default), *Full verdicts per run* exits (50), two queries each |
| VPNDB: neighbourhood and leads | VPNDB: the /24 around each non-exit hosting IP and the Iris hosting ASNs; DNSDB: other names on dedicated exits | 30 ranges, 20 networks, 10 DNSDB lookups of 1,000 records |
| Only the VPNDB IP check | VPNDB only: IP targets and CIDR ranges; no other source, domain targets skipped | one bulk request, full verdict of up to *Full verdicts per run* IPv4 targets (100 in *Check IP addresses*), 20 ranges |
| CT log & co-occurrence telemetry | Certificate API: CT log entries and the hosts seen with each certificate, newest certificates first | the max certificates per run, two calls each |

The analysis window does not change any lookup: it filters what the pages, alerts and scores show. CNAME chases and
reverse CNAME lookups are not part of a run; they run when you click them on the CNAME Chains page.

Options per use case (generated from `core/use_cases.py`):

| Option | Global default | Triage a suspicious domain | Map related infrastructure | Hunt C2 infrastructure | Subdomain takeover check | Phishing & lookalikes | Monitor changes | Check IP addresses (VPN, proxy, Tor) | Report & export evidence |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Passive DNS provider | DNSDB Scout | · | · | · | · | · | · | · | · |
| DNSDB result limit per domain | 5,000 | · | · | · | · | · | · | · | · |
| TXT lookup | on | · | · | · | off | · | · | · | · |
| Latest TXT records per domain | 10 | · | · | · | · | · | · | · | · |
| CAA lookup | on | · | off | · | off | · | · | · | · |
| CNAME lookup | on | · | · | · | · | · | · | · | · |
| Pivot on hosting IPs | off | · | on | on | · | · | · | · | · |
| Max IPs to pivot on | 10 | · | · | · | · | · | · | · | · |
| Incremental passive DNS | off | · | · | · | · | · | on | · | · |
| Domain History period | all | · | · | · | · | · | days | · | · |
| Domain History period (days) | 365 | · | · | · | · | · | 90 | · | · |
| Domain History changes per domain | 1,000 | · | · | · | · | · | · | · | · |
| VPN / proxy / Tor check (VPNDB) | on | · | · | · | · | · | · | · | · |
| VPNDB: hosting IPs per run | 500 | 100 | · | · | 100 | 200 | 200 | · | · |
| VPNDB: full verdicts per run | 50 | 20 | · | · | 10 | 20 | 20 | 100 | · |
| VPNDB: neighbourhood and leads | on | · | · | · | off | off | off | · | · |
| Only the VPNDB IP check | off | · | · | · | · | · | · | on | · |
| CT log & co-occurrence telemetry | on | · | · | · | · | · | · | · | · |
| Max certificates for CT lookups | 10 | · | · | · | · | 100 | · | · | · |
| Certificate inputs: pre-selected targets | 10 | · | · | · | · | · | · | · | · |
| Analysis window | Last 30 days | · | All time | Last 90 days | All time | · | · | All time | · |

A dot (·) means the use case keeps the global default.

## Brand watchlist

The brands you protect, set on **Settings → Brand watchlist** (saved in `dt_settings.json`). It is empty until you
add to it. The **Lookalike / Brand** detections compare every analyzed domain against it:

| Detection | Fires when (example for the brand `paypal`) |
| --- | --- |
| Typosquatting Lookalike | One letter added, missing, swapped or changed (two for brands over 7 letters): `paypa.com`, `paypall.com`, `pyapal.com` |
| Homoglyph / IDN Brand Impersonation | Reads as the brand once look-alike letters are mapped, other alphabets included: `paypa1.com`, `pаypal.com` (Cyrillic `а`) |
| Combosquatting (Brand + Keyword) | The brand inside a longer name: `paypal-help.com`; High with a [phishing keyword](#phishing-keywords) (`paypal-login.com`), Medium without |
| Brand Name on Alternate TLD | The exact brand on a domain that is not an official one: `paypal.net` |

How to fill it in:

- One entry per line or comma-separated. A word (`paypal`) is a brand name.
- A domain (`acme.com`, `acme.co.uk`) adds its first label as a brand **and** marks that domain as the brand's own:
  it is never flagged. Add every official domain of a brand this way.
- Entries shorter than four characters are ignored (they match too much).
- A brand with no official domain listed treats its `.com` as its own: `paypal.com` is not flagged, `paypal.net` is.
- Saving re-runs the detections on the loaded data at once, with no new lookups.

Without a watchlist, only internationalized (punycode, `xn--`) domains are flagged (*IDN / Punycode Domain*). The
detections check the analyzed domains; hostnames with a brand in a subdomain label are ranked by Subdomain Triage.

The brand watchlist is not the [Impersonated brands](#impersonated-brands) list: that built-in list of brands phishing
kits copy most (Microsoft, PayPal, DHL, ...) is used by Subdomain Triage and the CNAME rules, needs no setup and does
not change the lookalike detections.

## Collection limits

How much each lookup fetches. The options on *Settings → Collection options* change some of them per run; the rest
are fixed in `config.py`. A lookup that reaches its limit is marked *Partial* on the Data sources page.

Limits (generated from `config.py`):

| Setting in config.py | Value | What it limits |
| --- | --- | --- |
| `DNSDB_LIMIT_OPTIONS` | 10, 50, 100, 500, 1,000, 2,000, 5,000, 10,000, 25,000, 50,000, 100,000, 1,000,000 | choices of the DNSDB result limit (Settings) |
| `DNSDB_DEFAULT_LIMIT` | 5,000 | DNSDB records fetched per target by the main passive DNS lookup (Settings) |
| `IRIS_PDNS_LIMIT` | 500 | Iris pDNS records fetched per target by the main lookup |
| `TXT_SUPPLEMENT_DEFAULT_RECORDS` | 10 | latest TXT records kept per domain by the TXT lookup |
| `TXT_SUPPLEMENT_FETCH_LIMIT` | 500 | DNSDB TXT records fetched per name before trimming to the latest N |
| `CAA_SUPPLEMENT_FETCH_LIMIT` | 100 | DNSDB CAA records fetched for the apex name (all are kept) |
| `IRIS_SUPPLEMENT_FETCH_LIMIT` | 100 | Iris pDNS records requested per record-type lookup query |
| `CNAME_SUPPLEMENT_FETCH_LIMIT` | 5,000 | DNSDB CNAME records fetched (name and subdomains) when the main query was cut off |
| `CNAME_CHASE_MAX_STEPS` | 10 | names followed per CNAME chase (DNSDB Scout's CNAME chasing limit) |
| `CNAME_CHASE_RECORD_LIMIT` | 500 | DNSDB records fetched per chased name and record type |
| `CNAME_CHASE_QUERIES_PER_DOMAIN` | 10 | DNSDB queries a CNAME chase click may spend per domain (cached lookups are free) |
| `CNAME_RDATA_MAX_PER_CLICK` | 10 | names looked up per click of a reverse CNAME lookup |
| `CNAME_RDATA_RECORD_LIMIT` | 5,000 | names per reverse CNAME (RDATA) lookup |
| `DOMAIN_HISTORY_MAX_CHANGES` | 1,000 | Domain History: default Max changes fetched per domain (Settings can change it) |
| `DOMAIN_HISTORY_CAP_MAX` | 20,000 | highest Max changes the Settings field accepts |
| `DOMAIN_HISTORY_SAFETY_LIMIT` | 50,000 | "All time, no limit" still stops here (500 queries), so a run cannot page forever |
| `POPULAR_RANK_MAX` | 10,000 | Iris popularity rank up to which a domain counts as popular (lower confidence) |
| `MONITOR_HISTORY_DAYS` | 90 | Monitor changes use case: Domain History period (days of changes fetched) |
| `CERT_SEARCH_MAX_RECORDS` | 2,500 | certificates fetched per target by the certificate search |
| `CERT_EVENTS_MAX_RECORDS` | 2,500 | certificate events (hostnames / IPs seen with a certificate) per domain or IP |
| `CERT_SHA256_EVENTS_MAX_RECORDS` | 1,000 | events per certificate hash (certificate inputs and CT co-occurrence) |
| `CERT_EVENTS_LOOKBACK_DAYS` | 365 | Certificate Events time window (API default 30 days, maximum 366) |
| `SEED_MAX_CERTIFICATES` | 200 | certificates fetched per certificate input (hash, CN, SAN, ...) |
| `SEED_DEFAULT_TARGETS` | 10 | derived domains / IPs pre-selected in the certificate input preview |
| `SEED_MAX_TARGETS` | 100 | most derived domains / IPs one run may analyze |
| `HOSTNAME_NEW_DAYS` | 30 | Hostname Inventory: a hostname first seen this recently is flagged "New" |
| `PIVOT_STRONG_MAX` | 500 | Pivot Ranking: a value shared by 2..this many domains in Iris is a strong pivot |
| `PIVOT_USEFUL_MAX` | 10,000 | ... up to this many a useful one; more is weak (shared infrastructure) |
| `PIVOT_RESULT_LIMIT` | 500 | Pivot Ranking: domains fetched per Iris Investigate pivot search (one page) |
| `TRIAGE_BURST_MIN` | 5 | Subdomain Triage: hostnames of one domain first seen in the same hour to count as a burst |
| `CERT_CTL_LIMIT` | 500 | CT log entries fetched per certificate (CT telemetry) |
| `CT_LOOKUP_DEFAULT_MAX_HASHES` | 10 | two lookups per certificate; newest first, shared across domains |
| `IRIS_INVESTIGATE_BATCH_SIZE` | 100 | domains per Iris Investigate request |
| `IRISQL_PAGE_SIZE` | 500 | IrisQL search: domains per Iris Investigate request (one page) |
| `IRISQL_DEFAULT_RESULTS` | 500 | IrisQL search: domains fetched by default (pages are requested until this many) |
| `IRISQL_MAX_RESULTS` | 5,000 | IrisQL search: most domains one search may fetch |
| `CERTSQL_PAGE_SIZE` | 500 | CertsQL search: certificates per Certificate Search request (API maximum) |
| `CERTSQL_DEFAULT_RESULTS` | 500 | CertsQL search: certificates fetched by default |
| `CERTSQL_MAX_RESULTS` | 5,000 | CertsQL search: most certificates one search may fetch |
| `PIVOT_DEFAULT_MAX_IPS` | 10 | hosting IPs pivoted on per run (Settings: Max IPs to pivot on) |
| `PIVOT_IPS_PER_DOMAIN` | 3 | hosting IPs picked per domain before the run-wide maximum applies |
| `PIVOT_IP_RECORD_LIMIT` | 2,000 | DNSDB records fetched per pivot IP |
| `VPNDB_MAX_IPS` | 500 | hosting IPs checked in VPNDB per run (one bulk request; each IP is one query) |
| `VPNDB_IPS_PER_DOMAIN` | 100 | most recently seen IPs per domain before the run-wide maximum applies |
| `VPNDB_DETAIL_MAX` | 50 | anonymous IPs given the full verdict (sharing, Tor, evidence), one query each |
| `VPNDB_HISTORY_MAX` | 50 | anonymizer exits given their weekly history (exit while the domain used it?) |
| `VPNDB_NEIGHBOUR_MAX` | 30 | /24 ranges around non-exit hosting IPs looked up for known exits |
| `VPNDB_ASN_MAX` | 20 | hosting networks (Iris ASNs) looked up for the providers on them |
| `VPNDB_REVERSE_MAX` | 10 | dedicated exits whose other domains are looked up in DNSDB (rdata/ip) |
| `VPNDB_REVERSE_LIMIT` | 1,000 | DNSDB records per dedicated exit |
| `IP_CHECK_MAX_IPS` | 100 | IP check use case: IP targets given the full verdict, one query each |
| `CIDR_MAX_RANGES` | 20 | CIDR targets looked up in VPNDB per run (one prefix query each) |
| `CIDR_IP_CHECK_MAX` | 1,024 | addresses of one CIDR range bulk-checked one by one in VPNDB (a /22); a query each |
| `CIDR_IP_CHECK_TOTAL` | 4,096 | addresses of all CIDR ranges bulk-checked per run |
| `CIDR_ADDRESSES_PER_RANGE` | 200 | addresses VPNDB probing exited through in each range (last 30 days); a query a row |
| `MAX_WORKERS` | 8 | lookups run in parallel |
| `IRIS_PDNS_WORKERS` | 3 | Iris pDNS targets looked up at the same time (after the session check) |
| `CERT_API_MAX_WORKERS` | 4 | SHA256 / CT log lookups run per certificate; more parallel calls trigger HTTP 503s |
| `CERT_RETRY_PAUSE_SECONDS` | 5 | pause before failed certificate lookups are retried once, one at a time |
| `FETCH_CACHE_TTL_SECONDS` | 86,400 | default cache lifetime of successful lookups (Settings → Lookup cache) |
| `CACHE_GROUPS` | pdns: Passive DNS (DNSDB, Iris pDNS), iris: Iris Investigate (enrichment, risk, IrisQL), history: Domain History, certs: Certificates (search, events, CT log), vpndb: VPNDB | Source groups that can keep cached results for their own lifetime (Settings → Lookup cache) |
| `CACHE_GROUP_DEFAULTS` | history: 604,800, vpndb: 21,600 | changes rarely: 7 days; changes often: 6 hours |
| `CACHE_LIFETIMES` | Off: 0, 30 minutes: 1,800, 6 hours: 21,600, 1 day: 86,400, 7 days: 604,800, 30 days: 2,592,000 | cache lifetime choices on Settings → Lookup cache: label -> seconds (0: no cache) |

## Other built-in values

Values (generated from `config.py` and `core/window.py`):

| What | Value |
| --- | --- |
| Severity weights (risk vectors and Unified Risk) | Critical: 90, High: 70, Medium-High: 60, Medium: 40, Low: 20 |
| Analysis window choices | Last 7 days, Last 14 days, Last 30 days, Last 60 days, Last 90 days, Last 180 days, Last 365 days, All time, Custom range |
| Cache lifetime choices | Off, 30 minutes, 6 hours, 1 day, 7 days, 30 days |
| Default cache lifetime | 24 hours |
| Hostname counted as New (Hostname Inventory) | first seen within 30 days |
| Pivot strength (Pivot Ranking) | strong: shared by 2–500 domains in Iris; useful: up to 10,000; weak: more |
| Burst of new subdomains (Subdomain Triage) | 5+ first seen in the same hour |
| Offline datasets kept (default; change on Offline Datasets) | 20 newest |
| Run snapshots kept per target set (default; change on Runs & Diffs) | 10 newest |
| Rows shown in raw tables | 50,000 |
| Quota banner (products this app uses, DNSDB key) | yellow from 95% of the quota used or 30 days before expiry; red when used up or expired |

## Built-in lists

Curated lists the detections and pages match against. They are snapshots: review and extend them in the named file for
your environment. A match is a lead to check, not proof of abuse.

The lists (generated from the modules named under each one):

### Hosting watchlist

`HOSTING_WATCHLIST` in `core/intel_data.py`, 14 entries. High-abuse / offshore hosting watchlist (ISP name fragments, lowercase). Editable; verify before acting.

**Used by:** *Hosting Watchlist* alert, the Watchlist column on DNS & Hosting

`stark industries`, `aeza`, `zservers`, `proton66`, `flokinet`, `alexhost`, `shinjiru`, `njalla`, `pq hosting`, `private layer`, `frantech`, `ponynet`, `bulletproof`, `offshore`

### Impersonated brands

`IMPERSONATED_BRANDS` in `core/intel_data.py`, 43 entries. Brands phishing kits impersonate most often, matched in subdomain labels by Subdomain Triage. Names of 6+ letters match inside a label (`paypal-verify`); shorter ones only as a whole word between hyphens or dots (`dhl-track`).

**Used by:** Subdomain Triage (*Brand name* signal), CNAME rules (lure names on free hosting)

`microsoft`, `office365`, `outlook`, `onedrive`, `sharepoint`, `paypal`, `google`, `amazon`, `netflix`, `facebook`, `instagram`, `whatsapp`, `linkedin`, `docusign`, `dropbox`, `binance`, `coinbase`, `metamask`, `trezor`, `ledger`, `wellsfargo`, `bankofamerica`, `icloud`, `appleid`, `telegram`, `roblox`, `spotify`, `walmart`, `booking`, `apple`, `chase`, `citi`, `hsbc`, `dhl`, `ups`, `usps`, `fedex`, `adobe`, `steam`, `okta`, `zoom`, `irs`, `gov`

### Phishing keywords

`PHISHING_KEYWORDS` in `core/intel_data.py`, 21 entries. Words phishing pages put next to a brand (combosquats such as `paypal-login`), matched by the lookalike rules.

**Used by:** Lookalike rules (combosquats of your brands)

`login`, `signin`, `sign-in`, `secure`, `verify`, `verification`, `account`, `update`, `support`, `wallet`, `auth`, `billing`, `payment`, `invoice`, `recover`, `unlock`, `confirm`, `webscr`, `sso`, `portal`, `service`

### Sensitive hostname words

`SENSITIVE_WORDS` in `core/hostnames.py`, 26 entries. Name labels attackers like for credential phishing and remote access; matched against whole labels or label parts.

**Used by:** Hostname Inventory (*Sensitive name* flag)

`login`, `signin`, `logon`, `secure`, `account`, `auth`, `sso`, `vpn`, `webmail`, `mail`, `admin`, `portal`, `pay`, `billing`, `verify`, `update`, `wallet`, `support`, `remote`, `citrix`, `owa`, `okta`, `password`, `reset`, `invoice`, `bank`

### Shared platforms

`SHARED_PLATFORMS` in `core/intel_data.py`, 41 entries. Platforms that hand out subdomains of one shared domain to anyone (free hosting, serverless, tunnels, free subdomain registries); the risk of the domain itself says nothing about a subdomain there.

**Used by:** Subdomain Triage (platform domains), CNAME Chains (*Free hosting* service type)

`pages.dev`, `workers.dev`, `netlify.app`, `vercel.app`, `github.io`, `gitlab.io`, `web.app`, `firebaseapp.com`, `herokuapp.com`, `azurewebsites.net`, `azurestaticapps.net`, `blob.core.windows.net`, `appspot.com`, `cloudfront.net`, `amplifyapp.com`, `onrender.com`, `fly.dev`, `glitch.me`, `replit.app`, `repl.co`, `surge.sh`, `ngrok-free.app`, `ngrok.io`, `trycloudflare.com`, `loca.lt`, `blogspot.com`, `weebly.com`, `wixsite.com`, `webflow.io`, `framer.app`, `godaddysites.com`, `square.site`, `duckdns.org`, `no-ip.org`, `ddns.net`, `eu.cc`, `uk.cc`, `gu.cc`, `us.cc`, `eu.org`, `my.id`

### Takeover-prone services

`TAKEOVER_CNAME_SUFFIXES` in `core/intel_data.py`, 50 entries. CNAME targets on services where a dangling record (the customer's resource deleted, the CNAME left behind) can be claimed by anyone: subdomain takeover. Based on the public can-i-take-over-xyz list; suffix -> service.

**Used by:** CNAME Chains (*Takeover-prone*), *Dangling CNAME* alerts

`s3.amazonaws.com` → AWS S3, `s3-website.amazonaws.com` → AWS S3 website, `elasticbeanstalk.com` → AWS Elastic Beanstalk, `azurewebsites.net` → Azure App Service, `cloudapp.net` → Azure Cloud Services, `cloudapp.azure.com` → Azure VM, `trafficmanager.net` → Azure Traffic Manager, `blob.core.windows.net` → Azure Blob Storage, `azure-api.net` → Azure API Management, `azurecontainer.io` → Azure Container Instances, `azurehdinsight.net` → Azure HDInsight, `azurestaticapps.net` → Azure Static Web Apps, `herokuapp.com` → Heroku, `herokudns.com` → Heroku, `herokussl.com` → Heroku, `github.io` → GitHub Pages, `gitlab.io` → GitLab Pages, `bitbucket.io` → Bitbucket, `myshopify.com` → Shopify, `ghost.io` → Ghost, `surge.sh` → Surge, `readme.io` → ReadMe, `readthedocs.io` → Read the Docs, `helpscoutdocs.com` → Help Scout, `helpjuice.com` → Helpjuice, `zendesk.com` → Zendesk, `freshdesk.com` → Freshdesk, `uservoice.com` → UserVoice, `unbouncepages.com` → Unbounce, `wordpress.com` → WordPress.com, `pantheonsite.io` → Pantheon, `wpengine.com` → WP Engine, `strikinglydns.com` → Strikingly, `launchrock.com` → LaunchRock, `statuspage.io` → Statuspage, `cargocollective.com` → Cargo, `teamwork.com` → Teamwork, `tumblr.com` → Tumblr, `agilecrm.com` → Agile CRM, `smartjobboard.com` → SmartJobBoard, `simplebooklet.com` → Simplebooklet, `worksites.net` → Worksites, `youtrack.cloud` → YouTrack, `canny.io` → Canny, `hatenablog.com` → Hatena Blog, `landingi.com` → Landingi, `netlify.app` → Netlify, `netlify.com` → Netlify, `fly.dev` → Fly.io, `ngrok.io` → ngrok

### Dynamic DNS and tunnel services

`DYNAMIC_DNS_CNAME_SUFFIXES` in `core/intel_data.py`, 31 entries. CNAME targets on dynamic DNS or tunnelling services: a name that follows a home or attacker machine, or exposes a local service through a tunnel; common for C2 and short-lived phishing.

**Used by:** CNAME Chains (*Dynamic DNS / tunnel*), CNAME alerts

`duckdns.org` → Duck DNS, `no-ip.com` → No-IP, `no-ip.org` → No-IP, `no-ip.biz` → No-IP, `ddns.net` → No-IP, `hopto.org` → No-IP, `zapto.org` → No-IP, `sytes.net` → No-IP, `serveftp.com` → No-IP, `myftp.biz` → No-IP, `servebeer.com` → No-IP, `dynu.net` → Dynu, `afraid.org` → FreeDNS, `changeip.com` → ChangeIP, `dyndns.org` → Dyn, `dynv6.net` → dynv6, `ngrok.io` → ngrok, `ngrok-free.app` → ngrok, `ngrok.app` → ngrok, `trycloudflare.com` → Cloudflare Tunnel (quick), `loca.lt` → localtunnel, `localtunnel.me` → localtunnel, `serveo.net` → Serveo, `pagekite.me` → PageKite, `localhost.run` → localhost.run, `lhr.life` → localhost.run, `bore.pub` → bore, `playit.gg` → playit.gg, `ply.gg` → playit.gg, `portmap.io` → Portmap, `telebit.io` → Telebit

### Parking CNAME targets

`PARKING_CNAME_SUFFIXES` in `core/intel_data.py`, 11 entries. CNAME targets of domain parking and for-sale pages: thousands of unrelated domains share them.

**Used by:** CNAME Chains (*Parking*; never counted as a link between domains)

`parkingpage.namecheap.com` → Namecheap parking, `pixie.porkbun.com` → Porkbun parking, `sedoparking.com` → Sedo, `parkingcrew.net` → ParkingCrew, `bodis.com` → Bodis, `above.com` → Above, `parklogic.com` → ParkLogic, `dan.com` → Dan.com, `afternic.com` → Afternic, `cashparking.com` → CashParking, `parking.d.parity.domains` → Parity parking

### Parking name servers

`PARKING_NS_MARKERS` in `core/intel_data.py`, 15 entries. Domain parking name servers.

**Used by:** Parked-domain detections, campaign correlation

`sedoparking.com`, `bodis.com`, `parkingcrew.net`, `above.com`, `dns-parking.com`, `parklogic.com`, `ztomy.com`, `dan.com`, `afternic.com`, `namefind.com`, `cashparking.com`, `uniregistrymarket.link`, `parkingpage.namecheap.com`, `domainparking`, `parked`

### CDN CNAME targets

`CDN_CNAME_SUFFIXES` in `core/intel_data.py`, 16 entries. CNAME targets that indicate CDN fronting.

**Used by:** CDN fronting, CNAME Chains (*CDN*)

`cloudfront.net` → Amazon CloudFront, `akamaiedge.net` → Akamai, `akamai.net` → Akamai, `edgekey.net` → Akamai, `edgesuite.net` → Akamai, `fastly.net` → Fastly, `fastlylb.net` → Fastly, `cdn.cloudflare.net` → Cloudflare, `azureedge.net` → Azure CDN, `azurefd.net` → Azure Front Door, `b-cdn.net` → BunnyCDN, `cdn77.org` → CDN77, `incapdns.net` → Imperva, `sucuri.net` → Sucuri, `stackpathdns.com` → StackPath, `edgecastcdn.net` → Edgecast

### CDN networks (ISP names)

`CDN_ISP_MARKERS` in `core/intel_data.py`, 11 entries. ISP / organization name fragments (from Iris IP data) that identify CDN or reverse-proxy networks.

**Used by:** CDN attribution of IPs, origin discovery

`cloudflare` → Cloudflare, `akamai` → Akamai, `fastly` → Fastly, `incapsula` → Imperva, `imperva` → Imperva, `sucuri` → Sucuri, `cdn77` → CDN77, `edgecast` → Edgecast, `stackpath` → StackPath, `bunny` → BunnyCDN, `ddos-guard` → DDoS-Guard

### CDN IP ranges

`CDN_IP_RANGES` in `core/intel_data.py`, 41 entries. .

**Used by:** CDN attribution of IPs: hosting alerts, DNS & Hosting, IP pivots (CDN IPs are skipped), exports

Cloudflare: 22 ranges; Fastly: 19 ranges

### Large DNS providers

`LARGE_DNS_PROVIDER_MARKERS` in `core/intel_data.py`, 34 entries. Large managed DNS providers: shared name servers here do not indicate common ownership.

**Used by:** Campaign correlation: shared name servers here do not link domains

`cloudflare.com`, `awsdns`, `domaincontrol.com`, `googledomains.com`, `ns-cloud`, `google.com`, `azure-dns`, `nsone.net`, `ultradns`, `dynect.net`, `registrar-servers.com`, `dnsmadeeasy.com`, `akam.net`, `name-services.com`, `worldnic.com`, `hichina.com`, `porkbun.com`, `namebrightdns.com`, `digitalocean.com`, `linode.com`, `he.net`, `wixdns.net`, `squarespacedns.com`, `gandi.net`, `ovh.net`, `ui-dns.`, `dns-parking.com`, `hostgator.com`, `bluehost.com`, `siteground.net`, `dreamhost.com`, `namecheaphosting.com`, `cloudns.net`, `vercel-dns.com`

### Shared certificate names

`SHARED_SAN_SUFFIXES` in `core/cert_inputs.py`, 9 entries. Shared CDN / platform certificate names: their SANs list unrelated customers, so they are never derived as targets.

**Used by:** Certificate inputs: their SANs are never turned into targets

`cloudflaressl.com`, `cloudflare-dns.com`, `fastly.net`, `akamaiedge.net`, `edgekey.net`, `azureedge.net`, `cloudfront.net`, `herokuapp.com`, `googleusercontent.com`

### Homoglyphs

`HOMOGLYPHS` in `core/intel_data.py`, 42 entries. Visual confusables mapped to their ASCII look-alike (subset of Unicode TR39 + common digit swaps).

**Used by:** Lookalike rules

`0` → o, `1` → l, `3` → e, `4` → a, `5` → s, `7` → t, `8` → b, `9` → g, `@` → a, `$` → s, `!` → i, `|` → l, `а` → a, `е` → e, `о` → o, `р` → p, `с` → c, `у` → y, `х` → x, `і` → i, `ј` → j, `ԁ` → d, `ѕ` → s, `һ` → h, `к` → k, `м` → m, `т` → t, `в` → b, `н` → h, `ո` → n, `ɡ` → g, `ӏ` → l, `ο` → o, `α` → a, `ν` → v, `ι` → i, `κ` → k, `τ` → t, `ρ` → p, `υ` → u, `χ` → x, `ε` → e

### Multi-letter homoglyphs

`MULTI_CHAR_HOMOGLYPHS` in `core/intel_data.py`, 4 entries. Letter pairs that read as one letter (`rn` looks like `m`).

**Used by:** Lookalike rules

`rn` → m, `vv` → w, `cl` → d, `ii` → u

## Files the app keeps

All in the project folder, local and git-ignored.

| File or folder | Holds |
| --- | --- |
| `dt_settings.json` | Cache lifetime and each source's own lifetime, use case changes, custom profiles, the brand watchlist, watched target lists, how many runs and offline datasets to keep |
| `dt_cache/` | The lookup cache (see *Settings → Lookup cache*) |
| `dt_runs/` | Run snapshots for Runs & Diffs, with the API queries each run made |
| `dt_offline/` | Offline datasets saved with *Save offline copy* |
| `dt_suppressions.json` | Suppressed alerts |
| `dt_triage.json` | Triage status of alerts and verdicts on domains (New, Investigating, Benign, Malicious) with notes |
| `dt_token.json`, `dt_session_data/` | The Iris pDNS browser session (during a run also `run_state.json`, its cookies for the parallel lookups, deleted when the run ends) |

API credentials are read from environment variables, `~/.config/dt-analytics/credentials.toml` (where keys entered
in the app are saved) or the `~/.dt*` files, all outside the project; see [Credentials](INSTALLATION.md#credentials).
