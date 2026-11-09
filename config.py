"""Configuration: branding constants, filesystem paths, collection limits, and detection thresholds."""
from dataclasses import dataclass
from pathlib import Path

# --- BRANDING CONFIGURATION ---
DT_PRIMARY_DARK = "#1B1F29"
DT_ORANGE = "#F76509"
DT_GREEN = "#91D117"
DT_BLUE = "#4C68FD"
DT_SLATE = "#748590"

# --- FILESYSTEM PATHS (anchored to the project, independent of the launch directory) ---
BASE_DIR = Path(__file__).resolve().parent
TOKEN_FILE = BASE_DIR / "dt_token.json"
SESSION_DIR = BASE_DIR / "dt_session_data"
RUNS_DIR = BASE_DIR / "dt_runs"
SUPPRESSIONS_FILE = BASE_DIR / "dt_suppressions.json"
TRIAGE_FILE = BASE_DIR / "dt_triage.json"          # analyst decisions on alerts and domains (New ... Malicious)
SETTINGS_FILE = BASE_DIR / "dt_settings.json"
OFFLINE_DIR = BASE_DIR / "dt_offline"
CACHE_DIR = BASE_DIR / "dt_cache"
MAX_OFFLINE_DATASETS = 20
MAX_RUN_SNAPSHOTS = 10
LOGO_CANDIDATES = [BASE_DIR / name for name in ("domaintools_logo.svg", "domaintools_logo.png", "domaintools_logo.jpg")]

# --- CREDENTIAL FILES (environment variables take precedence; see integrations/credentials.py) ---
CREDENTIALS_FILE = Path.home() / ".config" / "dt-analytics" / "credentials.toml"   # override with $DT_CREDENTIALS_FILE
DTAPI_FILE = Path.home() / ".dtapi"                # username / API key on lines 1-2
DNSDB_KEY_FILE = Path.home() / ".dtdnsdb"         # DNSDB API key
CERT_API_KEY_FILE = Path.home() / ".dtcertapi"     # optional; the DomainTools API key is used otherwise
VPNDB_KEY_FILE = Path.home() / ".dtvpndb"          # VPNDB API key (vpndb_...); optional service

# --- COLLECTION LIMITS ---
DNSDB_LIMIT_OPTIONS = [10, 50, 100, 500, 1000, 2000, 5000, 10000, 25000, 50000, 100000, 1000000]  # choices of the DNSDB result limit (Settings)
DNSDB_DEFAULT_LIMIT = 5000           # DNSDB records fetched per target by the main passive DNS lookup (Settings)
IRIS_PDNS_LIMIT = 500                # Iris pDNS records fetched per target by the main lookup
TXT_SUPPLEMENT_DEFAULT_RECORDS = 10   # latest TXT records kept per domain by the supplemental lookup
TXT_SUPPLEMENT_FETCH_LIMIT = 500      # DNSDB TXT records fetched per name before trimming to the latest N
CAA_SUPPLEMENT_FETCH_LIMIT = 100      # DNSDB CAA records fetched for the apex name (all are kept)
IRIS_SUPPLEMENT_FETCH_LIMIT = 100     # Iris pDNS records requested per supplemental record-type query
CNAME_SUPPLEMENT_FETCH_LIMIT = 5000   # DNSDB CNAME records fetched (name and subdomains) when the main query was cut off
CNAME_CHASE_MAX_STEPS = 10           # names followed per CNAME chase (DNSDB Scout's CNAME chasing limit)
CNAME_CHASE_RECORD_LIMIT = 500       # DNSDB records fetched per chased name and record type
CNAME_CHASE_QUERIES_PER_DOMAIN = 10  # DNSDB queries a CNAME chase click may spend per domain (cached lookups are free)
CNAME_RDATA_MAX_PER_CLICK = 10       # names looked up per click of a reverse CNAME lookup
CNAME_RDATA_RECORD_LIMIT = 5000      # names per reverse CNAME (RDATA) lookup
DOMAIN_HISTORY_MAX_CHANGES = 1000    # Domain History: default cap of changes fetched per domain (Settings can change it)
DOMAIN_HISTORY_CAP_MAX = 20_000      # highest cap the Settings field accepts
DOMAIN_HISTORY_SAFETY_LIMIT = 50_000   # "All time, no cap" still stops here (500 queries), so a run cannot page forever
POPULAR_RANK_MAX = 10_000           # Iris popularity rank up to which a domain counts as popular (lower confidence)
MONITOR_HISTORY_DAYS = 90            # Monitor changes use case: Domain History period (days of changes fetched)
CERT_SEARCH_MAX_RECORDS = 2500       # certificates fetched per target by the certificate search
CERT_EVENTS_MAX_RECORDS = 2500       # certificate events (hostnames / IPs seen with a certificate) per domain or IP
CERT_SHA256_EVENTS_MAX_RECORDS = 1000  # events per certificate hash (certificate inputs and CT co-occurrence)
CERT_EVENTS_LOOKBACK_DAYS = 365     # Certificate Events time window (API default 30 days, maximum 366)
SEED_MAX_CERTIFICATES = 200         # certificates fetched per certificate input (hash, CN, SAN, ...)
SEED_DEFAULT_TARGETS = 10           # derived domains / IPs pre-selected in the certificate input preview
SEED_MAX_TARGETS = 100              # most derived domains / IPs one run may analyze
HOSTNAME_NEW_DAYS = 30              # Hostname Inventory: a hostname first seen this recently is flagged "New"
PIVOT_STRONG_MAX = 500              # Pivot Ranking: a value shared by 2..this many domains in Iris is a strong pivot
PIVOT_USEFUL_MAX = 10_000           # ... up to this many a useful one; more is weak (shared infrastructure)
PIVOT_RESULT_LIMIT = 500            # Pivot Ranking: domains fetched per Iris Investigate pivot search (one page)
TRIAGE_BURST_MIN = 5                # Subdomain Triage: hostnames of one domain first seen in the same hour to count as a burst
CERT_CTL_LIMIT = 500                 # CT log entries fetched per certificate (CT telemetry)
CT_LOOKUP_DEFAULT_MAX_HASHES = 10    # two lookups per certificate; newest first, shared across domains
IRIS_INVESTIGATE_BATCH_SIZE = 100    # domains per Iris Investigate request
IRISQL_PAGE_SIZE = 500               # IrisQL search: domains per Iris Investigate request (one page)
IRISQL_DEFAULT_RESULTS = 500         # IrisQL search: domains fetched by default (pages are requested until this many)
IRISQL_MAX_RESULTS = 5000            # IrisQL search: most domains one search may fetch
CERTSQL_PAGE_SIZE = 500              # CertsQL search: certificates per Certificate Search request (API maximum)
CERTSQL_DEFAULT_RESULTS = 500        # CertsQL search: certificates fetched by default
CERTSQL_MAX_RESULTS = 5000           # CertsQL search: most certificates one search may fetch
PIVOT_DEFAULT_MAX_IPS = 10           # hosting IPs pivoted on per run (Settings: Max IPs to pivot on)
PIVOT_IPS_PER_DOMAIN = 3             # hosting IPs picked per domain before the run-wide maximum applies
PIVOT_IP_RECORD_LIMIT = 2000         # DNSDB records fetched per pivot IP
VPNDB_MAX_IPS = 500                  # hosting IPs checked in VPNDB per run (one bulk request; each IP is one query)
VPNDB_IPS_PER_DOMAIN = 100           # most recently seen IPs per domain before the run-wide maximum applies
VPNDB_DETAIL_MAX = 50                # anonymous IPs given the full verdict (sharing, Tor, evidence), one query each
VPNDB_HISTORY_MAX = 50               # anonymizer exits given their weekly history (exit while the domain used it?)
VPNDB_NEIGHBOUR_MAX = 30             # /24 ranges around non-exit hosting IPs looked up for known exits
VPNDB_ASN_MAX = 20                   # hosting networks (Iris ASNs) looked up for the providers on them
VPNDB_REVERSE_MAX = 10               # dedicated exits whose other domains are looked up in DNSDB (rdata/ip)
VPNDB_REVERSE_LIMIT = 1000           # DNSDB records per dedicated exit
IP_CHECK_MAX_IPS = 100               # IP check use case: IP targets given the full verdict, one query each
CIDR_MAX_RANGES = 20                 # CIDR targets looked up in VPNDB per run (one prefix query each)
CIDR_IP_CHECK_MAX = 1024             # addresses of one CIDR range bulk-checked one by one in VPNDB (a /22); a query each
CIDR_IP_CHECK_TOTAL = 4096           # addresses of all CIDR ranges bulk-checked per run
CIDR_ADDRESSES_PER_RANGE = 200       # addresses VPNDB probing exited through in each range (last 30 days); a query a row
MAX_WORKERS = 8                      # lookups run in parallel
IRIS_PDNS_WORKERS = 3                # Iris pDNS targets looked up at the same time (after the session check)
CERT_API_MAX_WORKERS = 4         # SHA256 / CT log lookups run per certificate; more parallel calls trigger HTTP 503s
CERT_RETRY_PAUSE_SECONDS = 5     # pause before failed certificate lookups are retried once, one at a time
FETCH_CACHE_TTL_SECONDS = 86400   # default cache lifetime of successful lookups (Settings → Lookup cache)
# Source groups that can keep cached results for their own lifetime (Settings → Lookup cache)
CACHE_GROUPS = {"pdns": "Passive DNS (DNSDB, Iris pDNS)", "iris": "Iris Investigate (enrichment, risk, IrisQL)",
                "history": "Domain History", "certs": "Certificates (search, events, CT log)", "vpndb": "VPNDB"}
CACHE_GROUP_DEFAULTS = {"history": 604800, "vpndb": 21600}   # changes rarely: 7 days; changes often: 6 hours
# cache lifetime choices on Settings → Lookup cache: label -> seconds (0: no cache)
CACHE_LIFETIMES = {"Off": 0, "30 minutes": 1800, "6 hours": 21600, "1 day": 86400, "7 days": 604800,
                   "30 days": 2592000}

# --- DISPLAY LIMITS ---
MAX_RAW_DISPLAY_ROWS = 50000

# --- THREAT SEVERITY WEIGHTS ---
SEVERITY_WEIGHTS = {"Critical": 90, "High": 70, "Medium-High": 60, "Medium": 40, "Low": 20}


@dataclass(frozen=True)
class ThresholdSpec:
    """Metadata for one tunable detection threshold (drives both the slider and the engine)."""
    key: str
    label: str
    default: float
    min_value: float
    max_value: float
    step: float
    help: str
    section: str = "DomainTools Risk"   # data source the threshold applies to (sidebar grouping)

    @property
    def state_key(self):
        return f"thr_{self.key}"


THRESHOLD_SPECS = (
    # --- DomainTools Risk ---
    ThresholdSpec("risk_score", "Min Risk Score", 70, 0, 100, 1,
                  "Domains with a known DomainTools risk score below this value are skipped by the behavioral engine. "
                  "Domains without a risk score are still evaluated.", "DomainTools Risk"),
    ThresholdSpec("high_risk_score", "High-Risk Score Cutoff", 70, 0, 100, 1,
                  "Unified/predictive risk score at or above which a domain counts as high risk (KPIs).", "DomainTools Risk"),
    # --- Passive DNS & Domain History ---
    ThresholdSpec("parked_days", "Parked Dormancy (Days)", 180, 30, 365, 10,
                  "Days of inactivity before a sudden infrastructure burst triggers a Parked-to-Weaponized alert.", "Passive DNS & Domain History"),
    ThresholdSpec("flux_ips", "Rapid IP Rotation Event Count", 5, 2, 20, 1,
                  "Minimum distinct IPs within 7 days needed to flag Fast-Flux DNS behavior.", "Passive DNS & Domain History"),
    ThresholdSpec("flux_networks", "Fast-Flux Min Distinct Networks", 3, 2, 10, 1,
                  "Distinct ASNs (or network prefixes when ASN is unknown) of non-CDN IPs within 7 days for Multi-Network Fast-Flux.", "Passive DNS & Domain History"),
    ThresholdSpec("phish_days", "Phishing Prep Dormancy (Days)", 60, 10, 365, 1,
                  "Days of domain dormancy prior to a sudden Mail (MX) or SPF/TXT addition.", "Passive DNS & Domain History"),
    ThresholdSpec("txt_len", "Anomalous TXT Length", 200, 50, 1000, 50,
                  "Character length above which continuous TXT records trigger DNS Tunneling / C2 alerts.", "Passive DNS & Domain History"),
    ThresholdSpec("burst_density", "pDNS Burst Density (Queries/Day)", 10000, 1000, 50000, 1000,
                  "Query rate per day on short-lived infrastructure that flags flash-spam or botnet campaigns.", "Passive DNS & Domain History"),
    ThresholdSpec("volume_z", "Query Volume Anomaly (Robust Z)", 6.0, 3.0, 15.0, 0.5,
                  "Robust z-score (median/MAD) of daily pDNS query volume above which a day is flagged as anomalous.", "Passive DNS & Domain History"),
    ThresholdSpec("hop_days", "Domain Hopping Gap (Days)", 14, 1, 90, 1,
                  "Max days between one domain going dark on an IP and the next domain appearing there.", "Passive DNS & Domain History"),
    ThresholdSpec("cname_hops", "Long CNAME Chain Min Hops", 4, 2, 10, 1,
                  "CNAME chains with at least this many CNAME hops before an address are flagged as hiding the final "
                  "infrastructure.", "Passive DNS & Domain History"),
    # --- Iris Investigate & Domain Name ---
    ThresholdSpec("nrd_days", "Newly Registered Domain Age (Days)", 30, 1, 365, 1,
                  "Domains created within this many days (Iris create date) are flagged as newly registered.", "Iris Investigate & Domain Name"),
    ThresholdSpec("entropy", "DGA Entropy Score", 3.6, 2.0, 5.0, 0.1,
                  "Shannon Entropy cutoff. English names average ~2.5; algorithmic DGA names typically exceed 3.6.", "Iris Investigate & Domain Name"),
    # --- Certificate API ---
    ThresholdSpec("gap_hours", "Cert-to-DNS Gap (Hours)", 1.0, 0.5, 48.0, 0.5,
                  "Maximum gap between certificate issuance and first DNS observation for a Rapid Weaponization alert.", "Certificate API"),
    ThresholdSpec("short_lived_days", "Short-Lived Certificate Max Validity (Days)", 10, 1, 30, 1,
                  "Certificates valid this many days or less (e.g. Let's Encrypt's 6-day 'shortlived' profile) are flagged as "
                  "short-lived. Informational only: not used in risk scores or DIF fingerprints.", "Certificate API"),
    ThresholdSpec("ssl_churn_count", "Cert Churn Min Early Replacements", 2, 1, 10, 1,
                  "Early certificate replacements within the churn window that indicate abnormal rotation. A replacement is early "
                  "when a new certificate for the same names is issued while the previous one still has over half its validity "
                  "left; scheduled renewals of short-lived certificates do not count.", "Certificate API"),
    ThresholdSpec("ssl_churn_days", "Cert Churn Window (Days)", 30, 7, 90, 1,
                  "Timeframe window in days in which early certificate replacements are counted.", "Certificate API"),
    ThresholdSpec("ssl_san", "Mega-SAN Min Root Domains", 3, 2, 20, 1,
                  "Minimum unique registrable domains bundled into one certificate before a Mega-SAN alert.", "Certificate API"),
    ThresholdSpec("dv_risk_score", "Suspicious DV Min Risk Score", 50, 0, 100, 1,
                  "Risk score above which a Domain Validated (DV) certificate is flagged as suspicious.", "Certificate API"),
)

DEFAULT_THRESHOLDS = {spec.key: spec.default for spec in THRESHOLD_SPECS}
