"""Static reference data for detection rules: CDN ranges, provider lists, rule metadata, and ATT&CK tactics.

Lists here are curated snapshots - review and extend them for your environment. Watchlist matches are
investigative leads, not proof of abuse.
"""

# --- CDN IP RANGES (published by the providers; snapshot) ---
CDN_IP_RANGES = {
    "Cloudflare": [
        "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18",
        "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17",
        "162.158.0.0/15", "104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
        "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32", "2405:8100::/32",
        "2a06:98c0::/29", "2c0f:f248::/32",
    ],
    "Fastly": [
        "23.235.32.0/20", "43.249.72.0/22", "103.244.50.0/24", "103.245.222.0/23", "103.245.224.0/24",
        "104.156.80.0/20", "140.248.64.0/18", "140.248.128.0/17", "146.75.0.0/17", "151.101.0.0/16",
        "157.52.64.0/18", "167.82.0.0/17", "167.82.128.0/20", "167.82.160.0/20", "167.82.224.0/20",
        "172.111.64.0/18", "185.31.16.0/22", "199.27.72.0/21", "199.232.0.0/16",
    ],
}

# ISP / organization name fragments (from Iris IP data) that identify CDN or reverse-proxy networks
CDN_ISP_MARKERS = {
    "cloudflare": "Cloudflare", "akamai": "Akamai", "fastly": "Fastly", "incapsula": "Imperva", "imperva": "Imperva",
    "sucuri": "Sucuri", "cdn77": "CDN77", "edgecast": "Edgecast", "stackpath": "StackPath", "bunny": "BunnyCDN",
    "ddos-guard": "DDoS-Guard",
}

# CNAME targets that indicate CDN fronting
CDN_CNAME_SUFFIXES = {
    "cloudfront.net": "Amazon CloudFront", "akamaiedge.net": "Akamai", "akamai.net": "Akamai", "edgekey.net": "Akamai",
    "edgesuite.net": "Akamai", "fastly.net": "Fastly", "fastlylb.net": "Fastly", "cdn.cloudflare.net": "Cloudflare",
    "azureedge.net": "Azure CDN", "azurefd.net": "Azure Front Door", "b-cdn.net": "BunnyCDN", "cdn77.org": "CDN77",
    "incapdns.net": "Imperva", "sucuri.net": "Sucuri", "stackpathdns.com": "StackPath", "edgecastcdn.net": "Edgecast",
}

CLOUDFLARE_NS_SUFFIX = "ns.cloudflare.com"

# CNAME targets on services where a dangling record (the customer's resource deleted, the CNAME left behind) can be
# claimed by anyone: subdomain takeover. Based on the public can-i-take-over-xyz list; suffix -> service
TAKEOVER_CNAME_SUFFIXES = {
    "s3.amazonaws.com": "AWS S3", "s3-website.amazonaws.com": "AWS S3 website", "elasticbeanstalk.com": "AWS Elastic Beanstalk",
    "azurewebsites.net": "Azure App Service", "cloudapp.net": "Azure Cloud Services", "cloudapp.azure.com": "Azure VM",
    "trafficmanager.net": "Azure Traffic Manager", "blob.core.windows.net": "Azure Blob Storage",
    "azure-api.net": "Azure API Management", "azurecontainer.io": "Azure Container Instances",
    "azurehdinsight.net": "Azure HDInsight", "azurestaticapps.net": "Azure Static Web Apps",
    "herokuapp.com": "Heroku", "herokudns.com": "Heroku", "herokussl.com": "Heroku", "github.io": "GitHub Pages",
    "gitlab.io": "GitLab Pages", "bitbucket.io": "Bitbucket", "myshopify.com": "Shopify", "ghost.io": "Ghost",
    "surge.sh": "Surge", "readme.io": "ReadMe", "readthedocs.io": "Read the Docs", "helpscoutdocs.com": "Help Scout",
    "helpjuice.com": "Helpjuice", "zendesk.com": "Zendesk", "freshdesk.com": "Freshdesk", "uservoice.com": "UserVoice",
    "unbouncepages.com": "Unbounce", "wordpress.com": "WordPress.com", "pantheonsite.io": "Pantheon",
    "wpengine.com": "WP Engine", "strikinglydns.com": "Strikingly", "launchrock.com": "LaunchRock",
    "statuspage.io": "Statuspage", "cargocollective.com": "Cargo", "teamwork.com": "Teamwork", "tumblr.com": "Tumblr",
    "agilecrm.com": "Agile CRM", "smartjobboard.com": "SmartJobBoard", "simplebooklet.com": "Simplebooklet",
    "worksites.net": "Worksites", "youtrack.cloud": "YouTrack", "canny.io": "Canny", "hatenablog.com": "Hatena Blog",
    "landingi.com": "Landingi", "netlify.app": "Netlify", "netlify.com": "Netlify", "fly.dev": "Fly.io",
    "ngrok.io": "ngrok",
}
# CNAME targets on dynamic DNS or tunnelling services: a name that follows a home or attacker machine, or exposes a
# local service through a tunnel; common for C2 and short-lived phishing
DYNAMIC_DNS_CNAME_SUFFIXES = {
    "duckdns.org": "Duck DNS", "no-ip.com": "No-IP", "no-ip.org": "No-IP", "no-ip.biz": "No-IP", "ddns.net": "No-IP",
    "hopto.org": "No-IP", "zapto.org": "No-IP", "sytes.net": "No-IP", "serveftp.com": "No-IP", "myftp.biz": "No-IP",
    "servebeer.com": "No-IP", "dynu.net": "Dynu", "afraid.org": "FreeDNS", "changeip.com": "ChangeIP",
    "dyndns.org": "Dyn", "dynv6.net": "dynv6", "ngrok.io": "ngrok", "ngrok-free.app": "ngrok", "ngrok.app": "ngrok",
    "trycloudflare.com": "Cloudflare Tunnel (quick)", "loca.lt": "localtunnel", "localtunnel.me": "localtunnel",
    "serveo.net": "Serveo", "pagekite.me": "PageKite", "localhost.run": "localhost.run", "lhr.life": "localhost.run",
    "bore.pub": "bore", "playit.gg": "playit.gg", "ply.gg": "playit.gg", "portmap.io": "Portmap", "telebit.io": "Telebit",
}

# CNAME targets of domain parking and for-sale pages: thousands of unrelated domains share them
PARKING_CNAME_SUFFIXES = {
    "parkingpage.namecheap.com": "Namecheap parking", "pixie.porkbun.com": "Porkbun parking",
    "sedoparking.com": "Sedo", "parkingcrew.net": "ParkingCrew", "bodis.com": "Bodis", "above.com": "Above",
    "parklogic.com": "ParkLogic", "dan.com": "Dan.com", "afternic.com": "Afternic", "cashparking.com": "CashParking",
    "parking.d.parity.domains": "Parity parking",
}

# Large managed DNS providers: shared name servers here do not indicate common ownership
LARGE_DNS_PROVIDER_MARKERS = (
    "cloudflare.com", "awsdns", "domaincontrol.com", "googledomains.com", "ns-cloud", "google.com", "azure-dns",
    "nsone.net", "ultradns", "dynect.net", "registrar-servers.com", "dnsmadeeasy.com", "akam.net", "name-services.com",
    "worldnic.com", "hichina.com", "porkbun.com", "namebrightdns.com", "digitalocean.com", "linode.com", "he.net",
    "wixdns.net", "squarespacedns.com", "gandi.net", "ovh.net", "ui-dns.", "dns-parking.com", "hostgator.com",
    "bluehost.com", "siteground.net", "dreamhost.com", "namecheaphosting.com", "cloudns.net", "vercel-dns.com",
)

# Domain parking name servers
PARKING_NS_MARKERS = (
    "sedoparking.com", "bodis.com", "parkingcrew.net", "above.com", "dns-parking.com", "parklogic.com", "ztomy.com",
    "dan.com", "afternic.com", "namefind.com", "cashparking.com", "uniregistrymarket.link", "parkingpage.namecheap.com",
    "domainparking", "parked",
)

# High-abuse / offshore hosting watchlist (ISP name fragments, lowercase). Editable; verify before acting.
HOSTING_WATCHLIST = (
    "stark industries", "aeza", "zservers", "proton66", "flokinet", "alexhost", "shinjiru", "njalla",
    "pq hosting", "private layer", "frantech", "ponynet", "bulletproof", "offshore",
)

# Words phishing pages put next to a brand (combosquats such as `paypal-login`), matched by the lookalike rules
PHISHING_KEYWORDS = (
    "login", "signin", "sign-in", "secure", "verify", "verification", "account", "update", "support", "wallet",
    "auth", "billing", "payment", "invoice", "recover", "unlock", "confirm", "webscr", "sso", "portal", "service",
)

# Brands phishing kits impersonate most often, matched in subdomain labels by Subdomain Triage. Names of 6+ letters
# match inside a label (`paypal-verify`); shorter ones only as a whole word between hyphens or dots (`dhl-track`).
IMPERSONATED_BRANDS = (
    "microsoft", "office365", "outlook", "onedrive", "sharepoint", "paypal", "google", "amazon", "netflix", "facebook",
    "instagram", "whatsapp", "linkedin", "docusign", "dropbox", "binance", "coinbase", "metamask", "trezor", "ledger",
    "wellsfargo", "bankofamerica", "icloud", "appleid", "telegram", "roblox", "spotify", "walmart", "booking",
    "apple", "chase", "citi", "hsbc", "dhl", "ups", "usps", "fedex", "adobe", "steam", "okta", "zoom", "irs", "gov",
)

# Platforms that hand out subdomains of one shared domain to anyone (free hosting, serverless, tunnels, free
# subdomain registries); the risk of the domain itself says nothing about a subdomain there.
SHARED_PLATFORMS = (
    "pages.dev", "workers.dev", "netlify.app", "vercel.app", "github.io", "gitlab.io", "web.app", "firebaseapp.com",
    "herokuapp.com", "azurewebsites.net", "azurestaticapps.net", "blob.core.windows.net", "appspot.com",
    "cloudfront.net", "amplifyapp.com", "onrender.com", "fly.dev", "glitch.me", "replit.app", "repl.co", "surge.sh",
    "ngrok-free.app", "ngrok.io", "trycloudflare.com", "loca.lt", "blogspot.com", "weebly.com", "wixsite.com",
    "webflow.io", "framer.app", "godaddysites.com", "square.site", "duckdns.org", "no-ip.org", "ddns.net",
    "eu.cc", "uk.cc", "gu.cc", "us.cc", "eu.org", "my.id",
)

# Visual confusables mapped to their ASCII look-alike (subset of Unicode TR39 + common digit swaps)
HOMOGLYPHS = {
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "9": "g", "@": "a", "$": "s", "!": "i", "|": "l",
    # Cyrillic
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j", "ԁ": "d", "ѕ": "s",
    "һ": "h", "к": "k", "м": "m", "т": "t", "в": "b", "н": "h", "ո": "n", "ɡ": "g", "ӏ": "l",
    # Greek
    "ο": "o", "α": "a", "ν": "v", "ι": "i", "κ": "k", "τ": "t", "ρ": "p", "υ": "u", "χ": "x", "ε": "e",
}
# Letter pairs that read as one letter (`rn` looks like `m`)
MULTI_CHAR_HOMOGLYPHS = (("rn", "m"), ("vv", "w"), ("cl", "d"), ("ii", "u"))

# --- MITRE ATT&CK: base technique -> tactic ---
MITRE_TACTICS = {
    "T1008": "Command and Control", "T1071": "Command and Control", "T1090": "Command and Control",
    "T1568": "Command and Control", "T1573": "Command and Control",
    "T1583": "Resource Development", "T1584": "Resource Development", "T1585": "Resource Development",
    "T1588": "Resource Development", "T1608": "Resource Development",
    "T1562": "Defense Evasion", "T1552": "Credential Access", "T1048": "Exfiltration", "T1566": "Initial Access",
}
TACTIC_ORDER = ["Resource Development", "Initial Access", "Defense Evasion", "Credential Access", "Command and Control", "Exfiltration", "Other"]

# --- RULE METADATA: threat type -> (category, confidence) ---
RULE_METADATA = {
    # DNS / pDNS / Domain History
    "DGA / High Entropy Domain": ("Domain Name", "Low"),
    "Parked-to-Weaponized": ("DNS Behavior", "Medium"),
    "Rapid IP Rotation (Fast-Flux)": ("DNS Behavior", "Medium"),
    "Multi-Network Fast-Flux (ASN-Diverse)": ("DNS Behavior", "High"),
    "Sinkhole / Loopback Resolution": ("DNS Behavior", "High"),
    "Suspicious / Offshore Name Server": ("Hosting & DNS Providers", "Medium"),
    "High-Risk Mail Provider": ("Email", "Low"),
    "Phishing/Spam Prep": ("Email", "Low"),
    "Invalid/Malformed SPF": ("Email", "Medium"),
    "Highly Permissive SPF (+all)": ("Email", "High"),
    "Anomalous TXT Payload": ("DNS Behavior", "Low"),
    "Flash/Burst Campaign": ("DNS Behavior", "Medium"),
    "Query Volume Anomaly": ("DNS Behavior", "Low"),
    "IPTV / Stream Distribution Endpoint": ("Web & Content", "Medium"),
    "ACME Certificate Sprawl": ("Certificates", "Low"),
    "Deeply Nested Subdomains": ("DNS Behavior", "Low"),
    "Parked Domain (Parking Name Servers)": ("Registration & Lifecycle", "High"),
    "Parking Exit / Reactivation": ("Registration & Lifecycle", "Medium"),
    # CNAME chains
    "Dangling CNAME (Subdomain Takeover Risk)": ("Hosting & DNS Providers", "Medium"),
    "Unverified CNAME to Takeover-Prone Service": ("Hosting & DNS Providers", "Low"),
    "CNAME to Dynamic DNS / Tunnel Service": ("Hosting & DNS Providers", "Medium"),
    "CNAME to Free Hosting Platform": ("Hosting & DNS Providers", "Low"),
    "CNAME Retargeted to Another Provider": ("DNS Behavior", "Low"),
    "Long CNAME Chain / Loop": ("DNS Behavior", "Low"),
    "CNAME Link Between Analyzed Domains": ("Correlation", "Medium"),
    # Iris enrichment
    "Live Pirate Streaming Panel Detected": ("Web & Content", "High"),
    "Shared Web Tracker Fingerprint": ("Correlation", "High"),
    "Newly Registered Domain": ("Registration & Lifecycle", "High"),
    "Newly Registered & Weaponized Domain": ("Registration & Lifecycle", "High"),
    "High-Abuse / Offshore Hosting Provider": ("Hosting & DNS Providers", "Medium"),
    "Cross-Domain Redirect": ("Web & Content", "Medium"),
    "Potential Origin IP Exposure (Behind CDN)": ("Hosting & DNS Providers", "Medium"),
    # VPNDB: VPN, residential proxy and Tor exits
    "Domain on Tor Relay / Exit Node": ("Hosting & DNS Providers", "High"),
    "Domain on Residential Proxy Exit": ("Hosting & DNS Providers", "Medium"),
    "Domain on VPN / Proxy Exit": ("Hosting & DNS Providers", "Medium"),
    "Domain on Dedicated Anonymizer Exit": ("Hosting & DNS Providers", "Medium"),
    "Hosting Moved onto Anonymizer Exit": ("Hosting & DNS Providers", "Medium"),
    "Domain Rotates Across Anonymizer Exits": ("Hosting & DNS Providers", "Medium"),
    "Newly Registered Domain on Anonymizer Exit": ("Hosting & DNS Providers", "High"),
    "Anonymizer Exit Shared by Analyzed Domains": ("Hosting & DNS Providers", "Medium"),
    "Hosted Among Anonymizer Exits": ("Hosting & DNS Providers", "Low"),
    "Hosted Among Tor Exits": ("Hosting & DNS Providers", "Low"),
    # Lookalikes
    "Homoglyph / IDN Brand Impersonation": ("Lookalike / Brand", "High"),
    "Typosquatting Lookalike": ("Lookalike / Brand", "Medium"),
    "Combosquatting (Brand + Keyword)": ("Lookalike / Brand", "Medium"),
    "Brand in Subdomain": ("Lookalike / Brand", "Medium"),
    "Brand Name on Alternate TLD": ("Lookalike / Brand", "Low"),
    "IDN / Punycode Domain": ("Lookalike / Brand", "Low"),
    # Correlation
    "Shared Infrastructure Cluster": ("Correlation", "High"),
    "Domain Hopping on Shared IP": ("Correlation", "Medium"),
    # Certificates
    "Rapid Weaponization (Cert-to-DNS Gap)": ("Certificates", "Medium"),
    "Self-Signed Certificate Detected": ("Certificates", "High"),
    "Short-Lived Certificate": ("Certificates", "High"),
    "Mega-SAN Cluster (Bulk Infrastructure)": ("Certificates", "Medium"),
    "Multi-IP Certificate (Shared C2 / Proxy Cluster)": ("Certificates", "Medium"),
    "Bare-IP Certificate (C2 / Proxy Node)": ("Certificates", "High"),
    "SSL Common Name (CN) Mismatch": ("Certificates", "Low"),
    "Pre-Certificate Staging (CT Log Only)": ("Certificates", "Low"),
    "CT Log Evasion / Missing SCTs": ("Certificates", "Medium"),
    "Rogue Certificate Authority": ("Certificates", "High"),
    "Non-Compliant Validity Window": ("Certificates", "High"),
    "Deprecated Signature Algorithm": ("Certificates", "High"),
    "Wildcard Issuance Forbidden by CAA Policy": ("Certificates", "High"),
    "Unauthorized CA Certificate Issuance (CAA Breach)": ("Certificates", "High"),
    "CAA Mismatch (CA Trust Unverified)": ("Certificates", "Low"),
    "Non-Public / Private CA Certificate": ("Certificates", "Medium"),
    "Suspicious CAA Stripping / Evasion": ("Certificates", "Low"),
    "Wildcard Infrastructure Sprawl": ("Certificates", "Medium"),
    "Wildcard Certificate Observed": ("Certificates", "High"),
    "Suspicious Domain Validation (DV)": ("Certificates", "Low"),
    "Weak Cryptographic Key Material": ("Certificates", "High"),
    "Certificate Churn (Ephemeral SSL)": ("Certificates", "Medium"),
}
CONFIDENCE_ORDER = ["High", "Medium", "Low"]
# Shown as alerts but excluded from risk vectors, Unified Risk, and DIF: context, not evidence of abuse
INFORMATIONAL_RULES = frozenset({"Short-Lived Certificate"})

# --- ISO 3166-1 alpha-2 -> alpha-3 (for Plotly choropleth maps) ---
ISO2_TO_ISO3 = {
    "AD": "AND", "AE": "ARE", "AF": "AFG", "AG": "ATG", "AI": "AIA", "AL": "ALB", "AM": "ARM", "AO": "AGO", "AQ": "ATA",
    "AR": "ARG", "AS": "ASM", "AT": "AUT", "AU": "AUS", "AW": "ABW", "AX": "ALA", "AZ": "AZE", "BA": "BIH", "BB": "BRB",
    "BD": "BGD", "BE": "BEL", "BF": "BFA", "BG": "BGR", "BH": "BHR", "BI": "BDI", "BJ": "BEN", "BL": "BLM", "BM": "BMU",
    "BN": "BRN", "BO": "BOL", "BQ": "BES", "BR": "BRA", "BS": "BHS", "BT": "BTN", "BV": "BVT", "BW": "BWA", "BY": "BLR",
    "BZ": "BLZ", "CA": "CAN", "CC": "CCK", "CD": "COD", "CF": "CAF", "CG": "COG", "CH": "CHE", "CI": "CIV", "CK": "COK",
    "CL": "CHL", "CM": "CMR", "CN": "CHN", "CO": "COL", "CR": "CRI", "CU": "CUB", "CV": "CPV", "CW": "CUW", "CX": "CXR",
    "CY": "CYP", "CZ": "CZE", "DE": "DEU", "DJ": "DJI", "DK": "DNK", "DM": "DMA", "DO": "DOM", "DZ": "DZA", "EC": "ECU",
    "EE": "EST", "EG": "EGY", "EH": "ESH", "ER": "ERI", "ES": "ESP", "ET": "ETH", "FI": "FIN", "FJ": "FJI", "FK": "FLK",
    "FM": "FSM", "FO": "FRO", "FR": "FRA", "GA": "GAB", "GB": "GBR", "GD": "GRD", "GE": "GEO", "GF": "GUF", "GG": "GGY",
    "GH": "GHA", "GI": "GIB", "GL": "GRL", "GM": "GMB", "GN": "GIN", "GP": "GLP", "GQ": "GNQ", "GR": "GRC", "GS": "SGS",
    "GT": "GTM", "GU": "GUM", "GW": "GNB", "GY": "GUY", "HK": "HKG", "HM": "HMD", "HN": "HND", "HR": "HRV", "HT": "HTI",
    "HU": "HUN", "ID": "IDN", "IE": "IRL", "IL": "ISR", "IM": "IMN", "IN": "IND", "IO": "IOT", "IQ": "IRQ", "IR": "IRN",
    "IS": "ISL", "IT": "ITA", "JE": "JEY", "JM": "JAM", "JO": "JOR", "JP": "JPN", "KE": "KEN", "KG": "KGZ", "KH": "KHM",
    "KI": "KIR", "KM": "COM", "KN": "KNA", "KP": "PRK", "KR": "KOR", "KW": "KWT", "KY": "CYM", "KZ": "KAZ", "LA": "LAO",
    "LB": "LBN", "LC": "LCA", "LI": "LIE", "LK": "LKA", "LR": "LBR", "LS": "LSO", "LT": "LTU", "LU": "LUX", "LV": "LVA",
    "LY": "LBY", "MA": "MAR", "MC": "MCO", "MD": "MDA", "ME": "MNE", "MF": "MAF", "MG": "MDG", "MH": "MHL", "MK": "MKD",
    "ML": "MLI", "MM": "MMR", "MN": "MNG", "MO": "MAC", "MP": "MNP", "MQ": "MTQ", "MR": "MRT", "MS": "MSR", "MT": "MLT",
    "MU": "MUS", "MV": "MDV", "MW": "MWI", "MX": "MEX", "MY": "MYS", "MZ": "MOZ", "NA": "NAM", "NC": "NCL", "NE": "NER",
    "NF": "NFK", "NG": "NGA", "NI": "NIC", "NL": "NLD", "NO": "NOR", "NP": "NPL", "NR": "NRU", "NU": "NIU", "NZ": "NZL",
    "OM": "OMN", "PA": "PAN", "PE": "PER", "PF": "PYF", "PG": "PNG", "PH": "PHL", "PK": "PAK", "PL": "POL", "PM": "SPM",
    "PN": "PCN", "PR": "PRI", "PS": "PSE", "PT": "PRT", "PW": "PLW", "PY": "PRY", "QA": "QAT", "RE": "REU", "RO": "ROU",
    "RS": "SRB", "RU": "RUS", "RW": "RWA", "SA": "SAU", "SB": "SLB", "SC": "SYC", "SD": "SDN", "SE": "SWE", "SG": "SGP",
    "SH": "SHN", "SI": "SVN", "SJ": "SJM", "SK": "SVK", "SL": "SLE", "SM": "SMR", "SN": "SEN", "SO": "SOM", "SR": "SUR",
    "SS": "SSD", "ST": "STP", "SV": "SLV", "SX": "SXM", "SY": "SYR", "SZ": "SWZ", "TC": "TCA", "TD": "TCD", "TF": "ATF",
    "TG": "TGO", "TH": "THA", "TJ": "TJK", "TK": "TKL", "TL": "TLS", "TM": "TKM", "TN": "TUN", "TO": "TON", "TR": "TUR",
    "TT": "TTO", "TV": "TUV", "TW": "TWN", "TZ": "TZA", "UA": "UKR", "UG": "UGA", "UM": "UMI", "US": "USA", "UY": "URY",
    "UZ": "UZB", "VA": "VAT", "VC": "VCT", "VE": "VEN", "VG": "VGB", "VI": "VIR", "VN": "VNM", "VU": "VUT", "WF": "WLF",
    "WS": "WSM", "XK": "XKX", "YE": "YEM", "YT": "MYT", "ZA": "ZAF", "ZM": "ZMB", "ZW": "ZWE", "UK": "GBR", "EU": None,
}
