"""Static reference data for detection rules: CDN ranges, provider lists, rule metadata, and ATT&CK tactics.

Lists here are curated snapshots - review and extend them for your environment. Watchlist matches are
investigative leads, not proof of abuse.
"""

# --- CDN IP RANGES (published by the providers, or announced by their networks; snapshot) ---
# Ranges Cloudflare, Fastly and Amazon CloudFront publish for their edge networks, and those Akamai's CDN networks
# announce; an IP inside one is a CDN edge, shared by many unrelated sites, not the origin server
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
    # AWS ip-ranges.json, service CLOUDFRONT (edge and origin-facing), merged; snapshot of 2026-11-13
    "Amazon CloudFront": [
        "3.10.17.128/25", "3.11.53.0/24", "3.29.40.64/26", "3.29.40.128/25", "3.29.57.0/26", "3.35.130.128/25",
        "3.101.158.0/23", "3.107.43.128/25", "3.107.44.0/24", "3.128.93.0/24", "3.134.215.0/24",
        "3.146.232.0/22", "3.147.164.0/22", "3.147.244.0/22", "3.160.0.0/13", "3.168.0.0/14", "3.172.0.0/17",
        "3.173.0.0/16", "3.174.0.0/15", "3.231.2.0/25", "3.234.232.224/27", "3.236.48.0/23", "3.236.169.192/26",
        "13.32.0.0/15", "13.35.0.0/16", "13.54.63.128/26", "13.59.250.0/26", "13.113.196.64/26",
        "13.113.203.0/24", "13.124.199.0/24", "13.134.24.0/23", "13.134.94.0/23", "13.203.133.0/26",
        "13.210.67.128/26", "13.224.0.0/14", "13.228.69.0/24", "13.233.177.192/26", "13.249.0.0/16",
        "15.158.0.0/16", "15.188.184.0/24", "15.207.13.128/25", "15.207.213.128/25", "18.64.0.0/14",
        "18.68.0.0/16", "18.154.0.0/15", "18.160.0.0/15", "18.164.0.0/15", "18.172.0.0/15", "18.175.65.0/24",
        "18.175.66.0/23", "18.192.142.0/23", "18.199.68.0/22", "18.199.72.0/21", "18.200.212.0/23",
        "18.216.170.128/25", "18.229.220.192/26", "18.230.229.0/24", "18.230.230.0/25", "18.238.0.0/15",
        "18.244.0.0/15", "23.91.0.0/19", "23.228.212.0/23", "23.228.214.0/24", "23.228.220.0/22",
        "23.228.244.0/24", "23.228.246.0/23", "23.228.248.0/22", "23.234.192.0/18", "24.110.32.0/19",
        "24.110.128.0/17", "34.195.252.0/24", "34.216.51.0/25", "34.223.12.224/27", "34.223.80.192/26",
        "34.226.14.0/24", "35.93.168.0/22", "35.93.172.0/23", "35.158.136.0/24", "35.162.63.192/26",
        "35.167.191.128/26", "36.103.232.0/25", "36.103.232.128/26", "43.218.56.64/26", "43.218.56.128/25",
        "43.218.71.0/26", "44.220.194.0/23", "44.220.196.0/22", "44.220.200.0/22", "44.222.66.0/24",
        "44.227.178.0/24", "44.234.90.252/30", "44.234.108.128/25", "47.129.82.0/23", "47.129.84.0/24",
        "51.44.234.0/23", "51.44.236.0/22", "51.72.40.128/27", "51.74.20.0/23", "51.74.22.0/24",
        "51.74.192.0/18", "52.15.127.128/26", "52.46.0.0/18", "52.47.139.0/24", "52.52.191.128/26",
        "52.56.127.0/25", "52.57.254.0/24", "52.66.194.128/26", "52.78.247.128/26", "52.82.128.0/19",
        "52.84.0.0/15", "52.124.128.0/17", "52.199.127.192/26", "52.212.248.0/26", "52.220.191.0/26",
        "52.222.128.0/17", "54.182.0.0/16", "54.192.0.0/16", "54.230.0.0/17", "54.230.128.0/18",
        "54.230.200.0/21", "54.230.208.0/20", "54.230.224.0/19", "54.233.255.128/26", "54.239.128.0/18",
        "54.239.192.0/19", "54.240.128.0/18", "56.125.46.0/24", "56.125.47.0/32", "56.125.48.0/24",
        "57.182.253.0/24", "57.183.42.0/25", "58.254.138.0/25", "58.254.138.128/26", "64.252.64.0/18",
        "64.252.128.0/18", "65.8.0.0/16", "65.9.0.0/17", "65.9.128.0/18", "70.132.0.0/18", "71.152.0.0/17",
        "99.79.169.0/24", "99.84.0.0/16", "99.86.0.0/16", "108.138.0.0/15", "108.156.0.0/14",
        "111.13.171.128/25", "111.13.185.32/27", "111.13.185.64/27", "116.129.226.0/25", "116.129.226.128/26",
        "118.193.97.64/26", "118.193.97.128/25", "119.147.182.0/25", "119.147.182.128/26", "120.52.12.64/26",
        "120.52.22.96/27", "120.52.39.128/27", "120.52.153.192/26", "120.232.236.0/25", "120.232.236.128/26",
        "120.253.240.192/26", "120.253.241.160/27", "120.253.245.128/26", "120.253.245.192/27",
        "130.176.0.0/17", "130.176.128.0/18", "130.176.192.0/19", "130.176.224.0/20", "143.204.0.0/16",
        "144.220.0.0/16", "180.163.57.0/25", "180.163.57.128/26", "204.246.164.0/22", "204.246.168.0/21",
        "204.246.176.0/20", "205.251.202.0/23", "205.251.204.0/22", "205.251.208.0/20", "205.251.249.0/24",
        "205.251.250.0/23", "205.251.252.0/23", "205.251.254.0/24", "216.137.32.0/19", "2001:3fc6:4::/47",
        "2001:3fc6:20::/43", "2400:7fc0:500::/40", "2404:c2c0:500::/40", "2409:8c00:2421:300::/56",
        "2409:8c00:2421:400::/56", "2600:9000:ddd::/48", "2600:9000:eee::/48", "2600:9000:fff::/48",
        "2600:9000:1000::/36", "2600:9000:2000::/35", "2600:9000:4000::/36", "2600:9000:5200::/40",
        "2600:9000:5308::/45", "2600:9000:5310::/44", "2600:9000:5320::/43", "2600:9000:5340::/42",
        "2600:9000:5380::/41", "2600:9000:6000::/36", "2600:9000:f000::/38", "2600:9000:f400::/40",
        "2600:9000:f500::/43", "2600:9000:f520::/44", "2600:9000:f534::/46", "2600:9000:f538::/45",
        "2600:9000:f540::/42", "2600:9000:f580::/41", "2600:9000:f600::/39", "2600:9000:f800::/37",
        "2600:f0f0:9::/48", "2600:f0f0:601::/48", "2600:f0f0:602::/47", "2600:f0f0:5504::/46",
    ],
    # Akamai publishes no range list: the prefixes its CDN networks announce (AS20940, AS16625; RIPEstat), merged;
    # snapshot of 2026-11-13. Linode (AS63949, Akamai Cloud) is left out: it hosts customers' own servers.
    "Akamai": [
        "2.16.0.0/13", "23.0.0.0/12", "23.32.0.0/11", "23.64.0.0/14", "23.72.0.0/13", "23.192.0.0/11",
        "43.254.120.0/22", "49.231.112.0/24", "49.231.116.0/23", "59.151.128.0/18", "60.254.128.0/18",
        "61.19.12.0/24", "64.86.217.0/24", "66.198.8.0/24", "69.22.150.0/23", "69.31.112.0/23",
        "69.31.118.0/24", "69.31.122.0/24", "69.192.0.0/16", "72.246.0.0/15", "80.67.64.0/19", "84.53.128.0/18",
        "88.221.0.0/16", "92.122.0.0/15", "93.191.168.0/24", "95.100.0.0/15", "96.6.0.0/15", "96.16.0.0/15",
        "103.95.84.0/22", "103.238.148.0/22", "104.64.0.0/10", "109.207.109.0/24", "109.230.116.0/22",
        "109.230.127.0/24", "115.69.232.0/22", "118.214.0.0/16", "118.215.0.0/17", "118.215.128.0/18",
        "121.78.46.0/24", "121.254.136.0/24", "122.2.208.0/24", "122.252.32.0/19", "122.252.128.0/20",
        "124.106.8.0/24", "124.106.175.0/24", "125.56.192.0/18", "125.252.192.0/18", "165.254.0.0/24",
        "165.254.2.0/24", "165.254.26.128/26", "165.254.40.0/23", "165.254.44.0/23", "165.254.52.0/24",
        "165.254.58.0/25", "165.254.81.0/24", "165.254.110.0/23", "165.254.119.128/25", "165.254.123.0/24",
        "165.254.136.0/24", "165.254.142.0/24", "165.254.145.64/26", "165.254.156.0/23", "165.254.203.192/26",
        "165.254.237.128/25", "165.254.238.128/25", "165.254.247.128/25", "168.143.242.0/23", "172.224.0.0/12",
        "173.205.69.0/24", "173.205.76.0/23", "173.222.0.0/15", "184.24.0.0/13", "184.50.0.0/15",
        "184.84.0.0/14", "185.225.250.0/24", "187.210.208.0/24", "189.247.167.0/24", "189.247.204.0/22",
        "189.247.210.0/24", "189.247.212.0/24", "189.247.214.0/24", "189.247.216.0/24", "189.247.220.0/24",
        "190.94.188.0/24", "190.98.153.0/24", "190.98.160.0/24", "192.80.13.0/24", "192.204.5.0/24",
        "193.108.88.0/21", "193.108.152.0/22", "195.245.124.0/22", "198.87.182.0/25", "198.173.160.0/23",
        "200.60.136.0/24", "200.60.190.0/24", "202.138.164.0/22", "202.138.183.0/24", "203.69.138.0/24",
        "203.69.141.0/24", "203.74.95.0/24", "203.144.1.0/24", "203.198.20.0/24", "203.251.233.0/24",
        "203.251.234.0/24", "204.1.141.0/24", "204.2.139.0/24", "204.2.145.0/24", "204.2.158.0/23",
        "204.2.162.0/24", "204.2.164.0/23", "204.2.196.0/24", "204.8.48.0/22", "204.10.28.0/22",
        "204.93.48.0/24", "204.201.160.0/24", "204.237.186.0/23", "204.237.188.0/24", "210.61.248.0/23",
        "218.231.251.0/24", "219.76.11.0/24", "2001:418:1401:4::/64", "2001:418:1401:7::/64",
        "2001:418:1401:18::/64", "2001:418:1401:21::/64", "2001:418:1401:25::/64", "2001:418:1401:6a::/64",
        "2001:418:1401:71::/64", "2001:418:1401:7d::/64", "2001:418:4001:2::/64", "2001:418:4001:4::/64",
        "2001:590:2005:200::/56", "2001:668:108:400::/56", "2001:668:108:6000::/64", "2001:c38:500a::/48",
        "2001:41a8:807:100::/56", "2001:4450:40::/48", "2001:4457:ff0::/48", "2001:4546:1003::/48",
        "2401:fdc0:a000::/48", "2403:c780:7203::/48", "2404:c800:8203::/48", "2405:2000:2c02::/48",
        "2405:9600::/32", "2406:3000:35::/48", "2600:1400::/24", "2620:11b:d021::/48", "2800:280:4001::/48",
        "2806:1070:cefe::/48", "2a02:26f0::/32", "2a02:26f6::/48", "2a02:26f7::/32", "2a10:f783:23::/48",
        "2a10:fa44::/48", "2c0f:fc00:b011::/48",
    ],
}

# ISP / organization name fragments (from Iris IP data) that identify CDN or reverse-proxy networks
CDN_ISP_MARKERS = {
    "cloudflare": "Cloudflare", "cloudfront": "Amazon CloudFront", "akamai": "Akamai", "fastly": "Fastly", "incapsula": "Imperva", "imperva": "Imperva",
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

# JA4X certificate fingerprints of C2 frameworks and malware (FoxIO JA4+ database, as published with JA4+). A JA4X
# says how a certificate was generated, not what it names, so an unrelated certificate built with the same fields and
# extensions has the same value: confirm a match with the certificate itself. Editable; verify before acting.
KNOWN_JA4X = {
    "2166164053c1_2166164053c1_30d204a01551": "Cobalt Strike (default certificate)",
    "000000000000_4f24da86fad6_bf0f0589fc03": "Sliver / Havoc C2",
    "000000000000_7c32fa18c13e_bf0f0589fc03": "Sliver / Havoc C2",
    "2bab15409345_2bab15409345_75f1b0fafedd": "Metasploit",
    "2bab15409345_af684594efb4_000000000000": "Qakbot",
    "2bab15409345_af684594efb4_e3b0c44298fc": "Qakbot",
    "1a59268f55e5_1a59268f55e5_795797892f9c": "Pikabot",
    "7022c563de38_7022c563de38_0147df7a0c11": "AsyncRAT / QuasarRAT / BitRAT",
}

# JA4X fingerprints of dual-use tools: legitimate software that attackers also run for tunnels and remote access.
# Editable; verify before acting.
DUAL_USE_JA4X = {
    "d55f458d5a6c_d55f458d5a6c_0fc8c171b6ae": "SoftEther VPN",
}

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
    "T1572": "Command and Control", "T1583": "Resource Development", "T1584": "Resource Development", "T1585": "Resource Development",
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
    "Known C2 Certificate Fingerprint (JA4X)": ("Certificates", "Medium"),
    "Dual-Use Tool Certificate Fingerprint (JA4X)": ("Certificates", "Low"),
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
