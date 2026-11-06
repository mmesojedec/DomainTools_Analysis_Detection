"""TXT record application fingerprinting and encoded-payload detection."""
import re
import string

import pandas as pd

from core.threat_detection.context import upper_fields

APP_SIGNATURES = {
    # --- Core Email Authentication ---
    "DMARC": r"v=DMARC1",
    "SPF": r"v=spf1",
    "Sender ID (SPF 2.0)": r"spf2\.0/(?:pra|mfrom)",
    "BIMI (Brand Logo)": r"v=BIMI1",
    "DKIM / Crypto Key": r"v=DKIM1|p=[A-Za-z0-9+/]{40,}",
    "ValiMail": r"vali\.email",
    "SparkPost": r"sparkpost\.com",

    # --- Cloud Hyperscalers & Big Tech ---
    "Google Workspace / Gemini": r"google-site-verification=",
    "Microsoft 365 / Copilot / Azure": r"\bMS=(?:ms|[A-Fa-f0-9]{30,})|include:spf\.protection\.outlook\.com",
    "Apple Configuration": r"apple-domain-verification=",
    "Amazon SES / AWS": r"amazonses:|aws-waf-",
    "Yandex": r"yandex-verification=",
    "Yahoo": r"yahoo-verification-key=",
    "Facebook / Meta": r"facebook-domain-verification=",
    "LinkedIn": r"linkedin-site-verification=",

    # --- Modern AI & Developer Platforms ---
    "OpenAI": r"openai-domain-verification=",
    "Anthropic (Claude)": r"anthropic-domain-verification-",
    "Hugging Face": r"huggingface-domain-verification=",
    "Cursor (AI IDE)": r"cursor-domain-verification",
    "Gamma (AI Workspace)": r"gamma-domain-verification",
    "Shade (AI Assets)": r"shade-domain-verification",
    "MongoDB Atlas": r"mongodb-site-verification=",
    "Serval (AI Search)": r"serval-domain-verification",
    "GitHub": r"_github-challenge",

    # --- Enterprise Security & Privacy Governance ---
    "Wiz Cloud Security": r"wiz-domain-verification=",
    "1Password": r"1password-site-verification=",
    "OneTrust Privacy & Consent": r"onetrust-domain-verification=",
    "Okta": r"okta-verification=",
    "Datadog": r"datadog-verification=",
    "Jamf Apple MDM": r"jamf-site-verification=",
    "GlobalSign SSL": r"globalsign-smime-dv=|_?globalsign-domain-verification=",
    "Cisco Common Identity (Webex / Duo)": r"cisco-ci-domain-verification=",

    # --- Collaboration & Digital Workspaces ---
    "Slack": r"slack-domain-verification=",
    "Zoom": r"zoom-domain-verification=|ZOOM_verify_",
    "Cisco Webex": r"webex-domain-verification=",
    "Atlassian (Jira / Confluence)": r"atlassian(?:-sending)?-domain-verification=",
    "Notion": r"notion-domain-verification=",
    "Miro": r"miro-verification=",
    "Asana": r"\basv=",
    "Wrike": r"wrike-verification=",
    "Box": r"box-domain-verification=",
    "Dropbox": r"dropbox-domain-verification=",
    "LucidLink": r"lucidlink-verification=",
    "MASV File Transfer": r"\bmasv=",
    "Parallels": r"parallels-domain-verification=",
    "Canva": r"canva-site-verification=",

    # --- Customer Data, CRM & Marketing Automation ---
    "Twilio Segment (CDP)": r"segment-site-verification=",
    "Klaviyo Marketing": r"klaviyo-site-verification=",
    "Salesforce": r"salesforce-domain-verification=",
    "Salesforce Marketing Cloud (ExactTarget)": r"exacttarget\.com",
    "HubSpot": r"hubspot-developer-verification=",
    "Zendesk": r"include:mail\.zendesk\.com",
    "LogMeIn / GoTo": r"logmein-verification-code=",
    "SendGrid": r"include:sendgrid\.net",
    "Mailgun": r"include:mailgun\.org",
    "Mailchimp": r"mailchimp-domain-verification=|include:servers\.mcsv\.net",
    "Postscript SMS": r"ps-cd-verification=",

    # --- E-Commerce & Business Operations ---
    "Stripe": r"stripe-verification=",
    "Shopify": r"shopify-verification=",
    "DocuSign": r"docusign=",
    "Adobe": r"adobe-sign-verification=|adobe-idp-site-verification=",
    "SmartSheet": r"smartsheet-site-validation=",
    "Dell Technologies": r"dell-technologies-domain-verification=",
    "Brave Rewards": r"brave-ledger-verification=",
}

_COMPILED_SIGNATURES = [(app, re.compile(pattern, re.IGNORECASE)) for app, pattern in APP_SIGNATURES.items()]
_B64_PATTERN = re.compile(r"^[A-Za-z0-9+/]{30,}={0,2}$")
_B32_PATTERN = re.compile(r"^[A-Z2-7]{30,}={0,6}$")
# Iris pDNS source "A" returns TXT rdata without quotes and without its first character ("oogle-site-verification=",
# "=spf1", "=DKIM1"); the candidates for that character, most likely first
LOST_FIRST_SOURCE = "A"
_LOST_FIRST = "v" + string.ascii_lowercase.replace("v", "") + string.digits + "_" + string.ascii_uppercase

KNOWN_CATEGORY = "Known SaaS / Infrastructure"
TUNNEL_CATEGORY = "Potential Tunneling / C2"


def restore_first_char(entry):
    """
    `entry` with the first character Iris pDNS source A dropped put back, when exactly that character makes it a known
    signature (one that matches from the start, so the restored character is part of it); None when none does.
    """
    for char in _LOST_FIRST:
        candidate = char + entry
        if any(match.start() == 0 for _, pattern in _COMPILED_SIGNATURES for match in [pattern.search(candidate)]
               if match):
            return candidate
    return None


def classify_txt_entry(entry, source=""):
    """Returns (application, category) for one TXT string; a source A string is read with its first character back."""
    if source == LOST_FIRST_SOURCE:
        entry = restore_first_char(entry) or entry
    for app, pattern in _COMPILED_SIGNATURES:
        if pattern.search(entry):
            return app, KNOWN_CATEGORY
    if _B64_PATTERN.match(entry):
        return "Suspicious Base64 Payload", TUNNEL_CATEGORY
    if _B32_PATTERN.match(entry):
        return "Suspicious Base32 Payload", TUNNEL_CATEGORY
    return "Unknown / Custom TXT", "Uncategorized"


def _fmt(value):
    parsed = pd.to_datetime(value, errors="coerce")
    return parsed.strftime("%Y-%m-%d %H:%M:%S") if pd.notna(parsed) else ""


def analyze_txt_fingerprints(pdns_df):
    """Identifies known SaaS configurations or flags suspicious base32/base64 encoded payloads."""
    if pdns_df is None or pdns_df.empty or "Field" not in pdns_df.columns:
        return pd.DataFrame()

    txt_df = pdns_df[upper_fields(pdns_df) == "TXT"]
    if txt_df.empty:
        return pd.DataFrame()

    results = []
    for _, row in txt_df.iterrows():
        source_val = str(row.get("Source", "") or "")
        if source_val == "nan":
            source_val = ""
        first_seen = _fmt(row.get("First Seen")) or _fmt(row.get("Date"))
        last_seen = _fmt(row.get("Last Seen")) or _fmt(row.get("End")) or first_seen

        for line in str(row.get("Value", "")).split("\n"):
            entry = line.strip(' "\'\n\\')
            if not entry:
                continue
            app, category = classify_txt_entry(entry, source_val)
            restored = restore_first_char(entry) if source_val == LOST_FIRST_SOURCE else None
            results.append({
                "Domain": row["Domain"],
                "Source": source_val or "Unknown",
                "Application / Tag": app,
                "Category": category,
                "First Seen": first_seen,
                "Last Seen": last_seen,
                "Query Count": row.get("Count", 1),
                "Lifespan (Days)": row.get("Lifespan Days", 0),
                "Original Payload": entry,
                "Note": f"Iris source A dropped the first character; read as {restored[:60]}" if restored else "",
            })

    return pd.DataFrame(results)
