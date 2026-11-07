"""
Loads API credentials once per process (cleared on "Force refresh").

Each credential comes from the first source that provides it:
  1. environment variables
  2. a single TOML file (~/.config/dt-analytics/credentials.toml, or the path in $DT_CREDENTIALS_FILE)
  3. per-service files (~/.dtapi, ~/.dtdnsdb, ~/.dtcertapi, ~/.dtvpndb)
Keys entered on Settings → API credentials are saved to the TOML file (save_credentials).
The Certificate API uses the DomainTools API key unless a certificate-specific key is configured. Without a VPNDB key
the VPN / proxy / Tor check is skipped.
Sources and options are reported for display; credential values never are.
"""
import functools
import json
import os
import stat
import tempfile
import tomllib
from dataclasses import dataclass
from pathlib import Path

from config import CERT_API_KEY_FILE, CREDENTIALS_FILE, DNSDB_KEY_FILE, DTAPI_FILE, VPNDB_KEY_FILE

ENVIRONMENT, TOML, FILES = "Environment", "credentials.toml", "Files"
SOURCES = (ENVIRONMENT, TOML, FILES)
DOMAINTOOLS, DNSDB, CERT_API, VPNDB = "DomainTools API", "DNSDB Scout", "Certificate API", "VPNDB"
# DomainTools username / key variable pairs, first complete pair wins; DOMAINTOOLS_* are the names the SDK docs use
DOMAINTOOLS_ENV_PAIRS = (("DT_API_USERNAME", "DT_API_KEY"), ("DOMAINTOOLS_USERNAME", "DOMAINTOOLS_API_KEY"))
SERVICES = {
    DOMAINTOOLS: "Iris Investigate (with risk scores), Domain History, Account",
    DNSDB: "Passive DNS (DNSDB)",
    CERT_API: "Certificates, CT log events",
    VPNDB: "VPN, residential proxy and Tor attribution of IPs, prefixes and ASNs",
}
VPNDB_DEFAULT_URL = "https://vpndb.io/api/v1"


@dataclass(frozen=True)
class Credential:
    value: object = None    # str, or (username, api_key) for the DomainTools SDK
    source: str = ""        # where the value came from, e.g. "$DNSDB_API_KEY" or "~/.dtapi"
    warnings: tuple = ()
    kind: str = ""          # one of SOURCES
    origin: tuple = ()      # option keys that supplied the value, e.g. ("env:DNSDB_API_KEY",)

    @property
    def found(self):
        return self.value is not None


def credentials_file():
    override = os.environ.get("DT_CREDENTIALS_FILE", "").strip()
    return Path(override).expanduser() if override else CREDENTIALS_FILE


def display_path(path):
    path = Path(path)
    try:
        return f"~/{path.relative_to(Path.home())}"
    except ValueError:
        return str(path)


def _env(name):
    return os.environ.get(name, "").strip() or None


def _read_lines(path):
    try:
        with open(path, "r") as f:
            return [line.strip() for line in f if line.strip()]
    except OSError:
        return []


def _permission_warnings(path):
    try:
        mode = Path(path).stat().st_mode
    except OSError:
        return ()
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        return (f"{display_path(path)} is accessible by other users; restrict it with: chmod 600 {display_path(path)}",)
    return ()


def _from_file(value, path, kind, origin, section=""):
    return Credential(value, f"{display_path(path)} {section}".strip(), _permission_warnings(path), kind, origin)


@functools.lru_cache(maxsize=1)
def _load_toml():
    """(data, error) from the credentials file; ({}, None) when the file does not exist."""
    path = credentials_file()
    try:
        with open(path, "rb") as f:
            return tomllib.load(f), None
    except FileNotFoundError:
        return {}, None
    except (OSError, tomllib.TOMLDecodeError) as exc:
        return {}, f"{display_path(path)} could not be read ({exc}); falling back to the files."


def _toml_value(section, key):
    data, _ = _load_toml()
    entries = data.get(section)
    value = entries.get(key) if isinstance(entries, dict) else None
    return str(value).strip() or None if value is not None else None


def _half_set_env_warning(user_var, key_var, user_is_set, fallback_source):
    """Names the one DomainTools variable of a pair that is set and the source used instead."""
    present, missing = (f"${user_var}", f"${key_var}") if user_is_set else (f"${key_var}", f"${user_var}")
    used = f"using {fallback_source} instead" if fallback_source else "no other DomainTools credentials were found"
    return f"{present} is set without {missing}, so it is ignored; {used}."


@functools.lru_cache(maxsize=1)
def dtapi_credential():
    """(username, api_key) for the DomainTools SDK; both parts always come from the same source."""
    found, half_set = Credential(), []
    for user_var, key_var in DOMAINTOOLS_ENV_PAIRS:
        user, key = _env(user_var), _env(key_var)
        if user and key:
            found = Credential((user, key), f"${user_var} / ${key_var}", kind=ENVIRONMENT,
                               origin=(f"env:{user_var}", f"env:{key_var}"))
            break
        if user or key:
            half_set.append((user_var, key_var, bool(user)))
    if not found.found:
        user, key = _toml_value("domaintools", "username"), _toml_value("domaintools", "api_key")
        if user and key:
            found = _from_file((user, key), credentials_file(), TOML, ("toml:domaintools.username", "toml:domaintools.api_key"),
                               "[domaintools]")
        else:
            lines = _read_lines(DTAPI_FILE)
            if len(lines) >= 2:
                found = _from_file((lines[0], lines[1]), DTAPI_FILE, FILES, ("file:dtapi",))
    warnings = tuple(_half_set_env_warning(*pair, found.source) for pair in half_set)
    return Credential(found.value, found.source, warnings + found.warnings, found.kind, found.origin)


def _single_key(env_name, section, key_file, file_option):
    key = _env(env_name)
    if key:
        return Credential(key, f"${env_name}", kind=ENVIRONMENT, origin=(f"env:{env_name}",))
    key = _toml_value(section, "api_key")
    if key:
        return _from_file(key, credentials_file(), TOML, (f"toml:{section}.api_key",), f"[{section}]")
    lines = _read_lines(key_file)
    if lines:
        return _from_file(lines[0], key_file, FILES, (file_option,))
    return Credential()


@functools.lru_cache(maxsize=1)
def dnsdb_credential():
    return _single_key("DNSDB_API_KEY", "dnsdb", DNSDB_KEY_FILE, "file:dtdnsdb")


@functools.lru_cache(maxsize=1)
def cert_api_credential():
    """A certificate-specific key when configured, otherwise the DomainTools API key."""
    specific = _single_key("DT_CERT_API_KEY", "cert_api", CERT_API_KEY_FILE, "file:dtcertapi")
    if specific.found:
        return specific
    dtapi = dtapi_credential()
    if dtapi.found:
        username_options = {"toml:domaintools.username", *(f"env:{user_var}" for user_var, _ in DOMAINTOOLS_ENV_PAIRS)}
        origin = tuple(o for o in dtapi.origin if o not in username_options)   # only the API key part is used
        return Credential(dtapi.value[1], f"DomainTools API key ({dtapi.source})", dtapi.warnings, dtapi.kind, origin)
    return Credential()


@functools.lru_cache(maxsize=1)
def vpndb_credential():
    return _single_key("VPNDB_API_KEY", "vpndb", VPNDB_KEY_FILE, "file:dtvpndb")


def vpndb_base_url():
    """$VPNDB_URL, [vpndb] url in credentials.toml (an on-premise installation), or the hosted API."""
    url = _env("VPNDB_URL") or _toml_value("vpndb", "url") or VPNDB_DEFAULT_URL
    return url.rstrip("/")


def load_dtapi_credentials():
    """Returns (username, api_key), or None if not configured."""
    return dtapi_credential().value


def load_dnsdb_key():
    return dnsdb_credential().value


def load_cert_api_key():
    return cert_api_credential().value


def load_vpndb_key():
    return vpndb_credential().value


@functools.lru_cache(maxsize=1)
def get_dt_api():
    """Shared DomainTools SDK client, or None when no DomainTools credentials are configured."""
    creds = load_dtapi_credentials()
    if not creds:
        return None
    from domaintools import API
    return API(creds[0], creds[1], app_name="dt_analytics_detection")


def _service_credentials():
    return {DOMAINTOOLS: dtapi_credential(), DNSDB: dnsdb_credential(), CERT_API: cert_api_credential(),
            VPNDB: vpndb_credential()}


def _option_specs():
    """(source, option key, label, services it can supply, configured, detail) for every supported option."""
    env = [
        ("DT_API_USERNAME", (DOMAINTOOLS,), "Paired with $DT_API_KEY"),
        ("DT_API_KEY", (DOMAINTOOLS, CERT_API), "Paired with $DT_API_USERNAME; also the Certificate API key"),
        ("DOMAINTOOLS_USERNAME", (DOMAINTOOLS,), "SDK docs name; paired with $DOMAINTOOLS_API_KEY; $DT_API_* wins"),
        ("DOMAINTOOLS_API_KEY", (DOMAINTOOLS, CERT_API), "SDK docs name; paired with $DOMAINTOOLS_USERNAME; $DT_API_* wins"),
        ("DNSDB_API_KEY", (DNSDB,), ""),
        ("DT_CERT_API_KEY", (CERT_API,), "Only if the Certificate API needs its own key"),
        ("VPNDB_API_KEY", (VPNDB,), "$VPNDB_URL points at an on-premise installation"),
    ]
    specs = [(ENVIRONMENT, f"env:{name}", f"${name}", services, bool(_env(name)), detail) for name, services, detail in env]
    toml = [
        ("domaintools", "username", (DOMAINTOOLS,), ""),
        ("domaintools", "api_key", (DOMAINTOOLS, CERT_API), "Also the Certificate API key"),
        ("dnsdb", "api_key", (DNSDB,), ""),
        ("cert_api", "api_key", (CERT_API,), "Only if the Certificate API needs its own key"),
        ("vpndb", "api_key", (VPNDB,), "[vpndb] url points at an on-premise installation"),
    ]
    specs += [(TOML, f"toml:{section}.{key}", f"[{section}] {key}", services, bool(_toml_value(section, key)), detail)
              for section, key, services, detail in toml]
    dtapi_lines = len(_read_lines(DTAPI_FILE))
    specs += [
        (FILES, "file:dtapi", display_path(DTAPI_FILE), (DOMAINTOOLS, CERT_API), dtapi_lines >= 2,
         "Line 1 username, line 2 API key (also the Certificate API key)"
         + ("; incomplete: only one line found" if dtapi_lines == 1 else "")),
        (FILES, "file:dtdnsdb", display_path(DNSDB_KEY_FILE), (DNSDB,), bool(_read_lines(DNSDB_KEY_FILE)), "API key on line 1"),
        (FILES, "file:dtcertapi", display_path(CERT_API_KEY_FILE), (CERT_API,), bool(_read_lines(CERT_API_KEY_FILE)),
         "Optional: only if the Certificate API needs its own key"),
        (FILES, "file:dtvpndb", display_path(VPNDB_KEY_FILE), (VPNDB,), bool(_read_lines(VPNDB_KEY_FILE)),
         "VPNDB API key on line 1"),
    ]
    return specs


def credential_overview():
    """
    What is configured in each source and what queries actually use; never the values.
    Returns {"services": [...], "options": {source: [...]}, "toml": {...}, "matrix": [service x source status]}.
    """
    resolved = _service_credentials()
    option_files = {"file:dtapi": DTAPI_FILE, "file:dtdnsdb": DNSDB_KEY_FILE, "file:dtcertapi": CERT_API_KEY_FILE,
                    "file:dtvpndb": VPNDB_KEY_FILE}
    services = [{"Service": name, "Used by": SERVICES[name], "Found": cred.found, "Kind": cred.kind,
                 "Source": cred.source or "Not configured", "Warnings": list(dict.fromkeys(cred.warnings))}
                for name, cred in resolved.items()]
    options = {source: [] for source in SOURCES}
    for source, key, label, can_supply, configured, detail in _option_specs():
        used_for = [name for name, cred in resolved.items() if key in cred.origin]
        note = ""
        if configured and not used_for:
            others = [f"{name} uses {resolved[name].source}" for name in can_supply if resolved[name].found]
            note = "Not used: " + "; ".join(others) if others else "Not used"
            for user_var, key_var in DOMAINTOOLS_ENV_PAIRS:
                if key in (f"env:{user_var}", f"env:{key_var}") and not (_env(user_var) and _env(key_var)):
                    note = f"Not used: ${user_var} and ${key_var} must both be set" + (f"; {'; '.join(others)}" if others else "")
        path = option_files.get(key)
        options[source].append({
            "Option": label, "For": list(can_supply), "Configured": configured, "Used for": used_for,
            "Detail": detail, "Note": note, "Warnings": list(_permission_warnings(path)) if path and configured else [],
        })
    toml_path = credentials_file()
    error = _load_toml()[1]
    toml = {"path": display_path(toml_path), "exists": toml_path.exists(), "error": error,
            "overridden": bool(_env("DT_CREDENTIALS_FILE")),
            "warnings": list(_permission_warnings(toml_path)) if toml_path.exists() else []}
    matrix = [{"Service": name, **{source: _matrix_status(name, cred, source, options[source]) for source in SOURCES}}
              for name, cred in resolved.items()]
    return {"services": services, "options": options, "toml": toml, "matrix": matrix}


IN_USE, SET_NOT_USED, NOT_SET = "in use", "set, not used", "not set"


def _matrix_status(service, credential, source, source_options):
    """Whether `source` supplies `service`, has an option for it that a higher-priority source overrides, or has none."""
    if credential.kind == source:
        return IN_USE
    if any(o["Configured"] and service in o["For"] for o in source_options):
        return SET_NOT_USED
    return NOT_SET


SECTIONS = {DOMAINTOOLS: "domaintools", DNSDB: "dnsdb", CERT_API: "cert_api", VPNDB: "vpndb"}   # credentials.toml table per service


class CredentialFileError(Exception):
    """credentials.toml cannot be updated safely (unreadable, or holds values the app would not write back)."""


def _toml_key(name):
    return name if name and all(c.isalnum() or c in "_-" for c in name) else json.dumps(name)


def _toml_text(data):
    """TOML for {table: {key: scalar}}; JSON string escapes are valid TOML basic strings."""
    blocks = []
    for section, entries in data.items():
        lines = [f"[{_toml_key(section)}]"]
        for key, value in entries.items():
            shown = json.dumps(value) if isinstance(value, str) else str(value).lower() if isinstance(value, bool) else value
            lines.append(f"{_toml_key(key)} = {shown}")
        blocks.append("\n".join(lines))
    return "\n\n".join(blocks) + "\n" if blocks else ""


def saved_sections():
    """The services whose table is in credentials.toml (whatever wins in the end)."""
    data, _ = _load_toml()
    return [service for service, section in SECTIONS.items() if isinstance(data.get(section), dict)]


def save_credentials(updates, remove=()):
    """
    Writes `updates` ({service: {"username"/"api_key": value}}) into credentials.toml and drops the tables of the
    services in `remove`. Other tables and keys are kept; comments are not. The file is replaced atomically, created
    readable only by you (0600) in a folder only you can open (0700). Returns the file's display path.
    """
    path = credentials_file()
    data = {}
    if path.exists():
        try:
            with open(path, "rb") as f:
                data = tomllib.load(f)
        except (OSError, tomllib.TOMLDecodeError) as exc:
            raise CredentialFileError(f"{display_path(path)} could not be read ({exc}); fix or remove it first.") from exc
    if any(not isinstance(entries, dict) or any(isinstance(v, (dict, list)) for v in entries.values())
           for entries in data.values()):
        raise CredentialFileError(f"{display_path(path)} has entries the app does not write back; edit it by hand.")
    for service in remove:
        data.pop(SECTIONS[service], None)
    for service, values in updates.items():
        entries = data.setdefault(SECTIONS[service], {})
        entries.update({key: value.strip() for key, value in values.items() if value and value.strip()})
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, temp = tempfile.mkstemp(dir=path.parent, prefix=".credentials-", suffix=".toml")   # created 0600
    try:
        with os.fdopen(fd, "w") as f:
            f.write(_toml_text(data))
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp, path)
    except BaseException:
        Path(temp).unlink(missing_ok=True)
        raise
    os.chmod(path, 0o600)
    clear_credential_cache()
    return display_path(path)


def clear_credential_cache():
    for loader in (_load_toml, dtapi_credential, dnsdb_credential, cert_api_credential, vpndb_credential, get_dt_api):
        loader.cache_clear()


_FILE = display_path(credentials_file())
DTAPI_MISSING = (f"DomainTools credentials not found: set [domaintools] username and api_key in {_FILE}, "
                 "set $DT_API_USERNAME and $DT_API_KEY (or $DOMAINTOOLS_USERNAME and $DOMAINTOOLS_API_KEY), "
                 "or put the username and key on lines 1-2 of ~/.dtapi")
DNSDB_MISSING = f"DNSDB key not found: set [dnsdb] api_key in {_FILE}, set $DNSDB_API_KEY, or create ~/.dtdnsdb"
CERT_API_MISSING = (f"Certificate API key not found: it uses the DomainTools API key ([domaintools] api_key in {_FILE}, "
                    "$DT_API_KEY, $DOMAINTOOLS_API_KEY, or line 2 of ~/.dtapi) unless [cert_api] api_key or $DT_CERT_API_KEY is set")
VPNDB_MISSING = (f"VPNDB key not found: set [vpndb] api_key in {_FILE}, set $VPNDB_API_KEY, or create ~/.dtvpndb "
                 "(create a key on vpndb.io under Account → API keys)")
