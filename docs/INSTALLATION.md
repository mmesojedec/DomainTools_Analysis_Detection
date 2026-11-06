# Installation

How to install the app, configure API credentials and start it. For running an analysis, see the
[Usage guide](USAGE.md); for reading the results (alerts, severity and confidence, DIF fingerprints, risk scores,
ATT&CK mapping), see the [User Guide](USER_GUIDE.md).

## Contents

- [Requirements](#requirements)
- [Install](#install)
- [Credentials](#credentials)
- [Run the app](#run-the-app)
- [Development](#development)

## Requirements

- **Python 3.11 or newer.** The credentials file is read with the standard library `tomllib`. Tested with
  Python 3.14, Streamlit 1.66, pandas 3.0, Plotly 7.1 and `domaintools_api` 2.10.
- **Streamlit 1.66 or newer** (`requirements.txt`): the Data Export page builds its files only when you click
  Download, and the IrisQL / CertsQL query editor is a Streamlit custom component (`st.components.v2`). The
  editor's CodeMirror 5 library ships with the app in `views/assets/codemirror` (MIT license there): nothing extra
  to install, and no internet access needed for it.
- **DomainTools API access**, for Domain History, Risk Evidence and Iris Investigate; the same API key is used
  for the Certificate API.
- **DNSDB Scout API key**, for passive DNS through DNSDB, CNAME chasing and IP pivots. With Iris pDNS as the
  passive DNS provider it is optional; without it, CNAME chains stop where the collected data ends.
- **Chromium through Playwright**, only for the Iris pDNS provider.

## Install

```bash
python3 -m venv ~/.venv/dt_analytics_detection
source ~/.venv/dt_analytics_detection/bin/activate
pip install -r requirements.txt
```

Playwright and Chromium are only needed for the **Iris pDNS** provider:

```bash
playwright install chromium
```

## Credentials

Credentials can come from three sources. Each credential is taken from the **first** source that has it:

| Credential | 1. Environment | 2. `credentials.toml` | 3. Files |
| --- | --- | --- | --- |
| DomainTools API (Domain History, Risk Evidence, Iris Investigate) | `$DT_API_USERNAME` + `$DT_API_KEY`, or `$DOMAINTOOLS_USERNAME` + `$DOMAINTOOLS_API_KEY` | `[domaintools]` `username`, `api_key` | `~/.dtapi` (line 1 username, line 2 key) |
| DNSDB Scout | `$DNSDB_API_KEY` | `[dnsdb]` `api_key` | `~/.dtdnsdb` |
| Certificate API | `$DT_CERT_API_KEY` | `[cert_api]` `api_key` | `~/.dtcertapi` |
| VPNDB | `$VPNDB_API_KEY` | `[vpndb]` `api_key` | `~/.dtvpndb` |

- The **Certificate API** uses the DomainTools API key unless one of its own options is set, so it usually needs
  no separate entry.
- **VPNDB** (VPN, residential proxy and Tor attribution of IPs, prefixes and ASNs, [vpndb.io](https://vpndb.io)):
  without a key the VPN / proxy / Tor check is skipped and the IP check use case cannot run. Create a key on
  vpndb.io under *Account → API keys* (it starts with `vpndb_`). For an on-premise installation, set its address in
  `$VPNDB_URL` or `[vpndb]` `url` (e.g. `http://localhost:3000/api/v1`); the hosted `https://vpndb.io/api/v1` is used
  otherwise.
- Use whichever source suits you; different services can come from different sources.
- Credential values are never displayed, logged or saved with runs.

### Environment

| Variable | Used for |
| --- | --- |
| `DT_API_USERNAME` | DomainTools API username (needs `DT_API_KEY` too) |
| `DT_API_KEY` | DomainTools API key (needs `DT_API_USERNAME` too); also the Certificate API key |
| `DOMAINTOOLS_USERNAME` | Alternative name for the DomainTools API username (needs `DOMAINTOOLS_API_KEY` too) |
| `DOMAINTOOLS_API_KEY` | Alternative name for the DomainTools API key (needs `DOMAINTOOLS_USERNAME` too); also the Certificate API key |
| `DNSDB_API_KEY` | DNSDB Scout |
| `DT_CERT_API_KEY` | Certificate API, only if it needs its own key |
| `VPNDB_API_KEY` | VPNDB |
| `VPNDB_URL` | VPNDB address of an on-premise installation (optional) |
| `DT_CREDENTIALS_FILE` | Another path for `credentials.toml` |

- `DOMAINTOOLS_USERNAME` / `DOMAINTOOLS_API_KEY` are the names used in the
  [DomainTools Python SDK docs](https://docs.domaintools.com/python-sdk/). The SDK itself reads no environment
  variables: the app reads either pair and passes the values to the SDK. When both pairs are set,
  `DT_API_USERNAME` / `DT_API_KEY` win.
- The DomainTools username and key always come from the same pair or source; variables from different pairs are
  never combined. If only one variable of a pair is set, that pair is ignored, and the credentials panel names the
  variable and the source used instead.
- Variables are read when the app starts, so restart it after changing them.
- They work well with a password manager, so no key is stored in plain text, for example (1Password):

  ```bash
  op run --env-file=.env -- streamlit run app.py
  ```

### credentials.toml

One file for every service, at `~/.config/dt-analytics/credentials.toml` (or the path in `$DT_CREDENTIALS_FILE`):

```toml
[domaintools]          # DomainTools API: Domain History, Risk Evidence, Iris Investigate
username = "API_USERNAME"
api_key  = "API_KEY"   # also used by the Certificate API

[dnsdb]
api_key = "DNSDB_API_KEY"

# [cert_api]           # optional: only if the Certificate API needs a different key
# api_key = "API_KEY"

[vpndb]                # VPN / residential proxy / Tor attribution
api_key = "vpndb_..."
# url = "http://localhost:3000/api/v1"   # only for an on-premise installation
```

```bash
mkdir -p ~/.config/dt-analytics
touch ~/.config/dt-analytics/credentials.toml
chmod 600 ~/.config/dt-analytics/credentials.toml
```

If the file cannot be parsed, the credentials panel shows the error and the files below are used instead.

### Files

One file per service in your home directory:

| File | Contents |
| --- | --- |
| `~/.dtapi` | Line 1 DomainTools API username, line 2 API key (also the Certificate API key) |
| `~/.dtdnsdb` | DNSDB API key on line 1 |
| `~/.dtcertapi` | Optional: Certificate API key, only if it differs from the DomainTools API key |
| `~/.dtvpndb` | VPNDB API key on line 1 |

`~/.dtapi` uses the same format as the DomainTools SDK's own credential file. Restrict the files to your user:

```bash
chmod 600 ~/.dtapi ~/.dtdnsdb ~/.dtcertapi ~/.dtvpndb
```

### API Credentials panel

The sidebar shows one line saying how many services have credentials (a warning when one is missing, with a link to
enter the keys). The full **API credentials** panel is under *Settings → API credentials*, always open there: a table
with one row per service and one column per
source (**Env**, **TOML** = `credentials.toml`, **Files**). Hover a cell or name for the full name.

| Mark | Meaning |
| --- | --- |
| 🟢 | The source this service uses for queries |
| 🟡 | The source has an option for this service, but a source checked earlier wins |
| ⚪ | The source has nothing for this service |

Below the table the panel lists:

- services with no credentials;
- key files that other users on the machine can read (with the `chmod 600` fix);
- a `credentials.toml` that cannot be read;
- a half-set username / key pair.

**All options** opens a table of every environment variable, `credentials.toml` entry and file. Each row shows its
status: *In use* and by which service, *Set, not used* and why (for example "DNSDB Scout uses $DNSDB_API_KEY"), or
*Not set*. It also shows what the option is for and the expected format. **Reload** re-reads `credentials.toml` and
the files without restarting the app; changed environment variables still need a restart.

### Entering keys in the app

**Enter API keys**, below the panel, takes the DomainTools API username and key, the DNSDB API key and, optionally, a
Certificate API key. It opens by itself when a service has no credentials. **Save to credentials.toml** writes them
to [`credentials.toml`](#credentialstoml), so the order above does not change: environment variables still win, and
the `~/.dt*` files are used only when the file has no key.

- The file is outside the project folder, so keys cannot be committed by mistake. It is written in one step (a
  temporary file, then a rename) with `0600` permissions, in a folder created with `0700`.
- Keys are never shown again; the fields are password fields and are cleared after saving. Keys are not kept in the
  browser or in `dt_settings.json`.
- Leave a field empty to keep the saved value. The DomainTools username and key are needed together the first time.
- Other tables and keys in the file are kept, but saving rewrites the file without its comments. A file that cannot
  be parsed is never overwritten: fix or remove it first.
- **Remove** next to a service deletes its table from the file.
- If an environment variable already supplies the service, the confirmation says the variable still wins.

### Iris pDNS session

The Iris pDNS provider signs in through a Playwright browser window. The first time, log in to Iris in that window
and close it once Iris has loaded. The session token (`dt_token.json`, saved with `0600` permissions) and the
browser profile (`dt_session_data/`) are stored in the project folder and are git-ignored.

## Run the app

```bash
streamlit run app.py
```

Streamlit prints a local URL (usually `http://localhost:8501`) and opens it in your browser. Continue with the
[Usage guide](USAGE.md).

## Development

```bash
pip install -r requirements-dev.txt
pytest
ruff check .
```

The project layout is described in the [README](../README.md#project-structure).
