# Juniper SkyATP → Apstra Sync

Automatically pulls infected hosts from **Juniper ATP Cloud** (SkyATP EU) and pushes them into the quarantine IP list of an **Apstra** blueprint property set.

## How it works

1. Fetches the infected hosts feed from SkyATP (`GET /v2/skyatp/infected_hosts`)
2. Logs into Apstra and resolves the blueprint and property set by name
3. Reads the current `quarantine_ips` from the Apstra property set (**SSOT**)
4. Compares both lists — any difference triggers an update
5. Updates the `quarantine_ips` field in the property set (blueprint-scoped)
6. Commits the blueprint with the message `"Quarantined IP updated"`

> The Apstra property set is the **Single Source of Truth**. Manual changes to `quarantine_ips` are always detected and corrected on the next run.

## Requirements

```bash
pip install requests pyyaml
```

## Configuration

Credentials are stored in a local `config.py` file (excluded from git via `.gitignore`).  
Copy the template below and fill in your values:

```python
# config.py

# Juniper SkyATP
SKYATP_TOKEN    = "YOUR_BEARER_TOKEN"
SKYATP_BASE_URL = "https://api-eu.sky.junipersecurity.net"

# Apstra VM
APSTRA_HOST = "YOUR_APSTRA_IP"
APSTRA_USER = "admin"
APSTRA_PASS = "YOUR_PASSWORD"
```

Blueprint and property set names are set directly in the script:

```python
BLUEPRINT_NAME    = "Demo-DC"
PROPERTY_SET_NAME = "GBP-Classification"
```

### Generate a SkyATP Bearer Token

In the Juniper ATP Cloud web UI:  
**Administration > API Tokens > Generate Token**

## Usage

```bash
# Run once
python3 skyatp_to_apstra_ok.py

# Run every minute via cron
* * * * * /usr/bin/python3 /opt/scripts/skyatp_to_apstra_ok.py
```

## Sample output

```
2026-05-05 10:12:38 [INFO] === SkyATP → Apstra Sync ===
2026-05-05 10:12:39 [INFO] SkyATP infected hosts: 1 IP(s) — ['10.0.100.101']
2026-05-05 10:12:40 [INFO] Apstra login successful.
2026-05-05 10:12:40 [INFO] Blueprint resolved: 'Demo-DC' → 5c632439-...
2026-05-05 10:12:41 [INFO] Property set resolved: 'GBP-Classification' → e34d5f7c-...
2026-05-05 10:12:41 [INFO] Apstra quarantine_ips: 1 IP(s) — ['10.0.200.202']
2026-05-05 10:12:41 [WARNING]   [NEW]     10.0.100.101
2026-05-05 10:12:41 [INFO]   [CLEARED] 10.0.200.202
2026-05-05 10:12:42 [INFO] Apstra property set updated with 1 quarantine IP(s): ['10.0.100.101']
2026-05-05 10:12:43 [INFO] Blueprint 'Demo-DC' committed (staging v101): 'Quarantined IP updated'
2026-05-05 10:12:43 [INFO] Done.
```

## Files

| File | Description |
|------|-------------|
| `skyatp_to_apstra_ok.py` | Main script |
| `config.py` | Credentials — **not versioned** (see `.gitignore`) |
| `.gitignore` | Excludes `config.py`, logs and Python artifacts |

## Notes

- The Apstra property set is the **SSOT** — manual changes are always reconciled on the next run
- Only the blueprint-scoped property set is modified — the global property set is left untouched
- Blueprint and property set are resolved by **name** at runtime, no hardcoded IDs
- Apstra API calls skip SSL verification (self-signed certificate)
- A log file is written to `~/skyatp_to_apstra.log`
