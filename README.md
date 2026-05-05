# Juniper SkyATP → Apstra Sync

Automatically pulls infected hosts from **Juniper ATP Cloud** (SkyATP EU) and pushes them into the quarantine IP list of an **Apstra** blueprint property set.

## How it works

1. Fetches the infected hosts feed from SkyATP (`GET /v2/skyatp/infected_hosts`)
2. Compares with the previous run using a local state file
3. If the list has changed, logs into Apstra and resolves the blueprint and property set by name
4. Updates the `quarantine_ips` field in the property set (blueprint-scoped)
5. Commits the blueprint with the message `"Quarantined IP updated"`
6. Saves the current state for the next run

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
2026-05-05 09:54:19 [INFO] === SkyATP → Apstra Sync ===
2026-05-05 09:54:20 [INFO] SkyATP infected hosts: 1 total | 1 new | 0 cleared
2026-05-05 09:54:20 [WARNING]   [NEW]     10.0.100.101
2026-05-05 09:54:21 [INFO] Apstra login successful.
2026-05-05 09:54:21 [INFO] Blueprint resolved: 'Demo-DC' → 5c632439-...
2026-05-05 09:54:22 [INFO] Property set resolved: 'GBP-Classification' → e34d5f7c-...
2026-05-05 09:54:23 [INFO] Apstra property set updated with 1 quarantine IP(s): ['10.0.100.101']
2026-05-05 09:54:24 [INFO] Blueprint 'Demo-DC' committed (staging v99): 'Quarantined IP updated'
2026-05-05 09:54:24 [INFO] Done.
```

## Files

| File | Description |
|------|-------------|
| `skyatp_to_apstra_ok.py` | Main script |
| `config.py` | Credentials — **not versioned** (see `.gitignore`) |
| `.gitignore` | Excludes `config.py`, logs, state file and Python artifacts |

## State file

The script tracks the infected host list between runs using:  
`/var/tmp/skyatp_apstra_state.json`

Delete this file to force a full resync on the next run:
```bash
rm /var/tmp/skyatp_apstra_state.json
```

## Notes

- Only blueprint-scoped property sets are modified — the global property set is left untouched
- Blueprint and property set are resolved by **name** at runtime, no hardcoded IDs
- Apstra API calls use self-signed certificate (SSL verification disabled for Apstra only)
- A log file is written to `~/skyatp_to_apstra.log`
