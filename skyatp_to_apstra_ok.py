#!/usr/bin/env python3
"""
skyatp_to_apstra.py
-------------------
Pulls infected hosts from Juniper SkyATP EU instance and automatically
pushes them into the quarantine_ips field of an Apstra property set.

Cron example (every minute):
    * * * * * /usr/bin/python3 /opt/scripts/skyatp_to_apstra.py

Requirements:
    pip3 install requests

Configuration:
    Set credentials via environment variables or edit the CONFIG section below.
"""

import os
import json
import logging
import sys
import warnings
from datetime import datetime, timezone
from pathlib import Path

# Suppress LibreSSL warning on macOS
warnings.filterwarnings("ignore", category=Warning, module="urllib3")

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# ---------------------------------------------------------------------------
# CONFIG — public names (visible on GitHub)
# ---------------------------------------------------------------------------
BLUEPRINT_NAME    = "Demo-DC"
PROPERTY_SET_NAME = "GBP-Classification"

# ---------------------------------------------------------------------------
# CONFIG — credentials (loaded from config.py or environment variables)
# ---------------------------------------------------------------------------
try:
    import config as _cfg
    SKYATP_TOKEN    = os.getenv("SKYATP_TOKEN",    _cfg.SKYATP_TOKEN)
    SKYATP_BASE_URL = os.getenv("SKYATP_BASE_URL", _cfg.SKYATP_BASE_URL)
    APSTRA_HOST     = os.getenv("APSTRA_HOST",     _cfg.APSTRA_HOST)
    APSTRA_USER     = os.getenv("APSTRA_USER",     _cfg.APSTRA_USER)
    APSTRA_PASS     = os.getenv("APSTRA_PASS",     _cfg.APSTRA_PASS)
except ImportError:
    # Fallback: environment variables only
    SKYATP_TOKEN    = os.getenv("SKYATP_TOKEN",    "YOUR_SKYATP_TOKEN_HERE")
    SKYATP_BASE_URL = os.getenv("SKYATP_BASE_URL", "https://api-eu.sky.junipersecurity.net")
    APSTRA_HOST     = os.getenv("APSTRA_HOST",     "YOUR_APSTRA_HOST_HERE")
    APSTRA_USER     = os.getenv("APSTRA_USER",     "admin")
    APSTRA_PASS     = os.getenv("APSTRA_PASS",     "YOUR_APSTRA_PASSWORD_HERE")

SKYATP_ENDPOINT = "/v2/skyatp/infected_hosts"
APSTRA_BASE_URL = f"https://{APSTRA_HOST}"

# Log file — set to None to log to stdout only
LOG_FILE        = os.path.expanduser("~/skyatp_to_apstra.log")

# State file to track changes between runs
STATE_FILE      = Path("/var/tmp/skyatp_apstra_state.json")

# Request timeout in seconds
TIMEOUT         = 30

# ---------------------------------------------------------------------------
# LOGGING
# ---------------------------------------------------------------------------
handlers = [logging.StreamHandler(sys.stdout)]
if LOG_FILE:
    handlers.append(logging.FileHandler(LOG_FILE))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=handlers,
)
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# STATE
# ---------------------------------------------------------------------------

def load_known_ips() -> set:
    if STATE_FILE.exists():
        try:
            data = json.loads(STATE_FILE.read_text())
            return set(data.get("ips", []))
        except (json.JSONDecodeError, OSError) as exc:
            log.warning("Could not read state file (%s) — starting fresh.", exc)
    return set()


def save_known_ips(ips: set) -> None:
    try:
        STATE_FILE.write_text(json.dumps({
            "ips": list(ips),
            "updated": datetime.now(timezone.utc).isoformat()
        }))
    except OSError as exc:
        log.error("Could not write state file: %s", exc)

# ---------------------------------------------------------------------------
# SKYATP
# ---------------------------------------------------------------------------

def fetch_infected_ips() -> list:
    """Fetch infected host IPs from SkyATP EU. Returns a list of IP strings."""
    url = f"{SKYATP_BASE_URL}{SKYATP_ENDPOINT}"
    headers = {
        "Authorization": f"Bearer {SKYATP_TOKEN}",
        "Accept": "application/json",
    }
    response = requests.get(url, headers=headers, timeout=TIMEOUT, verify=True)
    response.raise_for_status()

    payload = response.json()
    # Response: {"data": {"count": N, "ip": [{"1.2.3.4": 6}, ...]}, ...}
    ip_list = payload.get("data", {}).get("ip", [])

    ips = []
    for entry in ip_list:
        if isinstance(entry, dict):
            for ip in entry.keys():
                ips.append(ip)
        else:
            ips.append(str(entry))

    return ips

# ---------------------------------------------------------------------------
# APSTRA
# ---------------------------------------------------------------------------

def apstra_login() -> str:
    """Authenticate to Apstra and return a session token."""
    url = f"{APSTRA_BASE_URL}/api/user/login"
    payload = {"username": APSTRA_USER, "password": APSTRA_PASS}
    response = requests.post(url, json=payload, timeout=TIMEOUT, verify=False)
    response.raise_for_status()
    token = response.json().get("token")
    if not token:
        raise ValueError("No token returned from Apstra login")
    return token


def resolve_blueprint_id(token: str) -> tuple:
    """Resolve the blueprint name to its (id, label)."""
    url = f"{APSTRA_BASE_URL}/api/blueprints"
    response = requests.get(url, headers={"AuthToken": token}, timeout=TIMEOUT, verify=False)
    response.raise_for_status()
    for bp in response.json().get("items", []):
        if bp.get("label") == BLUEPRINT_NAME:
            return bp["id"], bp["label"]
    raise ValueError(f"Blueprint '{BLUEPRINT_NAME}' not found on {APSTRA_HOST}")


def resolve_property_set_id(token: str, bp_id: str) -> tuple:
    """Resolve the property set name to its (id, label) within the blueprint."""
    url = f"{APSTRA_BASE_URL}/api/blueprints/{bp_id}/property-sets"
    response = requests.get(url, headers={"AuthToken": token}, timeout=TIMEOUT, verify=False)
    response.raise_for_status()
    items = response.json().get("items", [])
    for ps in items:
        if ps.get("label") == PROPERTY_SET_NAME:
            return ps["id"], ps["label"]
    raise ValueError(f"Property set '{PROPERTY_SET_NAME}' not found in blueprint '{BLUEPRINT_NAME}'")


def get_property_set(token: str, bp_id: str, ps_id: str) -> dict:
    """Fetch the current property set values from the blueprint (blueprint-scoped)."""
    url = f"{APSTRA_BASE_URL}/api/blueprints/{bp_id}/property-sets/{ps_id}"
    response = requests.get(url, headers={"AuthToken": token}, timeout=TIMEOUT, verify=False)
    response.raise_for_status()
    return response.json()


def build_values_yaml(current_ps: dict, new_ips: list) -> str:
    """Rebuild values_yaml preserving all fields, replacing quarantine_ips."""
    import yaml
    values = current_ps["values"].copy()
    values["quarantine_ips"] = new_ips
    return yaml.dump(values, default_flow_style=False, allow_unicode=True)


def update_quarantine_ips(token: str, current_ps: dict, new_ips: list, bp_id: str, ps_id: str) -> None:
    """Push updated quarantine_ips to Apstra blueprint property set (blueprint-scoped)."""
    url = f"{APSTRA_BASE_URL}/api/blueprints/{bp_id}/property-sets/{ps_id}"

    values_yaml = build_values_yaml(current_ps, new_ips)
    log.debug("Sending values_yaml:\n%s", values_yaml)

    payload = {
        "id": ps_id,
        "label": current_ps["label"],
        "values_yaml": values_yaml
    }

    response = requests.put(
        url,
        headers={"AuthToken": token, "Content-Type": "application/json"},
        json=payload,
        timeout=TIMEOUT,
        verify=False
    )
    response.raise_for_status()


def commit_blueprint(token: str, bp_id: str, staging_version: int, description: str) -> None:
    """Commit staged blueprint changes with a description."""
    url = f"{APSTRA_BASE_URL}/api/blueprints/{bp_id}/deploy"
    payload = {"version": staging_version, "description": description}
    response = requests.put(
        url,
        headers={"AuthToken": token, "Content-Type": "application/json"},
        json=payload,
        timeout=TIMEOUT,
        verify=False
    )
    response.raise_for_status()


def get_staging_version(token: str, bp_id: str) -> int:
    """Fetch the current staging version of the blueprint."""
    url = f"{APSTRA_BASE_URL}/api/blueprints/{bp_id}/diff-status"
    response = requests.get(url, headers={"AuthToken": token}, timeout=TIMEOUT, verify=False)
    response.raise_for_status()
    return response.json()["staging_version"]

# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------

def main() -> None:
    log.info("=== SkyATP → Apstra Sync ===")

    # Validate config
    if SKYATP_TOKEN == "YOUR_SKYATP_TOKEN_HERE":
        log.error("No SkyATP token configured. Set SKYATP_TOKEN env variable.")
        sys.exit(1)
    if APSTRA_PASS == "YOUR_APSTRA_PASSWORD_HERE":
        log.error("No Apstra password configured. Set APSTRA_PASS env variable.")
        sys.exit(1)

    # Load previous state
    known_ips = load_known_ips()

    # 1. Fetch infected IPs from SkyATP
    try:
        infected_ips = fetch_infected_ips()
    except requests.exceptions.HTTPError as exc:
        log.error("SkyATP HTTP error: %s", exc)
        sys.exit(1)
    except requests.exceptions.ConnectionError as exc:
        log.error("SkyATP connection error: %s", exc)
        sys.exit(1)

    current_ips = set(infected_ips)
    new_ips     = current_ips - known_ips
    cleared_ips = known_ips - current_ips

    log.info("SkyATP infected hosts: %d total | %d new | %d cleared",
             len(current_ips), len(new_ips), len(cleared_ips))

    for ip in sorted(new_ips):
        log.warning("  [NEW]     %s", ip)
    for ip in sorted(cleared_ips):
        log.info("  [CLEARED] %s", ip)

    # 2. Only update Apstra if the list has changed
    if not new_ips and not cleared_ips:
        log.info("No changes — skipping Apstra update.")
        return

    # 3. Login to Apstra
    try:
        token = apstra_login()
        log.info("Apstra login successful.")
    except Exception as exc:
        log.error("Apstra login failed: %s", exc)
        sys.exit(1)

    # 4. Resolve blueprint by name
    try:
        bp_id, bp_label = resolve_blueprint_id(token)
        log.info("Blueprint resolved: '%s' → %s", bp_label, bp_id)
    except ValueError as exc:
        log.error("%s", exc)
        sys.exit(1)

    # 5. Resolve property set by name
    try:
        ps_id, ps_label = resolve_property_set_id(token, bp_id)
        log.info("Property set resolved: '%s' → %s", ps_label, ps_id)
    except ValueError as exc:
        log.error("%s", exc)
        sys.exit(1)

    # 6. Get current property set (to preserve other values)
    try:
        current_ps = get_property_set(token, bp_id, ps_id)
    except Exception as exc:
        log.error("Failed to fetch Apstra property set: %s", exc)
        sys.exit(1)

    # 7. Push updated quarantine_ips
    try:
        update_quarantine_ips(token, current_ps, sorted(list(current_ips)), bp_id, ps_id)
        log.info("Apstra property set updated with %d quarantine IP(s): %s",
                 len(current_ips), sorted(list(current_ips)))
    except Exception as exc:
        log.error("Failed to update Apstra property set: %s", exc)
        sys.exit(1)

    # 8. Commit the blueprint
    try:
        staging_version = get_staging_version(token, bp_id)
        commit_blueprint(token, bp_id, staging_version, "Quarantined IP updated")
        log.info("Blueprint '%s' committed (staging v%d): 'Quarantined IP updated'",
                 BLUEPRINT_NAME, staging_version)
    except Exception as exc:
        log.error("Failed to commit blueprint: %s", exc)
        sys.exit(1)

    # 9. Save state
    save_known_ips(current_ips)
    log.info("Done.")


if __name__ == "__main__":
    main()