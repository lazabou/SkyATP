import requests
import json
import argparse
import sys


# Hostnames selon la région (voir Tableau 3 de la doc Juniper)
API_HOSTS = {
    "us":   "https://api.sky.junipersecurity.net",
    "eu":   "https://api.sky.junipersecurity.net",
    "apac": "https://api.sky.junipersecurity.net",
}


def get_infected_hosts(token: str, api_host: str, verify_ssl: bool = True) -> dict:
    """Récupère le feed des hosts infectés depuis Juniper SkyATP."""
    url = f"{api_host}/v1/skyatp/ih/feed"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    try:
        response = requests.get(url, headers=headers, verify=verify_ssl)
        response.raise_for_status()
        return response.json()

    except requests.exceptions.SSLError as e:
        print(f"[ERROR] Erreur SSL : {e}", file=sys.stderr)
        print("Conseil : utilise --no-ssl-verify si tu es en environnement de test", file=sys.stderr)
        sys.exit(1)
    except requests.exceptions.HTTPError as e:
        print(f"[ERROR] HTTP {response.status_code} : {e}", file=sys.stderr)
        sys.exit(1)
    except requests.exceptions.ConnectionError as e:
        print(f"[ERROR] Impossible de joindre l'API : {e}", file=sys.stderr)
        sys.exit(1)


def ping(token: str, api_host: str, verify_ssl: bool = True):
    """Vérifie que l'API est joignable (doit répondre 'I am a potato.')"""
    url = f"{api_host}/v1/skyatp/ping"
    headers = {"Authorization": f"Bearer {token}"}

    try:
        response = requests.get(url, headers=headers, verify=verify_ssl)
        print(f"[PING] Status: {response.status_code} | Réponse: {response.text.strip()}")
    except requests.exceptions.ConnectionError as e:
        print(f"[ERROR] Impossible de joindre l'API : {e}", file=sys.stderr)
        sys.exit(1)


def display_results(data: dict):
    """Affiche les hosts infectés de façon lisible."""
    hosts = data.get("feed", data if isinstance(data, list) else [])

    if not hosts:
        print("Aucun host infecté trouvé.")
        return

    print(f"\n{'IP Address':<20} {'Threat Level':<15}")
    print("-" * 35)

    for entry in hosts:
        ip = entry.get("ip", "N/A")
        threat = entry.get("threat_level", entry.get("threatLevel", "N/A"))
        print(f"{ip:<20} {threat:<15}")

    print(f"\nTotal : {len(hosts)} host(s) infecté(s)")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Juniper SkyATP - Infected Hosts Feed")
    parser.add_argument(
        "-t", "--token",
        required=True,
        help="Bearer token ou chemin vers un fichier contenant le token",
    )
    parser.add_argument(
        "-u", "--url",
        default="https://api.sky.junipersecurity.net",
        help="URL de base de l'API",
    )
    parser.add_argument(
        "-k", "--no-ssl-verify",
        action="store_true",
        help="Désactive la vérification SSL (INSECURE)",
    )
    parser.add_argument(
        "-p", "--ping",
        action="store_true",
        help="Ping l'API uniquement",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Affiche la sortie brute en JSON",
    )
    args = parser.parse_args()

    # Lecture du token (string direct ou fichier)
    token = args.token
    try:
        with open(token, "r") as f:
            token = f.read().strip()
    except (FileNotFoundError, OSError):
        pass

    verify_ssl = not args.no_ssl_verify

    if args.ping:
        ping(token, args.url, verify_ssl)
        sys.exit(0)

    data = get_infected_hosts(token, args.url, verify_ssl)

    if args.json:
        print(json.dumps(data, indent=2))
    else:
        display_results(data)
