# Juniper SkyATP — Infected Hosts Feed

Script Python pour récupérer le feed des hôtes infectés depuis l'API **Juniper ATP Cloud** (SkyATP).

## Fonctionnalités

- Authentification via **Bearer Token**
- Appel à l'endpoint `GET /v1/skyatp/ih/feed`
- Affichage tabulaire des adresses IP et de leur niveau de menace
- Sortie JSON brute disponible
- Ping de l'API pour vérifier la connectivité
- Lecture du token depuis un fichier ou directement en argument

## Prérequis

```bash
pip install requests
```

## Générer un Bearer Token

Dans l'UI web de Juniper ATP Cloud :  
**Administration > API Tokens > Generate Token**

## Usage

```bash
# Ping de l'API (vérifie la connectivité)
python atp_infected_hosts.py -t MON_TOKEN --ping

# Récupérer les hosts infectés (affichage tabulaire)
python atp_infected_hosts.py -t MON_TOKEN

# Token stocké dans un fichier
python atp_infected_hosts.py -t /path/to/token.txt

# Sortie JSON brute
python atp_infected_hosts.py -t MON_TOKEN --json

# Désactiver la vérification SSL (environnement de test uniquement)
python atp_infected_hosts.py -t MON_TOKEN -k
```

## Options

| Option | Description |
|--------|-------------|
| `-t`, `--token` | Bearer token ou chemin vers un fichier contenant le token |
| `-u`, `--url` | URL de base de l'API (défaut : `https://api.sky.junipersecurity.net`) |
| `-k`, `--no-ssl-verify` | Désactive la vérification SSL (INSECURE) |
| `-p`, `--ping` | Ping l'API uniquement |
| `--json` | Affiche la réponse brute en JSON |

## Exemple de sortie

```
IP Address           Threat Level
-----------------------------------
192.168.1.100        10
10.0.0.55            10

Total : 2 host(s) infecté(s)
```

## Régions API

Consulte le **Tableau 3** de la documentation Juniper pour l'hostname correspondant à ta région.  
L'URL par défaut est `https://api.sky.junipersecurity.net`.

## Notes

- Le threat level retourné par le feed est `10` pour tous les hosts dans l'infected hosts feed
- L'endpoint de ping doit répondre `I am a potato.` si l'API est joignable
