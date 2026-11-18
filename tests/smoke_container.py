"""Test fonctionnel du conteneur en marche : health, en-têtes, inscription, connexion, rejet d'un mauvais mot de passe.
Usage : python tests/smoke_container.py http://localhost:8080
"""
import re
import sys
import time

import requests

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8080"


def csrf(session, path):
    html = session.get(BASE + path, timeout=10).text
    return re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)


def check(cond, msg):
    print(("OK   " if cond else "FAIL ") + msg)
    if not cond:
        sys.exit(1)


for _ in range(15):
    try:
        if requests.get(BASE + "/health", timeout=3).status_code == 200:
            break
    except requests.RequestException:
        time.sleep(2)
else:
    check(False, "health endpoint joignable")

r = requests.get(BASE + "/health", timeout=5)
for h in ("Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options", "Strict-Transport-Security"):
    check(h in r.headers, f"en-tête {h} présent")

user, pwd = f"ci_{int(time.time())}", "Correct-Horse-Battery42!"
s = requests.Session()
r = s.post(BASE + "/register", data={"username": user, "password": pwd, "csrf_token": csrf(s, "/register")},
           allow_redirects=False, timeout=10)
check(r.status_code == 302, "inscription valide")
r = s.post(BASE + "/register", data={"username": "x" + user, "password": "faible", "csrf_token": csrf(s, "/register")},
           timeout=10)
check("16 caractères" in r.text, "mot de passe faible refusé")
r = s.post(BASE + "/login", data={"username": user, "password": "Mauvais-Mot-De-Passe42!", "csrf_token": csrf(s, "/login")},
           allow_redirects=False, timeout=10)
check(r.status_code == 200, "mauvais mot de passe refusé")
r = s.post(BASE + "/login", data={"username": user, "password": pwd, "csrf_token": csrf(s, "/login")},
           allow_redirects=False, timeout=10)
check(r.status_code == 302, "connexion valide")
check(user in s.get(BASE + "/dashboard", timeout=10).text, "tableau de bord affiche l'utilisateur")
r = requests.post(BASE + "/login", data={"username": user, "password": pwd}, timeout=10)
check(r.status_code == 400, "POST sans jeton CSRF rejeté")
print("Smoke test : tout est OK")
