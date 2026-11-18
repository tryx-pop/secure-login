#!/usr/bin/env bash
# Démarre l'image construite en CI avec un durcissement strict et vérifie qu'elle fonctionne.
set -euo pipefail

KEY=$(python3 -c "import base64,os;print(base64.urlsafe_b64encode(os.urandom(32)).decode())")

docker run -d --name app -p 8080:8080 \
  --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges:true \
  -e SECRET_KEY="ci-$RANDOM$RANDOM" \
  -e COOKIE_SECURE=0 \
  -e DATA_ENCRYPTION_KEY="$KEY" \
  -e USERNAME_INDEX_KEY=ci \
  -e DATABASE_URL="sqlite:////tmp/ci.db" \
  secure-login:ci

for _ in $(seq 15); do
  curl -fs localhost:8080/health && break
  sleep 2
done
curl -fs localhost:8080/health || { docker logs app; exit 1; }

if [ "$(docker exec app id -u)" = "0" ]; then
  echo "Le conteneur tourne en root"
  exit 1
fi
echo "Conteneur OK : sain et non-root"
