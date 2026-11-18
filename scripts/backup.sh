#!/usr/bin/env bash
# Sauvegarde logique chiffrée (age), EN PLUS des sauvegardes automatiques du fournisseur.
# À stocker chez un AUTRE fournisseur / une autre région. À planifier (cron ou GitHub Actions schedule).
# Prérequis : pg_dump, age ; PG_DUMP_URL au format postgresql://user:pass@host/db?sslmode=require ; BACKUP_RECIPIENT = clé publique age
set -euo pipefail
DEST="${BACKUP_DEST:?}"
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
pg_dump --no-owner "${PG_DUMP_URL:?}" | age -r "${BACKUP_RECIPIENT:?}" -o "$DEST/users-$STAMP.sql.age"
find "$DEST" -name 'users-*.sql.age' -mtime +30 -delete   # rétention 30 jours
echo "Backup OK : users-$STAMP.sql.age"
