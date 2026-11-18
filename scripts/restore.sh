#!/usr/bin/env bash
# Usage : restore.sh users-XXXX.sql.age /chemin/identite-age.txt postgresql://user:pass@host/db_de_test
# Toujours tester sur une base vierge, puis vérifier le nombre de comptes.
set -euo pipefail
age -d -i "$2" "$1" | psql "$3" -v ON_ERROR_STOP=1
psql "$3" -c "SELECT count(*) AS comptes FROM users;"
