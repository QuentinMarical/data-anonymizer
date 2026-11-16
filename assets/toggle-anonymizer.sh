#!/usr/bin/env sh
# Active ou désactive le garde data-anonymizer.
# Usage : sh toggle-anonymizer.sh [dossier-du-projet]   (défaut : dossier courant)
set -e
HERE="$(cd "$(dirname "$0")/.." && pwd)"
PROJECT="${1:-$PWD}"
if command -v python3 >/dev/null 2>&1; then PY=python3; else PY=python; fi
"$PY" "$HERE/scripts/toggle.py" --project "$PROJECT" toggle
printf '\n'
read -r -p "Entrée pour fermer..." _ || true
