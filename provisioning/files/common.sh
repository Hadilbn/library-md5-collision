#!/bin/bash
# Fonctions communes aux scripts de validation
fail() { echo "[ECHEC] $1"; exit 1; }
need_file() { [ -f "$1" ] || fail "Fichier introuvable : $1"; }
same_md5() { [ "$(md5sum < "$1")" = "$(md5sum < "$2")" ] || fail "Les hash MD5 sont differents."; }
differ() { cmp -s "$1" "$2" && fail "Les deux fichiers sont identiques : une collision doit produire deux fichiers differents."; true; }
# Les octets differents doivent tenir dans une fenetre de 128 octets
window_ok() {
  local first last
  first=$(cmp -l "$1" "$2" | head -1 | awk '{print $1}')
  last=$(cmp -l "$1" "$2" | tail -1 | awk '{print $1}')
  [ -n "$first" ] || fail "Aucune difference detectee."
  [ $((last - first)) -lt 128 ] || fail "Les differences depassent un bloc de 128 octets."
}
