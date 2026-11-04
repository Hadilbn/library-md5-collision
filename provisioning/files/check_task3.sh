#!/bin/bash
# Usage : check_task3 prog1 prog2
. /usr/local/lib/md5lab/common.sh
[ $# -eq 2 ] || fail "Usage : check_task3 prog1 prog2"
need_file "$1"; need_file "$2"
differ "$1" "$2"
same_md5 "$1" "$2"
[ "$(stat -c %s "$1")" -eq "$(stat -c %s "$2")" ] || fail "Tailles differentes."
window_ok "$1" "$2"
chmod +x "$1" "$2" 2>/dev/null
o1=$("$1" 2>&1) || fail "$1 ne s'execute pas correctement."
o2=$("$2" 2>&1) || fail "$2 ne s'execute pas correctement."
[ "$o1" != "$o2" ] || fail "Les deux programmes affichent la meme sortie."
echo "[OK] Meme hash MD5, sorties differentes."
echo "FLAG : FLAG{deux_executables_un_hash_c91d}"
