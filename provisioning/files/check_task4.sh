#!/bin/bash
# Usage : check_task4 prog4_benin prog4_malicieux
. /usr/local/lib/md5lab/common.sh
[ $# -eq 2 ] || fail "Usage : check_task4 prog4_benin prog4_malicieux"
need_file "$1"; need_file "$2"
differ "$1" "$2"
same_md5 "$1" "$2"
window_ok "$1" "$2"
chmod +x "$1" "$2" 2>/dev/null
o1=$("$1" 2>&1) || fail "$1 ne s'execute pas correctement."
o2=$("$2" 2>&1) || fail "$2 ne s'execute pas correctement."
echo "$o1" | grep -q "BENIN" || fail "Le premier programme doit afficher la branche BENIN."
echo "$o2" | grep -q "MALICIEUX" || fail "Le second programme doit afficher la branche MALICIEUX."
echo "[OK] Meme hash MD5, comportements differents (benin / malicieux)."
echo "FLAG : FLAG{certificat_md5_contourne_3e08}"
