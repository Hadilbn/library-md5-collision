#!/bin/bash
# Usage : check_task1 out1.bin out2.bin
. /usr/local/lib/md5lab/common.sh
[ $# -eq 2 ] || fail "Usage : check_task1 out1.bin out2.bin"
need_file "$1"; need_file "$2"
PREFIX=/home/ubuntu/tp_md5/prefix.txt
differ "$1" "$2"
same_md5 "$1" "$2"
plen=$(stat -c %s "$PREFIX")
expected=$(( (plen + 63) / 64 * 64 + 128 ))
[ "$(stat -c %s "$1")" -eq "$expected" ] || fail "Taille inattendue : les fichiers doivent venir de prefix.txt."
cmp -s -n "$plen" "$PREFIX" "$1" || fail "Les fichiers ne commencent pas par prefix.txt."
cmp -s -n "$plen" "$PREFIX" "$2" || fail "Les fichiers ne commencent pas par prefix.txt."
echo "[OK] Collision valide. Octets differents : $(cmp -l "$1" "$2" | wc -l) (note ce nombre pour ton rapport)."
echo "FLAG : FLAG{c0ll1de_m4me_pr3fixe_a7f3}"
