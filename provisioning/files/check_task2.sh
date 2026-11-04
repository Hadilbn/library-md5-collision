#!/bin/bash
# Usage : check_task2 final1.bin final2.bin
. /usr/local/lib/md5lab/common.sh
[ $# -eq 2 ] || fail "Usage : check_task2 final1.bin final2.bin"
need_file "$1"; need_file "$2"
differ "$1" "$2"
same_md5 "$1" "$2"
s1=$(stat -c %s "$1"); s2=$(stat -c %s "$2")
[ "$s1" -eq "$s2" ] || fail "Les fichiers n'ont pas la meme taille."
[ "$s1" -gt 192 ] || fail "Ajoute un suffixe apres les 192 octets de la collision."
window_ok "$1" "$2"
last=$(cmp -l "$1" "$2" | tail -1 | awk '{print $1}')
[ $((s1 - last)) -ge 1 ] || fail "Aucun suffixe commun apres la zone qui differe."
echo "[OK] Meme hash apres ajout d'un suffixe commun de $((s1 - last)) octets."
echo "FLAG : FLAG{suffixe_commun_meme_hash_5be2}"
