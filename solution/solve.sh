#!/bin/bash
# Reference solution for the instructor (run on the "seed" host as user "user").
# It solves all levels in a fresh sandbox and prints the flags returned by the authority.
# Usage: bash solve.sh [lab_dir]
set -euo pipefail
LAB=${1:-$HOME/lab}
W=$(mktemp -d); cd "$W"
echo "Working in $W"

# Find the offset of the first run of 200 'A' characters in a file (n-th run with $2)
find_A() { python3 - "$1" "${2:-1}" <<'PY'
import sys
d = open(sys.argv[1], 'rb').read(); n = int(sys.argv[2]); i = -1
for _ in range(n):
    i = d.find(b'A' * 200, i + 1 if i < 0 else i + 200)
print(i)
PY
}

echo "== Level 1: collision from prefix.txt"
md5collgen -p "$LAB/task1/prefix.txt" -o t1_1.bin t1_2.bin >/dev/null
md5sum t1_1.bin t1_2.bin
ca-submit task1 t1_1.bin t1_2.bin

echo "== Level 2: padding bytes"
L=$(stat -c %s "$LAB/task1/prefix.txt")
echo "prefix length = $L, padding = $(( (64 - L % 64) % 64 ))  <- this is the flag"

echo "== Level 3: 64-byte prefix"
md5collgen -p "$LAB/task1/prefix64.txt" -o q2_1.bin q2_2.bin >/dev/null
ca-submit q2 q2_1.bin q2_2.bin

echo "== Level 4: differing bytes"
OFF=$( (cmp -l q2_1.bin q2_2.bin || true) | awk '{printf "%s%d", (NR>1?",":""), $1-1-64}')
echo "relative positions: $OFF"
ca-submit q3 q2_1.bin q2_2.bin "$OFF"

echo "== Level 5: MD5 property"
cat t1_1.bin "$LAB/task2/suffix.txt" > t2_1.bin
cat t1_2.bin "$LAB/task2/suffix.txt" > t2_2.bin
md5sum t2_1.bin t2_2.bin
ca-submit task2 t2_1.bin t2_2.bin

echo "== Level 6: two executables"
gcc "$LAB/task3/xyz.c" -o xyz.out
off=$(find_A xyz.out); start=$(( (off + 63) / 64 * 64 ))
head -c $start xyz.out > pre3; tail -c +$((start + 128 + 1)) xyz.out > suf3
md5collgen -p pre3 -o c3_1 c3_2 >/dev/null
tail -c 128 c3_1 > P3; tail -c 128 c3_2 > Q3
cat pre3 P3 suf3 > a1.out; cat pre3 Q3 suf3 > a2.out; chmod +x a1.out a2.out
md5sum a1.out a2.out
ca-submit task3 a1.out a2.out

echo "== Levels 7-8: benign / malicious"
gcc "$LAB/task4/program.c" -o prog.out
x=$(find_A prog.out 1); y=$(find_A prog.out 2)
start=$(( (x + 63) / 64 * 64 )); r=$(( start - x )); ys=$(( y + r ))
head -c $start prog.out > pre4
md5collgen -p pre4 -o c4_1 c4_2 >/dev/null
tail -c 128 c4_1 > P4; tail -c 128 c4_2 > Q4
mid() { tail -c +$((start + 128 + 1)) prog.out | head -c $((ys - start - 128)); }
end() { tail -c +$((ys + 128 + 1)) prog.out; }
{ cat pre4 P4; mid; cat P4; end; } > benign.out
{ cat pre4 Q4; mid; cat P4; end; } > evil.out
chmod +x benign.out evil.out
md5sum benign.out evil.out; ./benign.out; ./evil.out
ca-submit certify benign.out
ca-submit deploy evil.out
