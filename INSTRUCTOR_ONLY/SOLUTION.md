# Instructor solution (DO NOT PUSH TO THE STUDENT REPOSITORY)

Commands were validated end-to-end against the verification server with a real `md5_fastcoll` build (same CLI as md5collgen).
Let `~/lab` be the working directory. Per level:

1. `md5collgen -p task1/prefix.txt -o out1.bin out2.bin; authority-upload t1 out1.bin out2.bin; authority-verify t1`
2. Q1 = size(out1) - 128 - size(prefix); Q2 = 192; Q3 = `cmp -l out1.bin out2.bin | awk '{print $1-1}'` (comma separated; typically 7 bytes).
   `authority-verify t1q q1=.. q2=192 q3=..`
3. `cat out1.bin suffix.txt > mt.bin; cat out2.bin suffix.txt > nt.bin; authority-upload t2 mt.bin nt.bin; authority-verify t2`
4. `gcc task3.c -o a.out; OFF=$(grep -obUaP 'A{200}' a.out | cut -d: -f1); authority-upload t3a a.out; authority-verify t3a offset=$OFF`
5. `S=$(( (OFF+63)/64*64 ))`; `head -c $S a.out > pre; md5collgen -p pre -o c1 c2; tail -c +$((S+129)) a.out > suf; cat c1 suf > v1.out; cat c2 suf > v2.out; chmod +x v*.out`; upload t3b.
6. Task 4: arrays at XOFF, YOFF (`grep -obUaP 'A{200}' t4`); `S=$(( (XOFF+63)/64*64 )); YW=$((YOFF+S-XOFF))`;
   `head -c $S t4 > pre; md5collgen -p pre -o d1 d2; tail -c 128 d1 > P; head -c $YW t4 | tail -c +$((S+129)) > mid; tail -c +$((YW+129)) t4 > end;`
   `cat d1 mid P end > benign.out; cat d2 mid P end > malicious.out`; upload t4.

Grading: platform score / 2 = mark on 20. Reading flags: instructors can see answers in the training instance (answers storage).
Unvalidated-by-test parts: Ansible provisioning and platform import (need your OpenStack/CyberRange; see README "Things to adapt").
