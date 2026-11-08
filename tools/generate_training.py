#!/usr/bin/env python3
"""Generates training.json.
Scores are written in HALF-POINTS because CyberRangeCZ score/penalty fields are integers:
  40 platform points  ==  20/20  (divide by 2),  penalties 1..4 == -0.5 .. -2.
Run with --decimal to write real values (20 points total, penalties 0.5..2) instead,
if your platform version accepts decimals.
"""
import json, sys

DECIMAL = "--decimal" in sys.argv
def v(h):                      # half-points -> platform value
    if not DECIMAL:
        return h
    x = h / 2
    return int(x) if x == int(x) else x

def hints(lst):
    return [{"title": t, "content": c, "hint_penalty": v(p), "order": i} for i, (t, c, p) in enumerate(lst)]

def tl(order, title, dur, var, content, solution, score, hint_list):
    return {
        "title": title, "level_type": "TRAINING_LEVEL", "order": order,
        "estimated_duration": dur, "minimal_possible_solve_time": None,
        "answer": None, "answer_variable_name": var,
        "content": content, "solution": solution, "solution_penalized": True,
        "hints": hints(hint_list), "incorrect_answer_limit": 10, "attachments": [],
        "max_score": v(score), "variant_answers": True,
        "reference_solution": [], "mitre_techniques": [], "expected_commands": [],
        "commands_required": False,
    }

levels = []

levels.append({
 "title": "Introduction", "level_type": "INFO_LEVEL", "order": 0, "estimated_duration": 0,
 "minimal_possible_solve_time": None,
 "content": """# General information: please read carefully

* This exercise is the practical work (TP) **MD5 Collision Attack Lab** (based on the SEED Labs of Wenliang Du). It is worth **20 points**.
* Every level gives you **a flag that is different for every student**. A flag is printed by the *Certification Authority* only when **your own files** pass its verification. Flags of other students do not work in your sandbox.
* Hints are optional. Every hint costs between **0.5 and 2 points** (shown in the platform as 1 to 4 half-points: *40 platform points = 20/20*). Showing the solution of a level gives you 0 for that level.
* The levels must be solved **in order**: later levels reuse the files you created before.
* This exercise is for educational purposes only. The story is fictitious.

# Storyline

You are a security researcher. **SafeSoft Certification Authority** certifies programs: it tests a program, and if it is good, it issues a certificate that contains the **MD5 hash** of the program. Users trust any program whose hash matches a certificate.

Your mission: show that this trust is broken. Step by step you will generate MD5 collisions, understand why they can be extended with a common suffix, embed them in executables, and finally obtain a certificate for a *benign* program that is also valid for a *malicious* one.

# Your lab

* You work on the **`seed`** machine (SEED Ubuntu VM). Your working directory is `~/lab` (read `~/lab/README.txt`).
* Tools: `md5collgen`, `md5sum`, `diff`, `cmp`, `head`, `tail`, `cat`, `gcc`, `bless` (hex editor), `xxd`.
* The Certification Authority is the host **`authority`**. Use two helper commands:
  * `authority-upload <task> <file>...` sends your files,
  * `authority-verify <task> [key=value ...]` verifies them. **On success it prints your personal FLAG**, which you then submit in the platform.
* Keep screenshots and the commands you used: the lab report (screenshots + explanations) is still required.""",
})

levels.append({
 "title": "Get Access", "level_type": "ACCESS_LEVEL", "order": 1, "estimated_duration": 0,
 "minimal_possible_solve_time": None, "passkey": "start",
 "cloud_content": """Your first task is to access the sandbox, where you will complete all following tasks. After you have successfully connected, submit the answer **`start`**.

### Sandbox access
1. In the topology overview on the right, right-click on **`seed`** and then click on **`Open GUI`**; a new pop-up window will appear.
2. Login with username **`seed`** and password **`dees`**.
3. Open a terminal and run `cat ~/lab/README.txt`.

Alternatively, you can use SSH to connect to the machine. See the [documentation](https://docs.platform.cyberrange.cz/user-guide-advanced/sandboxes/sandbox-access/#user-access) for more details.""",
 "local_content": "This sandbox has not been tested for use with local sandbox.",
})

levels.append(tl(2, "Task 1.1 - Generate two files with the same MD5 hash", 10, "flag_t1",
"""The authority gives you a **personal prefix file**: `~/lab/task1/prefix.txt` (its content and length are different for every student).

Use `md5collgen` to generate two different files `out1.bin` and `out2.bin` that **start with your prefix** and have the **same MD5 hash**. Check them with `diff`, `md5sum` and look at them with `bless`/`xxd`.

Then send them to the authority and ask for verification:

```
authority-upload t1 out1.bin out2.bin
authority-verify t1
```

On success the authority prints your **FLAG**. The flag of this level is that value.""",
"```\ncd ~/lab/task1\nmd5collgen -p prefix.txt -o out1.bin out2.bin\ndiff out1.bin out2.bin ; md5sum out1.bin out2.bin\nauthority-upload t1 out1.bin out2.bin\nauthority-verify t1      # prints the FLAG\n```", 6,
[("Which tool and which syntax?", "`md5collgen -p <prefix file> -o <output 1> <output 2>`. The output names must be exactly `out1.bin` and `out2.bin`.", 1),
 ("How do I send my files?", "`authority-upload t1 out1.bin out2.bin` and then `authority-verify t1`. Run them from the directory containing the files.", 2),
 ("Verification fails", "The authority checks that BOTH files start with YOUR `~/lab/task1/prefix.txt` (do not edit it), have the same size, are different and have the same MD5. Re-generate the files from the original prefix.", 3)]))

levels.append(tl(3, "Task 1.2 - Questions Q1, Q2, Q3", 10, "flag_t1q",
"""Analyse the files of the previous level with a hex editor (`bless`) and answer the three questions of the lab. The answers are checked by the authority (they depend on **your** files):

* **Q1** - Your `prefix.txt` is not a multiple of 64 bytes. **How many padding bytes** did `md5collgen` add after the prefix, before the 128 bytes of collision data?
* **Q2** - Create a prefix file of **exactly 64 bytes** and run `md5collgen` again. **What is the size (bytes) of each output file?**
* **Q3** - Which bytes are different between `out1.bin` and `out2.bin`? Give **all differing byte offsets**, 0-based from the beginning of the file, in increasing order, separated by commas.

```
authority-verify t1q q1=<n> q2=<n> q3=<o1,o2,...>
```

The flag of this level is the FLAG printed on success.""",
"```\nwc -c prefix.txt out1.bin             # Q1: padding = size(out1) - 128 - size(prefix)\nhead -c 64 /dev/zero | tr '\\0' A > p64.txt\nmd5collgen -p p64.txt -o q1.bin q2.bin ; wc -c q1.bin   # Q2 = 192\ncmp -l out1.bin out2.bin                # Q3: subtract 1 from each byte number\nauthority-verify t1q q1=... q2=192 q3=...\n```", 6,
[("Q1 - how to count the padding?", "Padding = (size of `out1.bin` - 128) - size of `prefix.txt`. Use `wc -c file` to get sizes.", 1),
 ("Q2 - how to build a 64-byte prefix?", "For example: `head -c 64 /dev/zero | tr '\\0' A > p64.txt`, then run `md5collgen` on it and check the size of the outputs with `wc -c`.", 2),
 ("Q3 - how to list differing bytes?", "`cmp -l out1.bin out2.bin` lists differing bytes with 1-BASED positions (decimal). Subtract 1 from each to get 0-based offsets.", 3)]))

levels.append(tl(4, "Task 2 - MD5 property: same suffix, same hash", 10, "flag_t2",
"""MD5 processes the input block by block (64 bytes), each step using the previous *Intermediate Hash Value*. Consequently, if `MD5(M) = MD5(N)`, then `MD5(M || T) = MD5(N || T)` for any suffix `T`.

Design the experiment to prove it, using the files `out1.bin` (M) and `out2.bin` (N) of Task 1 and your personal suffix `~/lab/task2/suffix.txt` (T):

* `mt.bin` = `out1.bin || T`
* `nt.bin` = `out2.bin || T`

Compare `md5sum` of the two files, then:

```
authority-upload t2 mt.bin nt.bin
authority-verify t2
```

The flag of this level is the FLAG printed on success.""",
"```\ncd ~/lab\ncat task1/out1.bin task2/suffix.txt > mt.bin\ncat task1/out2.bin task2/suffix.txt > nt.bin\nmd5sum mt.bin nt.bin\nauthority-upload t2 mt.bin nt.bin\nauthority-verify t2\n```", 6,
[("How to concatenate files?", "`cat file1 file2 > file3` writes the content of file1 followed by file2 into file3.", 1),
 ("Which files and names?", "`cat out1.bin suffix.txt > mt.bin` and `cat out2.bin suffix.txt > nt.bin`. The same T must be used for both, and T must be your own `suffix.txt`.", 2),
 ("Verification fails", "The files `out1.bin`/`out2.bin` of Task 1 must still be the ones accepted by the authority (t1 uploaded). Check `diff mt.bin nt.bin` (must differ) and `md5sum` (must be equal).", 3)]))

levels.append(tl(5, "Task 3.1 - Locate the array inside an executable", 15, "flag_t3a",
"""You receive a C program `~/lab/task3/task3.c` (personalised for you). Its array `xyz` contains 200 bytes `0x41` (the letter `A`) and the program prints the array.

1. Compile it: `gcc task3.c -o a.out` and run it.
2. Find in the binary the **position (0-based offset) where the 200 `A` begin**. Use `bless` (offsets are shown in hexadecimal) or a command line tool.
3. Upload the binary and give the offset to the authority:

```
authority-upload t3a a.out
authority-verify t3a offset=<decimal offset or 0xHEX>
```

The flag of this level is the FLAG printed on success.""",
"```\ncd ~/lab/task3\ngcc task3.c -o a.out && ./a.out\ngrep -obUaP 'A{200}' a.out | cut -c1-12     # offset of the array\nauthority-upload t3a a.out\nauthority-verify t3a offset=<offset>\n```", 4,
[("How to find the array?", "Open `a.out` in `bless` and search for the hex pattern `41 41 41 41 ...`, or use `grep -obUaP 'A{200}' a.out` (prints `offset:match`).", 1),
 ("Which offset format?", "0-based, decimal (or hex with the `0x` prefix). The first byte of the file has offset 0. In `bless` the offset of the cursor is shown in the status bar.", 2)]))

levels.append(tl(6, "Task 3.2 - Two executables, same MD5, different output", 25, "flag_t3b",
"""Create two **different** executables `v1.out` and `v2.out` such that:

* their `xyz` arrays are different (so they print different output),
* their **MD5 hashes are identical**.

Method (see Figure 3 of the lab): split `a.out` into `prefix` (length = **a multiple of 64**, ending inside the array), a **128-byte region** inside the array, and `suffix` (the rest). Run `md5collgen` on the prefix to obtain two outputs `prefix||P` and `prefix||Q`; then:

* `v1.out = prefix || P || suffix`
* `v2.out = prefix || Q || suffix`

Remember to `chmod +x` them, run them, compare `md5sum`, then:

```
authority-upload t3b v1.out v2.out
authority-verify t3b
```

(the binary `a.out` of the previous level must have been uploaded). The flag is the FLAG printed on success.""",
"```\nOFF=<offset of the array>\nS=$(( (OFF + 63) / 64 * 64 ))      # prefix length, multiple of 64, inside the array\nhead -c $S a.out > prefix\nmd5collgen -p prefix -o c1 c2\ntail -c +$((S+129)) a.out > suffix   # data after the 128-byte region\ncat c1 suffix > v1.out ; cat c2 suffix > v2.out ; chmod +x v1.out v2.out\nmd5sum v1.out v2.out ; ./v1.out ; ./v2.out\nauthority-upload t3b v1.out v2.out ; authority-verify t3b\n```", 8,
[("Where to cut?", "Prefix length S must be a multiple of 64 and the 128-byte region [S, S+128) must lie entirely inside the array [OFF, OFF+200). Take the smallest multiple of 64 that is >= OFF.", 2),
 ("head / tail usage", "`head -c S a.out > prefix` saves the first S bytes. `tail -c +N a.out > suffix` saves from the N-th byte (1-based) to the end, so the suffix after the 128-byte region starts at N = S + 129.", 3),
 ("Assembling and verifying", "`md5collgen` outputs are `prefix||P` and `prefix||Q` (size S+128). Build `cat out1 suffix > v1.out`, `cat out2 suffix > v2.out`, `chmod +x`, and compare `md5sum`. Upload both after `a.out` was uploaded at t3a.", 3)]))

levels.append(tl(7, "Task 4 - Same hash, different behaviour", 35, "flag_t4",
"""Now the real attack. The authority certifies a **benign** program and its certificate contains its MD5. You will build a **malicious** program with the **same MD5** so the certificate is valid for both.

Use `~/lab/task4/task4.c`: it has two arrays `X` and `Y` (200 bytes `0x41` each). If `X` and `Y` have the same content the program prints `BENIGN:<your token>`, otherwise `MALICIOUS:<your token>`.

Build two executables (Figure 4 of the lab):

* `benign.out`: contents of `X` and `Y` **equal**,
* `malicious.out`: contents of `X` and `Y` **different**,

with **identical MD5 hash**. Only the contents of the arrays change, not the logic. Idea: the common prefix ends inside `X` (length multiple of 64); `md5collgen` gives `P` and `Q`; put `P` (benign) or `Q` (malicious) in the 128-byte window of `X`, and put `P` at the **same relative position** in `Y`, in both versions. The suffix (including `Y`) must be the same in both files.

```
authority-upload t4 benign.out malicious.out
authority-verify t4
```

The flag of this level is the FLAG printed on success.""",
"```\ngcc task4.c -o t4\ngrep -obUaP 'A{200}' t4 | cut -c1-12         # -> XOFF and YOFF\nS=$(( (XOFF + 63) / 64 * 64 ))  ;  YW=$(( YOFF + S - XOFF ))\nhead -c $S t4 > pre ; md5collgen -p pre -o d1 d2\ntail -c 128 d1 > P\nhead -c $YW t4 | tail -c +$((S+129)) > mid     # between X window and Y window\ntail -c +$((YW+129)) t4 > end                  # after Y window\ncat d1 mid P end > benign.out ; cat d2 mid P end > malicious.out\nchmod +x benign.out malicious.out ; md5sum benign.out malicious.out\n./benign.out ; ./malicious.out\nauthority-upload t4 benign.out malicious.out ; authority-verify t4\n```", 10,
[("Find the arrays", "Compile `task4.c`, then locate both runs of 200 `A` in the binary (`grep -obUaP 'A{200}' t4`). Let XOFF and YOFF be their offsets.", 2),
 ("Choose the cut and the windows", "S = smallest multiple of 64 >= XOFF (prefix = first S bytes, md5collgen on it). X window = [S, S+128). The Y window is at the same relative position: YW = YOFF + (S - XOFF), length 128.", 3),
 ("Assemble the two files", "benign = `d1 || bytes[S+128 .. YW) || P || bytes[YW+128 .. end)` ; malicious = `d2 || (same middle) || P || (same end)`. Here `P` is the last 128 bytes of `d1`. Use `head`/`tail -c +N` (N is 1-based) to extract the middle and end parts.", 4)]))

levels.append({
 "title": "Debrief and report", "level_type": "INFO_LEVEL", "order": 8, "estimated_duration": 0,
 "minimal_possible_solve_time": None,
 "content": """# Congratulations!

You obtained a certificate for a benign program that is also valid for a malicious one. This is exactly why a hash function must be **collision resistant**. MD5 (2004) and SHA-1 (SHAttered, 2017) are broken for this purpose; use SHA-256 / SHA-3 for integrity and signatures.

# Lab report

The platform score only validates the practical part. Submit your **lab report** to your teacher: describe what you did and observed, with **screenshots**, the **important commands/code snippets with explanations**, and answers to the questions Q1-Q3 (Task 1), the experiment of Task 2, and the approach of Tasks 3 and 4. Code without explanation receives no credit.""",
})

total = sum(l.get("max_score", 0) for l in levels)
est = sum(l.get("estimated_duration", 0) for l in levels)
doc = {
 "title": "MD5 Collision Attack Lab",
 "description": "SEED Labs MD5 collision attack: generate collisions, extend them with a suffix, build colliding executables and obtain a certificate for a malicious program. Flags are different for every student.",
 "prerequisites": ["Linux command line", "Basic C and hexadecimal notation", "Notions of hash functions"],
 "outcomes": ["You understand the collision-resistance property and the impact of a collision attack.",
              "You can generate MD5 collisions with md5collgen and exploit them in executables."],
 "state": "UNRELEASED", "show_stepper_bar": True, "levels": levels,
 "estimated_duration": est, "variant_sandboxes": True,
}
with open("training.json", "w") as fh:
    json.dump(doc, fh, indent=2, ensure_ascii=False)
    fh.write("\n")
print("total platform points:", total, "(= %s/20)" % (total if DECIMAL else total / 2), "| estimated minutes:", est)
