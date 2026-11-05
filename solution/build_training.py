#!/usr/bin/env python3
"""Generates ../training.json (CyberRangeCZ linear training with APG variant answers).

Scoring: the platform only accepts integer points, so the training is scored on
200 points = 20/20.  Final mark = score / 10.  Hint penalties 5..20 = 0.5..2 points.
"""
import json
import os

def hint(order, title, content, penalty):
    return {"title": title, "content": content, "hint_penalty": penalty, "order": order}

def level(order, title, var, content, solution, hints, score, duration, limit=10):
    return {
        "title": title, "level_type": "TRAINING_LEVEL", "order": order,
        "estimated_duration": duration, "minimal_possible_solve_time": None,
        "answer": None, "answer_variable_name": var,
        "content": content, "solution": solution, "solution_penalized": True,
        "hints": hints, "incorrect_answer_limit": limit, "attachments": [],
        "max_score": score, "variant_answers": True, "reference_solution": [],
        "mitre_techniques": [], "expected_commands": [], "commands_required": False,
    }

INTRO = """# General information: please read carefully

* This training follows the **SEED Lab "MD5 Collision Attack Lab"** (Wenliang Du). Keep the lab PDF at hand.
* The solution of a level **will be required** in the further levels. Do not skip ahead.
* **Every student has a personal sandbox**: personal files (with your own *student-id*) and personal flags. Flags of a classmate will **not** work for you, and the authority **rejects files generated from somebody else's prefix**.
* All your files are in **`~/lab/`** on the `seed` machine. Read `~/lab/README.txt` first.
* Flags are given by the **Trusted Software Certification Authority** (host `authority`, `10.1.26.9`) when your work is correct. Submit your work with the command **`ca-submit`** (run `ca-submit help`) or with the web page `http://authority/` in Firefox.

# Grading

| | |
|-|-|
| Total | **200 points = 20/20** (final mark = points / 10) |
| Hints | each hint costs **5 to 20 points (= 0.5 to 2 /20)**, shown on the hint |
| Solution | displaying the solution of a level gives **0 points** for that level |

| Level | Topic (lab task) | Points | /20 |
|-|-|-|-|
| 1 | Task 1 - first collision | 25 | 2.5 |
| 2 | Task 1 - Question 1 (padding) | 20 | 2 |
| 3 | Task 1 - Question 2 (64-byte prefix) | 20 | 2 |
| 4 | Task 1 - Question 3 (differing bytes) | 20 | 2 |
| 5 | Task 2 - MD5 property | 25 | 2.5 |
| 6 | Task 3 - two executables | 40 | 4 |
| 7 | Task 4 - certification | 15 | 1.5 |
| 8 | Task 4 - malicious deployment | 35 | 3.5 |

# Storyline

You work for a small software company. Your customers only install software that has been certified by the **Trusted Software Certification Authority**. The authority tests every program and signs a certificate that contains the **MD5 hash** of the program, so nobody can modify the program after certification... or can they?

Your boss suspects that MD5 is not good enough any more and asks you to prove it, step by step: first by producing simple collisions, then colliding executables, and finally a malicious program that is accepted with the certificate of a benign one.

*This game is for educational purposes only. The story is fictitious.*"""

ACCESS = """Your first task is to access the sandbox, where you will complete all following tasks. After you have successfully connected, submit the answer **`start`**.

### Sandbox access
1. In the topology overview on the right, right-click on **`seed`** and then click on **`Open GUI`**; a new pop-up window will appear.
2. Login with username **`user`** and password **`Password123`**.
3. Open a terminal and run `cat ~/lab/README.txt`.

Alternatively, you can use SSH to connect to the machine. SSH access makes it easier to copy-paste commands and flags, but requires more steps to set up. See the [documentation](https://docs.platform.cyberrange.cz/user-guide-advanced/sandboxes/sandbox-access/#user-access)."""

L1 = """*Lab Task 1 - Generating two different files with the same MD5 hash.*

Your boss wants a first proof: **two different files with the same MD5 hash**, both starting with the prefix file he prepared for you: **`~/lab/task1/prefix.txt`**.

1. Use **`md5collgen`** with your prefix file to generate two output files.
2. Check that they are different (`diff`) but have the same hash (`md5sum`).
3. Look at both files in a hex editor (`bless`) or with `xxd` and note your observations (you will need them in the next levels).
4. Send the two **unmodified** outputs to the authority:

```
ca-submit task1 out1.bin out2.bin
```

The flag is the value printed after `FLAG:`."""

L1_SOL = """```
cd ~/lab/task1
md5collgen -p prefix.txt -o out1.bin out2.bin
diff out1.bin out2.bin        # Binary files differ
md5sum out1.bin out2.bin      # identical hashes
ca-submit task1 out1.bin out2.bin
```"""

L2 = """*Lab Task 1 - Question 1: if the length of your prefix file is not a multiple of 64, what is going to happen?*

MD5 works on blocks of 64 bytes, and `md5collgen` must start the collision blocks on a block boundary. Look carefully at the files generated in the previous level, right after the end of your prefix text.

**The flag is the number of padding bytes that `md5collgen` inserted between your `prefix.txt` and the 128 generated bytes** (a decimal number, e.g. `12`).

Your prefix length is personal, so is the answer. You have only **5 attempts**."""

L2_SOL = """`md5collgen` pads the prefix with **zero bytes (0x00)** up to the next multiple of 64, then appends the 128 colliding bytes.

```
stat -c %s ~/lab/task1/prefix.txt       # L
# padding = 64 - (L % 64)
xxd ~/lab/task1/out1.bin | less         # the 00 bytes after the prefix
```"""

L3 = """*Lab Task 1 - Question 2: create a prefix file with exactly 64 bytes, run the collision tool again and see what happens.*

A 64-byte prefix is ready for you: **`~/lab/task1/prefix64.txt`** (check its size!).

1. Generate a collision from it.
2. Compare the size of the outputs with those of Level 1. Is there any padding now?
3. Submit the two unmodified outputs:

```
ca-submit q2 out1.bin out2.bin
```"""

L3_SOL = """```
cd ~/lab/task1
wc -c prefix64.txt                       # 64
md5collgen -p prefix64.txt -o q2_1.bin q2_2.bin
ls -l q2_1.bin q2_2.bin                  # 192 bytes = 64 + 128, no padding
ca-submit q2 q2_1.bin q2_2.bin
```"""

L4 = """*Lab Task 1 - Question 3: are the 128 bytes generated by `md5collgen` completely different for the two output files? Identify all the bytes that are different.*

Take the pair generated in Level 3 (or Level 1) and find **every** position where the two files differ.

Submit the pair **and** the list of positions (decimal, separated by commas). Positions can be given either **relative to the start of the 128-byte block (0..127)** or **absolute in the file (0-based)**:

```
ca-submit q3 q2_1.bin q2_2.bin "pos1,pos2,..."
```

Note: the exact number of differing bytes is not always the same from one run to another. Use YOUR files.

*For your report: what does this tell you about how the collision is built?*"""

L4_SOL = """`cmp -l` prints the 1-based offsets of the differing bytes:

```
cmp -l q2_1.bin q2_2.bin
# for the 64-byte prefix: relative = offset - 1 - 64
ca-submit q3 q2_1.bin q2_2.bin "$( (cmp -l q2_1.bin q2_2.bin || true) | awk '{printf "%s%d",(NR>1?",":""),$1-65}')"
```

Typically only 6-8 bytes differ (around positions 19, 45, 59 in each 64-byte block): the two blocks differ only in a few bits of the message words M4, M11 and M14 (Wang's differential path). The rest of the 128 bytes is identical."""

L5 = """*Lab Task 2 - Understanding MD5's property.*

MD5 processes the input block by block (Merkle-Damgard construction). Therefore, if `MD5(M) = MD5(N)` then for any suffix `T`: **`MD5(M || T) = MD5(N || T)`**.

Design an experiment that demonstrates this property:

* `M` and `N` are one of your collision pairs (from Level 1 or Level 3),
* `T` is your personal suffix **`~/lab/task2/suffix.txt`**.

Build `M || T` and `N || T`, check their hashes, then submit both files:

```
ca-submit task2 MT.bin NT.bin
```"""

L5_SOL = """```
cd ~/lab/task1
cat out1.bin ../task2/suffix.txt > MT.bin
cat out2.bin ../task2/suffix.txt > NT.bin
md5sum MT.bin NT.bin      # still identical
ca-submit task2 MT.bin NT.bin
```"""

L6 = """*Lab Task 3 - Generating two executable files with the same MD5 hash.*

Your personal version of the lab program is **`~/lab/task3/xyz.c`** (the `xyz` array is filled with 200 x `0x41` = `A`). Do **not** change the `student_id` line.

Create **two executables** with the **same MD5 hash** whose `xyz` arrays are different (so they print different output):

1. Compile the program: `gcc xyz.c -o xyz.out`.
2. Locate the 200 `A` in the binary (`bless`, `xxd`, `grep`).
3. Split the binary into **prefix** (length = multiple of 64, ending inside the array) + **128-byte region** (inside the array) + **suffix**.
4. Run `md5collgen` on the prefix, keep the 128 generated bytes P and Q of each output.
5. Build `prefix || P || suffix` and `prefix || Q || suffix`, run both, check the MD5 hashes.
6. Submit them:

```
ca-submit task3 a1.out a2.out
```

The authority runs both programs and checks your student-id."""

L6_SOL = """```
cd ~/lab/task3 && gcc xyz.c -o xyz.out
OFF=$(grep -obUaP 'A{200}' xyz.out | head -1 | cut -d: -f1)   # start of xyz
START=$(( (OFF + 63) / 64 * 64 ))                               # 64-aligned, inside xyz
head -c $START xyz.out > prefix
tail -c +$((START + 128 + 1)) xyz.out > suffix
md5collgen -p prefix -o p1 p2
tail -c 128 p1 > P; tail -c 128 p2 > Q
cat prefix P suffix > a1.out; cat prefix Q suffix > a2.out
chmod +x a1.out a2.out; ./a1.out; ./a2.out; md5sum a1.out a2.out
ca-submit task3 a1.out a2.out
```"""

L7 = """*Lab Task 4 - Making the two programs behave differently (part 1).*

Now the real attack. You want a **malicious** program certified by the authority. You will prepare **two programs with the same MD5**: a benign one that you send for certification, and a malicious one that you deploy afterwards with the same certificate.

Your skeleton is **`~/lab/task4/program.c`**: it contains two arrays `X` and `Y` (both filled with `A`). If `X` and `Y` are equal it runs `benign_code()`, otherwise `malicious_code()` (see Figure 4 of the lab).

1. Compile it and locate **both** arrays in the binary.
2. Generate P and Q from a prefix that ends inside `X` (multiple of 64).
3. Build two versions that differ **only** in the content of the arrays:
   * **benign**: `X` contains P, `Y` contains P (at the same relative position),
   * **malicious**: `X` contains Q, `Y` contains P.
4. Check that both have the same MD5 and run them.
5. **Get the benign version certified:**

```
ca-submit certify benign.out
```

The flag is printed on your certificate. **Keep the malicious version for the next level!** (Certify the benign twin of your collision pair, otherwise the next level cannot work.)"""

L7_SOL = """```
cd ~/lab/task4 && gcc program.c -o prog.out
grep -obUaP 'A{200}' prog.out        # two offsets: X and Y
# X = offset of X, Yo = offset of Y
START=$(( (X + 63) / 64 * 64 )); R=$(( START - X )); YS=$(( Yo + R ))
head -c $START prog.out > prefix
md5collgen -p prefix -o p1 p2; tail -c 128 p1 > P; tail -c 128 p2 > Q
tail -c +$((START+129)) prog.out | head -c $((YS-START-128)) > middle
tail -c +$((YS+129)) prog.out > end
cat prefix P middle P end > benign.out
cat prefix Q middle P end > evil.out
chmod +x benign.out evil.out; md5sum benign.out evil.out
ca-submit certify benign.out
```"""

L8 = """*Lab Task 4 - Making the two programs behave differently (part 2).*

The authority has signed a certificate for the MD5 hash of your benign program. Customers trust any program whose MD5 matches a certificate...

**Deploy your malicious version** (same MD5, different content, prints `MALICIOUS`):

```
ca-submit deploy evil.out
```

If the authority accepts it with the existing certificate, it prints the final flag.

*For your report: explain why the logic of the program did not need to change, and why this attack works for MD5 but would not work with a collision-resistant hash like SHA-256.*"""

L8_SOL = """```
./evil.out                 # MALICIOUS: ...
md5sum benign.out evil.out # same hash
ca-submit deploy evil.out
```
The two programs share the prefix and the suffix; only the 128-byte block inside `X` differs (P vs Q) and both have the same MD5. `Y` contains P in both versions, so `X == Y` in the benign one and `X != Y` in the malicious one."""

EPILOGUE = """# Congratulations!

You have shown that a broken collision-resistance property is not a theoretical problem:

* two different inputs with the same MD5 can be generated in seconds (`md5collgen`, Marc Stevens' fastcoll);
* thanks to the Merkle-Damgard construction, any common suffix keeps the collision;
* executables can be crafted so that a certified benign program and a malicious one share the same MD5.

This is why MD5 (and SHA-1, see the SHAttered attack) must not be used for signatures, certificates or integrity checks. Use SHA-256/SHA-3.

Do not forget your **lab report** (screenshots, observations, answers to the questions and explained code snippets)."""

levels = [
    {"title": "Introduction", "level_type": "INFO_LEVEL", "order": 0,
     "estimated_duration": 0, "minimal_possible_solve_time": None, "content": INTRO},
    {"title": "Get Access", "level_type": "ACCESS_LEVEL", "order": 1,
     "estimated_duration": 0, "minimal_possible_solve_time": None, "passkey": "start",
     "cloud_content": ACCESS, "local_content": "This sandbox has not been tested for use with local sandbox."},
    level(2, "Level 1: Your first MD5 collision", "flag_task1", L1, L1_SOL, [
        hint(0, "How to use md5collgen?", "`md5collgen -p <prefix file> -o <output1> <output2>`", 5),
        hint(1, "How to submit?", "`ca-submit task1 <output1> <output2>` from the `seed` machine. Submit the raw outputs, do not edit them.", 5),
        hint(2, "Rejected: wrong prefix or size?", "Use exactly `~/lab/task1/prefix.txt` (your personal file). The outputs must be the files written by md5collgen, unmodified.", 10),
    ], 25, 10),
    level(3, "Level 2: Prefix not a multiple of 64 (Question 1)", "t1_padding", L2, L2_SOL, [
        hint(0, "Where to look?", "Open `out1.bin` with `xxd` or `bless` and look at the bytes just after the end of your prefix text. What value do they have?", 5),
        hint(1, "How to count?", "Get the prefix size with `stat -c %s prefix.txt` or `wc -c`. The collision blocks start at the next multiple of 64.", 10),
    ], 20, 10, limit=5),
    level(4, "Level 3: A 64-byte prefix (Question 2)", "flag_q2", L3, L3_SOL, [
        hint(0, "Which file?", "Use `~/lab/task1/prefix64.txt`, it is exactly 64 bytes (`wc -c`).", 5),
        hint(1, "How to submit?", "`ca-submit q2 <output1> <output2>`. The outputs must be 192 bytes long.", 10),
    ], 20, 5),
    level(5, "Level 4: Which bytes differ? (Question 3)", "flag_q3", L4, L4_SOL, [
        hint(0, "Which tool?", "`cmp -l file1 file2` lists every differing byte: offset (1-based!) and the two values in octal.", 5),
        hint(1, "Converting the offsets", "cmp offsets are 1-based. Absolute 0-based position = offset - 1. Relative position = offset - 1 - (size of the padded prefix).", 10),
    ], 20, 10),
    level(6, "Level 5: Understanding MD5's property (Task 2)", "flag_task2", L5, L5_SOL, [
        hint(0, "What are M, N and T?", "M and N are the two outputs of md5collgen (same hash). T is `~/lab/task2/suffix.txt`. Append the same T to both.", 10),
        hint(1, "How to concatenate?", "`cat file1 file2 > file3` puts file2 after file1 into file3.", 10),
    ], 25, 10),
    level(7, "Level 6: Two executables with the same MD5 (Task 3)", "flag_task3", L6, L6_SOL, [
        hint(0, "How to find the array?", "`grep -obUaP 'A{200}' xyz.out` prints the offset of the 200 A's. You can also search for `41 41 41` in bless.", 5),
        hint(1, "Where to cut?", "Prefix length = the first multiple of 64 that is >= the offset of the array. The 128-byte region then lies inside the array (200 bytes).", 10),
        hint(2, "head and tail", "`head -c N file` = first N bytes. `tail -c +K file` = from byte K (1-based!) to the end, so the suffix starts at `tail -c +$((N+128+1))`. P = `tail -c 128 out1`.", 20),
    ], 40, 30),
    level(8, "Level 7: Get your benign program certified (Task 4)", "flag_cert", L7, L7_SOL, [
        hint(0, "Two arrays?", "`grep -obUaP 'A{200}' prog.out` gives two offsets: the first is X, the second is Y.", 5),
        hint(1, "Where to put P in Y?", "P must be at the SAME position inside Y as inside X: Y_start = offset(Y) + (prefix_length - offset(X)). Everything outside the two 128-byte regions stays unchanged.", 10),
    ], 15, 25),
    level(9, "Level 8: Deploy the malicious program (Task 4)", "flag_final", L8, L8_SOL, [
        hint(0, "Not accepted?", "The deployed program must have exactly the MD5 of a certified program but be a different file. Did you certify the benign twin of YOUR collision pair?", 10),
        hint(1, "Malicious version", "The malicious version is prefix || Q || middle || P || end: X contains Q, Y contains P, so X != Y.", 20),
    ], 35, 10),
    {"title": "Epilogue", "level_type": "INFO_LEVEL", "order": 10,
     "estimated_duration": 0, "minimal_possible_solve_time": None, "content": EPILOGUE},
]

training = {
    "title": "MD5 Collision Attack Lab",
    "description": "Hands-on version of the SEED Lab 'MD5 Collision Attack Lab': generate MD5 collisions, "
                   "verify the Merkle-Damgard suffix property, create colliding executables and get a "
                   "malicious program accepted with the certificate of a benign one. Personal flags (APG).",
    "prerequisites": ["Basic Linux command line", "Basic C programming", "Notion of hash functions"],
    "outcomes": [
        "Generate MD5 collisions with md5collgen and analyse them with a hex editor",
        "Understand MD5 block processing, padding and the Merkle-Damgard suffix property",
        "Manipulate executables at the binary level (head, tail, cat, bless)",
        "Understand why broken collision resistance breaks code certification",
    ],
    "state": "UNRELEASED",
    "show_stepper_bar": True,
    "levels": levels,
    "estimated_duration": sum(l.get("estimated_duration", 0) for l in levels),
    "variant_sandboxes": True,
}

here = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(here, "..", "training.json"), "w") as f:
    json.dump(training, f, indent=1, ensure_ascii=False)

total = sum(l.get("max_score", 0) for l in levels)
print("levels:", len(levels), "total points:", total, "=> /20:", total / 10)
for l in levels:
    if l["level_type"] == "TRAINING_LEVEL":
        pen = sum(h["hint_penalty"] for h in l["hints"])
        assert pen <= l["max_score"]
        assert all(5 <= h["hint_penalty"] <= 20 for h in l["hints"])
        print("  %-55s %3d pts  hints: %s" % (l["title"], l["max_score"],
              [h["hint_penalty"] / 10 for h in l["hints"]]))
