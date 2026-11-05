#!/usr/bin/env python3
"""
"Trusted Software Certification Authority" for the MD5 Collision Attack Lab.

The authority validates the student's work (collisions, executables, ...) and
returns the per-sandbox (APG) flag when the work is correct.

Security model (the student must not be able to read the flags):
  * this service runs as root, the configuration with the flags is
    /opt/ca/config.json (mode 0600, root only);
  * uploaded programs are executed as the unprivileged user "carunner",
    with a timeout and resource limits, so a student program cannot read
    the flags.
"""
import hashlib
import json
import os
import pwd
import re
import resource
import shutil
import subprocess
import tempfile
import threading

from flask import Flask, request, Response

CONFIG_PATH = os.environ.get("CA_CONFIG", "/opt/ca/config.json")
STATE_PATH = os.environ.get("CA_STATE", "/opt/ca/state/certificates.json")
RUN_DIR = os.environ.get("CA_RUN_DIR", "/var/lib/carunner")
RUN_USER = os.environ.get("CA_RUN_USER", "carunner")
RUN_TIMEOUT = 5
MAX_UPLOAD = 2 * 1024 * 1024

with open(CONFIG_PATH) as f:
    CFG = json.load(f)

TOKEN = CFG["token"].encode()
T1_PREFIX = CFG["t1_prefix"].encode()
Q2_PREFIX = CFG["q2_prefix"].encode()
T2_SUFFIX = CFG["task2_suffix"].encode()
FLAGS = CFG["flags"]

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD
state_lock = threading.Lock()


# --------------------------------------------------------------------------- helpers
def reply(ok, lines, flag_name=None):
    out = ["[OK]" if ok else "[REJECTED]"]
    out += ["    " + l for l in lines]
    if ok and flag_name:
        out.append("")
        out.append("    FLAG: " + FLAGS[flag_name])
        out.append("    (submit only the value after 'FLAG: ')")
    return Response("\n".join(out) + "\n", mimetype="text/plain",
                    status=200 if ok else 400)


def get_file(name):
    f = request.files.get(name)
    if f is None:
        return None
    return f.read()


def md5(b):
    return hashlib.md5(b).hexdigest()


def sha256(b):
    return hashlib.sha256(b).hexdigest()


def ceil64(n):
    return (n + 63) // 64 * 64


def first_diff(a, b):
    for i, (x, y) in enumerate(zip(a, b)):
        if x != y:
            return i
    return min(len(a), len(b))


def diff_positions(a, b):
    return [i for i, (x, y) in enumerate(zip(a, b)) if x != y]


def which_prefix(data):
    """Return (prefix_name, collision_block_start) for a file produced by md5collgen
    from one of this student's prefixes, or (None, None)."""
    if data.startswith(T1_PREFIX):
        start = ceil64(len(T1_PREFIX))
        if data[len(T1_PREFIX):start] == b"\x00" * (start - len(T1_PREFIX)):
            return "prefix.txt", start
    if data.startswith(Q2_PREFIX):
        return "prefix64.txt", len(Q2_PREFIX)
    return None, None


def basic_pair_checks(a, b, problems):
    if a is None or b is None:
        problems.append("Two files are required (fields file1 and file2).")
        return False
    if a == b:
        problems.append("The two files are identical. A collision needs two DIFFERENT inputs.")
        return False
    if md5(a) != md5(b):
        problems.append("MD5 hashes differ: %s vs %s" % (md5(a), md5(b)))
        return False
    return True


def run_program(data):
    """Run an uploaded ELF as the unprivileged runner user. Returns (rc, stdout) or raises."""
    pw = pwd.getpwnam(RUN_USER)
    workdir = tempfile.mkdtemp(prefix="job-", dir=RUN_DIR)
    try:
        os.chown(workdir, pw.pw_uid, pw.pw_gid)
        path = os.path.join(workdir, "prog")
        with open(path, "wb") as f:
            f.write(data)
        os.chown(path, pw.pw_uid, pw.pw_gid)
        os.chmod(path, 0o755)

        def demote():
            os.setsid()
            resource.setrlimit(resource.RLIMIT_CPU, (RUN_TIMEOUT, RUN_TIMEOUT))
            resource.setrlimit(resource.RLIMIT_AS, (256 * 1024 * 1024,) * 2)
            resource.setrlimit(resource.RLIMIT_FSIZE, (1024 * 1024,) * 2)
            resource.setrlimit(resource.RLIMIT_NPROC, (32, 32))
            os.setgroups([])
            os.setgid(pw.pw_gid)
            os.setuid(pw.pw_uid)

        p = subprocess.run([path], cwd=workdir, preexec_fn=demote,
                           stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, timeout=RUN_TIMEOUT,
                           env={"PATH": "/usr/bin:/bin", "HOME": workdir})
        return p.returncode, p.stdout[:65536].decode(errors="replace")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def is_elf(b):
    return b is not None and b[:4] == b"\x7fELF"


def load_state():
    try:
        with open(STATE_PATH) as f:
            return json.load(f)
    except (OSError, ValueError):
        return []


def save_state(certs):
    os.makedirs(os.path.dirname(STATE_PATH), exist_ok=True)
    with open(STATE_PATH, "w") as f:
        json.dump(certs, f, indent=1)


def cert_file(md5sum):
    return os.path.join(os.path.dirname(STATE_PATH), md5sum + ".bin")


# --------------------------------------------------------------------------- pages
INDEX = """<!doctype html><html><head><meta charset="utf-8">
<title>Trusted Software Certification Authority</title>
<style>body{font-family:sans-serif;max-width:900px;margin:2em auto;line-height:1.4}
fieldset{margin:1em 0;padding:1em}legend{font-weight:bold}code{background:#eee;padding:1px 4px}</style>
</head><body>
<h1>Trusted Software Certification Authority</h1>
<p>Upload your work below, or use the command <code>ca-submit</code> on the SEED machine
(run <code>ca-submit help</code>).</p>
%s
</body></html>"""

FORMS = [
    ("task1", "Level 1 - collision from prefix.txt", ["file1", "file2"], False),
    ("q2", "Level 3 - collision from a 64-byte prefix (prefix64.txt)", ["file1", "file2"], False),
    ("q3", "Level 4 - differing bytes (any of your collision pairs + the positions)", ["file1", "file2"], True),
    ("task2", "Level 5 - MD5 property (collision pair + suffix.txt)", ["file1", "file2"], False),
    ("task3", "Level 6 - two executables with the same MD5", ["file1", "file2"], False),
    ("certify", "Level 7 - certify your benign program", ["file"], False),
    ("deploy", "Level 8 - deploy a program with a certified hash", ["file"], False),
]


@app.get("/")
def index():
    html = ""
    for ep, title, fields, offsets in FORMS:
        html += '<fieldset><legend>%s</legend><form method="post" action="/api/%s" enctype="multipart/form-data">' % (title, ep)
        for fld in fields:
            html += '%s: <input type="file" name="%s"> ' % (fld, fld)
        if offsets:
            html += '<br>positions: <input name="offsets" size="60" placeholder="e.g. 19,45,...">'
        html += ' <button>Submit</button></form></fieldset>'
    return INDEX % html


@app.get("/health")
def health():
    return "ok\n"


# --------------------------------------------------------------------------- Level 1
@app.post("/api/task1")
def task1():
    a, b = get_file("file1"), get_file("file2")
    problems = []
    if not basic_pair_checks(a, b, problems):
        return reply(False, problems)
    expected_len = ceil64(len(T1_PREFIX)) + 128
    for name, d in (("file1", a), ("file2", b)):
        if not d.startswith(T1_PREFIX):
            return reply(False, ["%s does not start with YOUR ~/lab/task1/prefix.txt." % name,
                                 "Generate the collision from your own prefix file."])
        if len(d) != expected_len:
            return reply(False, ["%s is %d bytes, expected the raw md5collgen output (%d bytes)."
                                 % (name, len(d), expected_len)])
    return reply(True, ["Both files start with your prefix, they are different,",
                        "and both have MD5 = " + md5(a)], "flag_task1")


# --------------------------------------------------------------------------- Level 3
@app.post("/api/q2")
def q2():
    a, b = get_file("file1"), get_file("file2")
    problems = []
    if not basic_pair_checks(a, b, problems):
        return reply(False, problems)
    for name, d in (("file1", a), ("file2", b)):
        if not d.startswith(Q2_PREFIX):
            return reply(False, ["%s does not start with YOUR ~/lab/task1/prefix64.txt." % name])
        if len(d) != 64 + 128:
            return reply(False, ["%s is %d bytes, expected 192 bytes (64 prefix + 128 generated)."
                                 % (name, len(d))])
    return reply(True, ["64-byte prefix collision accepted: no padding was needed.",
                        "MD5 = " + md5(a)], "flag_q2")


# --------------------------------------------------------------------------- Level 4
def parse_offsets(s):
    vals = set()
    for tok in re.split(r"[\s,;]+", (s or "").strip()):
        if not tok:
            continue
        vals.add(int(tok, 0))  # accepts 19, 0x13 ...
    return vals


@app.post("/api/q3")
def q3():
    a, b = get_file("file1"), get_file("file2")
    problems = []
    if not basic_pair_checks(a, b, problems):
        return reply(False, problems)
    pa, start = which_prefix(a)
    pb, _ = which_prefix(b)
    if pa is None or pa != pb or len(a) != start + 128 or len(b) != start + 128:
        return reply(False, ["Submit a raw md5collgen pair generated from YOUR prefix.txt or prefix64.txt."])
    try:
        given = parse_offsets(request.form.get("offsets"))
    except ValueError:
        return reply(False, ["Could not parse the positions. Use e.g. '19,45,59' (decimal or 0x..)."])
    real_abs = set(diff_positions(a, b))
    real_rel = {p - start for p in real_abs}
    if given == real_abs or given == real_rel:
        return reply(True, ["Correct: %d bytes differ inside the 128-byte block." % len(real_rel),
                            "Relative positions (0..127): " + ", ".join(map(str, sorted(real_rel))),
                            "Absolute positions in file : " + ", ".join(map(str, sorted(real_abs)))],
                     "flag_q3")
    return reply(False, ["Wrong set of positions (you gave %d values, the pair has %d differing bytes)."
                         % (len(given), len(real_abs)),
                         "Give ALL positions, either relative to the 128-byte block or absolute in the file."])


# --------------------------------------------------------------------------- Level 5
@app.post("/api/task2")
def task2():
    a, b = get_file("file1"), get_file("file2")
    problems = []
    if not basic_pair_checks(a, b, problems):
        return reply(False, problems)
    pa, start = which_prefix(a)
    pb, _ = which_prefix(b)
    if pa is None or pa != pb:
        return reply(False, ["The files must start with one of YOUR collision pairs (prefix.txt or prefix64.txt)."])
    for name, d in (("file1", a), ("file2", b)):
        if d[start + 128:] != T2_SUFFIX:
            return reply(False, ["%s: the data after the 128-byte collision block is not exactly"
                                 " YOUR ~/lab/task2/suffix.txt." % name])
    if a[:start + 128] == b[:start + 128]:
        return reply(False, ["The collision blocks are identical; use the two DIFFERENT outputs of md5collgen."])
    return reply(True, ["MD5(M || T) == MD5(N || T) == " + md5(a),
                        "The suffix did not break the collision: the property holds."], "flag_task2")


# --------------------------------------------------------------------------- Level 6
@app.post("/api/task3")
def task3():
    a, b = get_file("file1"), get_file("file2")
    problems = []
    if not basic_pair_checks(a, b, problems):
        return reply(False, problems)
    if not (is_elf(a) and is_elf(b)):
        return reply(False, ["Both files must be ELF executables compiled from ~/lab/task3/xyz.c."])
    fd = first_diff(a, b)
    if TOKEN not in a[:fd]:
        return reply(False, ["Your student-id was not found in the common part (prefix) of the executables.",
                             "Compile YOUR ~/lab/task3/xyz.c, do not reuse someone else's binaries."])
    try:
        ra, oa = run_program(a)
        rb, ob = run_program(b)
    except subprocess.TimeoutExpired:
        return reply(False, ["A program did not finish within %d s." % RUN_TIMEOUT])
    except Exception as e:  # noqa
        return reply(False, ["Could not run the programs: %s" % e])
    if ra != 0 or rb != 0:
        return reply(False, ["Both programs must run and exit with code 0 (got %d and %d)." % (ra, rb)])
    if lab_id_line() not in oa or lab_id_line() not in ob:
        return reply(False, ["The programs must print your student-id line (keep the code of xyz.c)."])
    if oa == ob:
        return reply(False, ["Both programs print the same output; their xyz arrays must differ."])
    return reply(True, ["Same MD5 (%s), different xyz arrays, different output." % md5(a)], "flag_task3")


def lab_id_line():
    return "student-id: " + TOKEN.decode()


# --------------------------------------------------------------------------- Levels 7-8
@app.post("/api/certify")
def certify():
    p = get_file("file")
    if not is_elf(p):
        return reply(False, ["Upload one ELF executable (field 'file')."])
    if TOKEN not in p:
        return reply(False, ["Your student-id was not found in the program. Build it from ~/lab/task4/program.c."])
    try:
        rc, out = run_program(p)
    except subprocess.TimeoutExpired:
        return reply(False, ["The program did not finish within %d s." % RUN_TIMEOUT])
    if lab_id_line() not in out:
        return reply(False, ["The program must print your student-id line."])
    if "MALICIOUS" in out:
        return reply(False, ["Testing revealed MALICIOUS behaviour. Certification refused!"])
    if "BENIGN" not in out:
        return reply(False, ["The program does not demonstrate its benign behaviour (expected 'BENIGN' in the output)."])
    h = md5(p)
    with state_lock:
        certs = load_state()
        if h not in [c["md5"] for c in certs]:
            certs.append({"md5": h, "sha256": sha256(p)})
            with open(cert_file(h), "wb") as f:
                f.write(p)
            save_state(certs)
    return reply(True, ["The program was tested and behaves well.",
                        "------------------ CERTIFICATE ------------------",
                        " Subject   : program of student " + TOKEN.decode(),
                        " MD5       : " + h,
                        " Verdict   : BENIGN - safe to install",
                        " Serial no.: see the flag below",
                        "-------------------------------------------------",
                        "Anyone presenting a program with this MD5 will be trusted."], "flag_cert")


@app.post("/api/deploy")
def deploy():
    p = get_file("file")
    if not is_elf(p):
        return reply(False, ["Upload one ELF executable (field 'file')."])
    h = md5(p)
    with state_lock:
        certs = {c["md5"]: c for c in load_state()}
    if h not in certs:
        return reply(False, ["MD5 %s is not certified. Deployment refused." % h])
    if sha256(p) == certs[h]["sha256"]:
        return reply(False, ["This is exactly the program that was certified (the benign one).",
                             "Deployed fine... but nothing malicious happened.",
                             "Deploy a DIFFERENT program that has the same MD5."])
    with open(cert_file(h), "rb") as f:
        original = f.read()
    if TOKEN not in p[:first_diff(p, original)]:
        return reply(False, ["Your student-id was not found in the common prefix of the two programs."])
    try:
        rc, out = run_program(p)
    except subprocess.TimeoutExpired:
        return reply(False, ["The program did not finish within %d s." % RUN_TIMEOUT])
    if "MALICIOUS" not in out:
        return reply(False, ["The certificate matched (MD5 %s) but the program did not show malicious"
                             " behaviour ('MALICIOUS' expected in the output)." % h])
    return reply(True, ["Certificate check: MD5 %s ... VALID" % h,
                        "The 'certified' program was deployed and executed MALICIOUS code!",
                        "MD5 collisions completely break hash-based certification."], "flag_final")


if __name__ == "__main__":
    os.makedirs(RUN_DIR, exist_ok=True)
    app.run(host="0.0.0.0", port=int(os.environ.get("CA_PORT", "80")), threaded=True)
