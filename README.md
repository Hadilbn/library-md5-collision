# Cybersecurity game "MD5 Collision Attack Lab"
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![License: CC BY-NC-SA 4.0](https://img.shields.io/badge/License-CC%20BY--NC--SA%204.0-lightgrey.svg)](https://creativecommons.org/licenses/by-nc-sa/4.0/)

Linear game for [CyberRangeCZ Platform](https://docs.platform.cyberrange.cz/) with
[APG](https://docs.platform.cyberrange.cz/user-guide-advanced/trainings/trainings-overview/#automatic-generation-problem-apg-in-linear-training-definition)
(every sandbox gets **personal files and personal flags**), based on the SEED Lab *MD5 Collision Attack Lab*.

## Game Levels Summary
| Level | Lab task | Flag source | Points |
|-|-|-|-|
| 1 | Task 1 - collision with `md5collgen` from a personal prefix | authority (`flag_task1`) | 25 |
| 2 | Task 1 Q1 - number of padding bytes (prefix length differs per student) | `t1_padding` | 20 |
| 3 | Task 1 Q2 - collision from a 64-byte prefix | authority (`flag_q2`) | 20 |
| 4 | Task 1 Q3 - positions of the differing bytes (checked on the student's own files) | authority (`flag_q3`) | 20 |
| 5 | Task 2 - `MD5(M‖T) = MD5(N‖T)` with a personal suffix | authority (`flag_task2`) | 25 |
| 6 | Task 3 - two executables with the same MD5 (programs are executed) | authority (`flag_task3`) | 40 |
| 7 | Task 4 - certify the benign program | authority (`flag_cert`) | 15 |
| 8 | Task 4 - deploy the malicious twin with the same certificate | authority (`flag_final`) | 35 |

**Scoring:** 200 points = **20/20** (mark = points / 10). The platform only stores integer
points, so hint penalties of **5–20 points = 0.5–2 points /20**. Revealing a solution = 0 for that level.

## Anti-cheating design
* `variables.yml` generates, per sandbox, a `student_token`, the prefix length (`t1_padding`) and 7 random flags.
* The flags are **never stored on the student's machine**: they live only on the `authority` host
  (`/opt/ca/config.json`, root 0600). Students have no account there.
* The authority only accepts collisions generated from the **student's own** prefix (it contains the token),
  so files from a classmate are rejected. Patching the token into a classmate's binary breaks the collision.
* Uploaded programs are executed as the unprivileged user `carunner` (timeout, rlimits) and cannot read the flags.

## Topology summary
|Host|Image|Flavor|Role|
|-|-|-|-|
|seed|seed (SEED Ubuntu 20.04)|m1.medium|student workstation (`user` / `Password123`)|
|authority|debian-12-x86_64|m1.medium|Certification Authority (checker + flags), `10.1.26.9`, port 80|
|router|debian-12-x86_64|m1.medium|router|

> Adapt `image:` / `mgmt_user:` of the `seed` host in `topology.yml` to the exact name of the SEED image
> and its management user in your OpenStack project.

## Files
* `topology.yml`, `variables.yml`, `training.json` – sandbox + training definitions
* `provisioning/` – Ansible (roles `seed`, `authority`, `hosts`); `md5collgen` (static build of
  Marc Stevens' *fastcoll*) is installed only if the SEED image does not already have it
* `solution/solve.sh` – reference solution (run on `seed` as `user`; solves all 8 levels)
* `solution/build_training.py` – regenerates `training.json`

## Import into CyberRangeCZ
1. Push this repository to a Git server reachable by the platform.
2. **Sandbox definitions → Create**: Git URL of the repository, revision `main`.
3. Create a pool (one sandbox per student, e.g. 30) and allocate.
4. **Training definitions → Upload** `training.json`
   (it is an APG training: *variant sandboxes* enabled, levels use *Variant Answers*).
5. Create a training instance with the definition and the pool.

## License
* The code (Ansible and custom code) is licensed under the MIT License.
* The game design is licensed under CC BY-NC-SA 4.0, because it is derived from the SEED Lab
  "MD5 Collision Attack Lab", Copyright © 2018 by Wenliang Du (CC BY-NC-SA 4.0).

**Attribution:** see `ATTRIBUTION.txt`.
