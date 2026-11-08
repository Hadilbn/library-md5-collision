# Game design

Linear training, 6 scored levels, ~105 minutes. Each scored level ends with a **verification by the Certification Authority**
which returns a per-sandbox flag. Mapping to the SEED lab: Task 1 -> levels 2-3, Task 2 -> level 4, Task 3 -> levels 5-6, Task 4 -> level 7.

Verification summary (server.py): t1 valid collision on the student's prefix; t1q answers Q1/Q2/Q3 computed from the student's files;
t2 `out1||T` / `out2||T` with T containing the personal token; t3a ELF of the personalised program + array offset;
t3b same-MD5 executables differing only inside one 128-byte block of the array and printing different output;
t4 same-MD5 executables, one prints `BENIGN:<token>`, the other `MALICIOUS:<token>`.
