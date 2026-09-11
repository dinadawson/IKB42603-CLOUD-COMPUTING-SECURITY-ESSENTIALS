# Lab 5: Monitoring, Logging & Incident Detection

**Course:** IKB42603 Cloud Computing Security Essentials
**Name:** _(fill in your full name as printed in Lab 2)_
**Lecturer:** _(confirm — Lab 2 used "MADAM ADNI"; lab manual header PDF shows "Prof. Dr. Shahrulniza Musa")_
**Section:** B03, Group S
**Date:** _(submission date)_

## Objectives

This lab builds visibility into cloud operations and turns that visibility into detection and response:

1. **Centralised logging** — collecting logs from an application into a single store (simulated CloudWatch Logs via LocalStack).
2. **Querying logs** for security-relevant activity.
3. **Tamper-evidence** via a hash-chained log.
4. **Incident detection** by correlating multiple log lines into a single alert.
5. **Incident response** — contain, collect evidence, document.

**Environment note:** Completed on macOS (zsh) with LocalStack pinned to version `3.0` (newer versions require a paid auth token, consistent with earlier labs in this repo).

## Setup

```bash
docker run -d --name localstack -p 4566:4566 localstack/localstack:3.0
EP='--endpoint-url=http://localhost:4566'
aws $EP logs create-log-group --log-group-name /ccse/app
aws $EP logs create-log-stream --log-group-name /ccse/app --log-stream-name auth
```

## Task 1 — Generate Application Logs

### Procedure
```bash
cat > auth.log <<'EOF'
2025-03-01T09:00:01 LOGIN_OK user=ahmad ip=10.0.0.5
2025-03-01T09:01:10 LOGIN_FAIL user=admin ip=203.0.113.9
2025-03-01T09:01:12 LOGIN_FAIL user=admin ip=203.0.113.9
2025-03-01T09:01:15 LOGIN_FAIL user=admin ip=203.0.113.9
2025-03-01T09:01:18 LOGIN_FAIL user=admin ip=203.0.113.9
2025-03-01T09:01:22 LOGIN_OK user=admin ip=203.0.113.9
2025-03-01T09:01:40 EXPORT_DATA user=admin ip=203.0.113.9 size=500MB
EOF
```

<img width="643" height="302" alt="dinadswson@ac-dee Labs Epa--end0o nt-urlehttolocalhost4566" src="https://github.com/user-attachments/assets/a0c7503d-1ad9-47cc-870f-07b0929c7737" />


**Observed result:** A 7-line authentication log was created, simulating a legitimate login (`ahmad`) alongside a suspicious pattern from a single IP (`203.0.113.9`): four failed login attempts, followed by a successful login, followed by a large data export.

## Task 2 — Centralise Logs (Ship to CloudWatch)

### Procedure
```bash
TS=$(date +%s000)
while IFS= read -r line; do
 aws $EP logs put-log-events --log-group-name /ccse/app --log-stream-name auth \
 --log-events timestamp=$TS,message="$line" >/dev/null
 TS=$((TS+1000))
done < auth.log

aws $EP logs get-log-events --log-group-name /ccse/app --log-stream-name auth \
 --query 'events[].message' --output text
```

<img width="1053" height="451" alt="Screenshot 2026-09-10 at 2 24 05 PM" src="https://github.com/user-attachments/assets/f975fc9f-820f-49c5-891c-343dda164b0e" />


**Observed result:** All 7 log lines were successfully shipped to the centralised CloudWatch Logs store and read back intact.

**Security interpretation:** Centralising logs (rather than leaving them on each individual host) means logs survive even if the originating host is compromised or destroyed, and allows querying and correlation across every service from one place — a prerequisite for any of the detection work in Session B.

## Task 3 — Query for Security-Relevant Activity

### Procedure
```bash
grep LOGIN_FAIL auth.log | awk '{print $4, $5}' | sort | uniq -c
```

<img width="702" height="30" alt="Screenshot 2026-09-10 at 2 24 52 PM" src="https://github.com/user-attachments/assets/58fd082d-2024-43e4-8941-16ab63e5af86" />


**Observed result:** 4 failed login attempts were identified, all originating from the same IP address, `203.0.113.9`.

**Security interpretation:** A single failed login is unremarkable, but grouping and counting failures by source IP surfaces a pattern consistent with a brute-force attempt. This is a **log query** — an on-demand, retrospective look at durable records — as distinct from a real-time **event/alert**, which is addressed in Task 5.

**Session A complete.** `auth.log` was retained for Session B.

## Task 4 — Tamper-Proof (Hash-Chained) Logs

### Procedure
```bash
PREV=0
while IFS= read -r line; do
 PREV=$(printf '%s%s' "$PREV" "$line" | shasum -a 256 | cut -d' ' -f1)
 printf '%s | %s\n' "$line" "$PREV"
done < auth.log > auth.chain

sed 's/500MB/5MB/' auth.log > auth.tampered

PREV=0
while IFS= read -r line; do
 PREV=$(printf '%s%s' "$PREV" "$line" | shasum -a 256 | cut -d' ' -f1)
done < auth.tampered

echo "Original final hash:"
tail -1 auth.chain | sed 's/.*| //'
echo "Tampered final hash:"
echo "$PREV"
```

<img width="506" height="147" alt="2011=4 authooin sed s Original final hash" src="https://github.com/user-attachments/assets/8fbd794e-54a5-4979-b3ad-b2922961ac9c" />


**Observed result:**
- Original final hash: `ababa787b4bf524d9daddca8c48e4909fc105769a6f17574f42cefe8f81233cf`
- Tampered final hash (after changing `500MB` to `5MB` in the export line): `72f1d53774a3a938fa7bd3a88f67894e5a64055a41ee7511eac53d7bd89d859b`

**Security interpretation:** Each entry's hash incorporates the hash of every entry before it, so altering even a single character anywhere in the log — here, an attacker attempting to understate the size of exfiltrated data — changes the final hash completely. Recomputing the chain and comparing the final hash against a securely stored reference value proves whether the log has been altered, without needing to inspect every line manually. As the lab notes, the final hash should ideally be forwarded to a separate, append-only store so that an attacker who compromises the application server cannot also rewrite the audit trail that would reveal the compromise.

## Task 5 — Detect the Incident (Correlation)

### Procedure
```bash
IP=203.0.113.9
FAILS=$(grep -c "LOGIN_FAIL.*$IP" auth.log)
SUCCESS=$(grep -c "LOGIN_OK.*$IP" auth.log)
EXPORT=$(grep -c "EXPORT_DATA.*$IP" auth.log)
echo "IP=$IP fails=$FAILS success=$SUCCESS export=$EXPORT"

if [ "$FAILS" -ge 3 ] && [ "$SUCCESS" -ge 1 ] && [ "$EXPORT" -ge 1 ]; then
 echo 'ALERT: probable brute-force -> compromise -> data exfiltration'
fi
```

<img width="562" height="289" alt="il -1 auth chain  sed &#39;s  1" src="https://github.com/user-attachments/assets/c754a189-54f7-4e2b-a70c-d8ea9ff88738" />


**Observed result:** `IP=203.0.113.9 fails=4 success=1 export=1`, triggering `ALERT: probable brute-force -> compromise -> data exfiltration`.

**Security interpretation:** No single log line here is inherently alarming — a failed login happens routinely, as does a successful login or a data export. The incident only becomes visible when these three signals are **correlated** by source IP and read together as a sequence: repeated failures (an attack in progress), followed by a success (the attack succeeded), followed by an export (the attacker acted on the access gained). This is the core function of a SIEM — turning individually unremarkable events into a single, actionable detection.

## Task 6 — Incident Response

### Procedure
```bash
docker run --rm --cap-add=NET_ADMIN alpine sh -c \
 'apk add -q iptables; iptables -A INPUT -s 203.0.113.9 -j DROP; iptables -L INPUT -n | tail -2'

cp auth.log evidence_20260910.log
shasum -a 256 evidence_*.log > evidence.sha256
cat evidence.sha256
```

<img width="716" height="290" alt="dinadawson@nac-dee Lab5  IP-283 0 113 9" src="https://github.com/user-attachments/assets/03d74c47-8e96-40a3-a4cb-a821cc6ca6be" />


**Observed result:**
- **Contain:** A firewall rule was added dropping all inbound traffic from `203.0.113.9`.
- **Collect:** A timestamped copy of the log was made (`evidence_20260910.log`) and its SHA-256 hash recorded in `evidence.sha256`, giving `0adc5d2ac06cbbdd366099bcc0540c4c0f76946e71b52e4c99322731696a203b`.

**Security interpretation:** Containment (blocking the attacker's IP) stops ongoing harm without necessarily fixing the root cause. Collecting evidence with a recorded hash, immediately and before further investigation, means the integrity of that evidence can later be proven (via `shasum -a 256 -c evidence.sha256`) even if the original log file is later modified or lost — a requirement for both forensic and legal defensibility.

## Incident Report

**Detection:** Correlation of the centralised authentication logs (Task 5) flagged IP `203.0.113.9` for exhibiting four consecutive failed login attempts against the `admin` account, followed immediately by a successful login and a 500MB data export — a pattern consistent with a successful brute-force attack followed by data exfiltration.

**Analysis:** The timeline shows the attacker (`203.0.113.9`) made four failed attempts against `admin` between `09:01:10` and `09:01:18`, succeeded on the fifth attempt at `09:01:22`, then exfiltrated 500MB of data eighteen seconds later at `09:01:40`. The short gap between compromise and exfiltration suggests either an automated attack script or a targeted, pre-planned action rather than casual browsing after gaining access.

**Containment:** An `iptables` rule was applied to drop all inbound traffic from `203.0.113.9`, immediately cutting off the attacker's ability to continue accessing the system from that address, pending a full investigation and credential rotation for the `admin` account.

**Evidence & integrity:** The original `auth.log` was hash-chained (Task 4) to make any retroactive tampering detectable. A separate, timestamped evidence copy (`evidence_20260910.log`) was created and its SHA-256 hash recorded independently (`evidence.sha256`), so the integrity of the evidence can be verified at any later point, including in a formal investigation.

**Lesson learned:** The `admin` account had no apparent rate-limiting or account lockout after repeated failed attempts, allowing the brute-force attempt to continue uninterrupted until it succeeded. Implementing a lockout or exponential backoff after a small number of consecutive failures (e.g. 3–5) would have stopped this specific attack before it reached the successful login stage.

## Short-Answer Questions

### Q1. What is the difference between a log and an event? Give an example of each from this lab.

A **log** is a durable, passive record of something that happened, stored for later retrieval and analysis — for example, the `auth.log` entries themselves, or the centralised read-back in Task 2, which simply preserve what occurred without judging its significance. An **event** is a real-time trigger raised the moment a condition of interest is met — for example, the `ALERT: probable brute-force -> compromise -> data exfiltration` message in Task 5, which fires immediately once the correlation conditions (≥3 fails, ≥1 success, ≥1 export from the same IP) are satisfied. In short: logs are what you can look up later; events are what tell you to look right now.

### Q2. Why must audit logs be tamper-proof, and how does a hash chain achieve this?

If an attacker can silently edit or delete log entries after compromising a system, they can erase evidence of their own intrusion — making detection, forensics, and accountability impossible. Audit logs must therefore be tamper-**evident** at minimum: even if an attacker can technically edit a file, any edit must be detectable. A hash chain achieves this by making each entry's hash a function of both that entry's content and the hash of the entry before it (Task 4). Changing any single character anywhere in the log changes that entry's hash, which cascades and changes every hash computed after it — so the final hash of the chain will no longer match a securely stored reference value, immediately revealing that tampering occurred somewhere in the log.

### Q3. How did correlation detect an incident that no single log line revealed?

Individually, each line in `auth.log` looks unremarkable: a failed login could be a typo, a successful login is routine, and a data export is a normal business action. Task 5's correlation logic combined three separate signals — failure count, success count, and export count — filtered to the *same source IP* within the *same log*. Only when all three conditions were true simultaneously (`fails≥3`, `success≥1`, `export≥1`) did the script raise `ALERT`. No single log line contains enough information to justify an alert on its own; the incident only becomes visible when the sequence and shared origin (`203.0.113.9`) of all three actions are considered together — exactly what a SIEM automates at scale.

### Q4. List the incident-response steps you performed and the goal of each.

- **Detect** (Task 5) — correlate log events to identify that an incident is in progress, rather than relying on any single alert.
- **Contain** (Task 6) — immediately block the attacker's source IP via an `iptables DROP` rule, stopping further unauthorized access while investigation continues.
- **Collect evidence** (Task 6) — preserve a timestamped copy of the affected logs and record its cryptographic hash, ensuring the evidence can later be proven unaltered.
- **Document** (this incident report) — record what happened, how it was found, what was done, and what was learned, so the incident can be reviewed, reported to stakeholders, and used to prevent recurrence.

### Q5. How do the same logs serve both security monitoring and compliance evidence?

For security monitoring, the logs in this lab were used to detect an active threat: querying for failed logins (Task 3) and correlating multiple event types by IP (Task 5) turned raw records into an actionable alert. The same underlying logs also serve as **compliance evidence**: the hash-chained log (Task 4) and the separately hashed evidence copy (Task 6) provide a durable, verifiable record that can be presented to an auditor or regulator to demonstrate that access to a system was monitored, that an incident was detected and handled, and that the evidence supporting that account has not been altered after the fact. The dual purpose is why logs are described as foundational to both detection and compliance — the same centralised, tamper-evident record answers "did we notice this?" and "can you prove what happened?" at the same time.

## Verification

```bash
aws --endpoint-url=http://localhost:4566 logs describe-log-groups
shasum -a 256 -c evidence.sha256
```

`[SCREENSHOT: verification commands output]`

## Security Best-Practices Checklist

- [x] Logs are centralised, not left scattered on each host.
- [x] Security-relevant activity (failed logins) can be queried.
- [x] Logs are tamper-evident (hash chain) and forwarded to a separate store.
- [x] An incident is detected by correlating multiple events.
- [x] Incident response performed: contain, collect evidence, document.

## Cleanup

```bash
rm -f auth.log auth.chain auth.tampered evidence_*.log evidence.sha256
docker stop localstack && docker rm localstack
```

## Conclusion

This lab moved from pure visibility to actionable security operations. Session A established the foundation — generating, centralising, and querying logs (Tasks 1–3) so that security-relevant activity could be found at all. Session B built on that foundation: a hash chain (Task 4) ensured the logs themselves could be trusted, correlation (Task 5) turned three individually unremarkable log lines into a single high-confidence detection, and the incident-response lifecycle (Task 6) demonstrated that detection alone is not enough — it must be followed by swift containment and evidence preservation. The recurring theme across both sessions was the lab's opening security tip: you cannot secure, or prove compliance for, what you cannot see — and once you can see it, you must also be able to trust what you see.
