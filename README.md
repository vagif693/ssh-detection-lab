# SSH Detection Lab

A Python tool that reads real SSH authentication logs, detects brute-force attacks with tested rules mapped to MITRE ATT&CK, rates their severity, and keeps the full history in SQLite.

Built and validated on a real, unmodified 2,000-line OpenSSH log from a server under attack.

## Example

```
$ sshlab data/OpenSSH_2k.log
634 events parsed, 1366 lines skipped
634 new events stored, 0 already in the database
Database now holds 634 events and 11 alerts
  [CRITICAL] 183.62.140.253   peak 279 in 10 min, 286 total, 10 usernames
  [HIGH    ] 187.141.143.180  peak  80 in 10 min,  80 total, 28 usernames
  [HIGH    ] 103.99.0.122     peak  30 in 10 min,  46 total, 19 usernames
  [HIGH    ] 112.95.230.3     peak  26 in 10 min,  26 total, 3 usernames
  [MEDIUM  ] 5.188.10.180     peak  18 in 10 min,  18 total, 7 usernames
  ...
Report written to report.json
```

The worst attacker made 279 password attempts in 10 minutes, roughly one every two seconds: clearly automated.

## How it works

```
auth log  ->  parser  ->  events (SQLite)  ->  detection rules  ->  alerts (SQLite)  ->  JSON report
```

1. **Parse.** Each sshd line becomes a structured event: time, host, process, event type, user, source IP, port, and the original line kept as evidence. Lines that are not authentication events are skipped and counted, never silently lost.
2. **Store.** Events go into SQLite. Each line is fingerprinted with SHA-256, so ingesting the same log twice adds nothing.
3. **Detect.** Rules run over the full stored history, so an attack split across several log files is still caught.
4. **Report.** Alerts are saved (updated if the attack continued) and written to a JSON report with evidence lines.

## Detection rules

| Rule | Logic | Severity | MITRE ATT&CK |
| --- | --- | --- | --- |
| SSH brute force | 5+ failed passwords from one IP within any 10-minute window | MEDIUM 5+, HIGH 20+, CRITICAL 100+ | [T1110.001 Password Guessing](https://attack.mitre.org/techniques/T1110/001/) |

**Why a sliding window and not a total count:** a user who mistypes a password six times over a day is not an attack; 279 guesses in 10 minutes is. Severity is based on the peak inside one window, because speed is what separates automation from people.

**False positives covered by tests:** failures below the threshold, failures spread over hours, successful logins mixed in, and two IPs whose failures must not be added together.

## Lessons from real data

Comparing the parser's counts with `grep` showed it was missing attempts. Two real-world cases caused it:

- **Compressed repeats.** Syslog writes `message repeated 5 times: [ Failed password ... ]` as a single line. Each such line now counts as five attempts.
- **Odd usernames.** Attackers sent usernames beginning with a space (`" 0101"`), which a simple `\S+` pattern cannot match.

Fixing both raised the count from 517 to 528 failed attempts, matching the raw log exactly. Both cases have regression tests.

Syslog timestamps carry no year, so the parser assumes one (`DEFAULT_YEAR`). Windows that cross New Year are a known limitation.

## Security design

- **Parameterised SQL everywhere.** User-controlled values never become SQL text. A test passes `x' OR '1'='1` as an IP filter and confirms it returns nothing.
- **Allow-listed identifiers.** The one query that needs a table name checks it against an allow-list, because placeholders cannot be used for identifiers.
- **Transactions.** Each batch is saved completely or not at all.
- **Immutable evidence.** Events and alerts are frozen dataclasses, and every alert keeps the original log lines that triggered it.
- **No secrets in the repository.** Databases, reports and `.env` files are ignored by Git.

## Quick start

```
git clone https://github.com/vagif693/ssh-detection-lab.git
cd ssh-detection-lab
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
sshlab data/OpenSSH_2k.log
```

Options: `--window` (minutes, default 10), `--threshold` (default 5), `--db` (default `sshlab.db`), `--output` (default `report.json`). Run `sshlab --help` for details.

## Tests

```
pytest -v
```

22 tests cover every log-line shape, the detection rule's true and false positives, storage idempotency, SQL-injection resistance, and data persistence.

## Project structure

```
src/sshlab/
  parser.py    log lines -> events
  rules.py     detection rules and severity
  store.py     SQLite storage
  report.py    JSON report
  cli.py       the sshlab command
tests/         pytest suite
data/          real OpenSSH log sample (Loghub)
```

## Roadmap

- [x] Parser with real-log edge cases
- [x] Brute-force rule with sliding window
- [x] SQLite storage with idempotent ingest
- [ ] Read-only API with API-key authentication
- [ ] Compromised-account rule (failures followed by success) and password-spraying rule
- [ ] CI with pytest, Bandit, Semgrep and pip-audit
- [ ] Docker

## Data

`data/OpenSSH_2k.log` comes from the [Loghub](https://github.com/logpai/loghub) dataset collection, used for study and research.

## License

MIT
