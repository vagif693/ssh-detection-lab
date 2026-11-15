# SSH Detection Lab

A Python tool that reads real SSH authentication logs, detects brute force, password spraying and compromised accounts with tested rules mapped to MITRE ATT&CK, keeps the history in SQLite, and serves alerts through an API protected by an API key.

Built and validated on a real, unmodified 2,000-line OpenSSH log from a server under attack.

## Example

The sample log in `data/sample_attack.log` contains three planted scenarios: a user who mistypes twice, a brute force that succeeds, and slow password spraying.

````
$ sshlab data/sample_attack.log --db sample.db
36 events parsed, 0 lines skipped
36 new events stored, 0 already in the database
Database now holds 36 events and 3 alerts
  [CRITICAL] ssh_compromised_account  T1078      203.0.113.50       8 attempts, 1 usernames
  [HIGH    ] ssh_password_spraying    T1110.003  198.51.100.23     12 attempts, 12 usernames
  [MEDIUM  ] ssh_brute_force          T1110.001  203.0.113.50       8 attempts, 1 usernames
````

The user who mistyped twice raises no alert. The slow spraying (one guess every 3 minutes) is caught even though it never triggers the brute-force rule.

## Detection rules

| Rule | Logic | Severity | MITRE ATT&CK |
| --- | --- | --- | --- |
| Compromised account | 3+ failed passwords, then a successful login from the same IP within 1 hour | CRITICAL | [T1078 Valid Accounts](https://attack.mitre.org/techniques/T1078/) |
| Password spraying | 10+ different usernames from one IP within 1 hour, 3 or fewer guesses each | HIGH | [T1110.003 Password Spraying](https://attack.mitre.org/techniques/T1110/003/) |
| Brute force | 5+ failed passwords from one IP within any 10-minute window | MEDIUM 5+, HIGH 20+, CRITICAL 100+ | [T1110.001 Password Guessing](https://attack.mitre.org/techniques/T1110/001/) |

**Why sliding windows and not totals:** a user who mistypes a password six times over a day is not an attack; 279 guesses in 10 minutes is.

**Why two password rules:** a careful attacker sends one guess every few minutes to stay under brute-force thresholds. The spraying rule looks at how many *different* usernames are tried, so it catches that pattern. A per-username limit stops it from double-counting ordinary brute force.

**False positives covered by tests:** failures below thresholds, failures spread over hours, typos followed by a successful login, success from a different IP, success hours after the failures, and one username guessed many times.

## Results on real data

On the Loghub OpenSSH log, the tool raises 13 alerts across 11 attacking IPs:

- `183.62.140.253` made 279 attempts in 10 minutes, about one every 2 seconds (CRITICAL brute force).
- `187.141.143.180` tried 28 usernames with about 3 guesses each in 7 minutes, and is flagged for both brute force and password spraying.
- The log's only successful login has no failures before it, and the compromised-account rule correctly stays silent.

## Lessons from real data

Comparing the parser's counts with `grep` showed it was missing attempts:

- **Compressed repeats.** Syslog writes `message repeated 5 times: [ Failed password ... ]` as a single line. Each such line now counts as five attempts.
- **Odd usernames.** Attackers sent usernames beginning with a space (`" 0101"`), which a simple `\S+` pattern cannot match.

Fixing both raised the count from 517 to 528 failed attempts, matching the raw log exactly. Both cases have regression tests.

Syslog timestamps carry no year, so the parser assumes one (`DEFAULT_YEAR`). Windows that cross New Year are a known limitation.

## API

A read-only FastAPI service exposes the stored alerts.

````
export SSHLAB_API_KEY=$(python -c "import secrets; print(secrets.token_urlsafe(32))")
uvicorn sshlab.api:app
curl -H "X-API-Key: $SSHLAB_API_KEY" "localhost:8000/alerts?severity=CRITICAL"
````

| Endpoint | Returns | Auth |
| --- | --- | --- |
| `GET /health` | Service status | None |
| `GET /alerts?severity=&limit=` | Alerts, most severe first (limit 1–500) | API key |
| `GET /alerts/{id}` | One alert with its evidence lines | API key |
| `GET /ips/{ip}/timeline` | Every event from one IP, in time order | API key |

Interactive documentation is generated at `/docs`.

## Security design

- **API key in a header**, read from an environment variable and compared with `secrets.compare_digest` to prevent timing attacks.
- **Fails closed:** if no key is configured, protected endpoints return 503 instead of serving data.
- **Input validation:** severity is an enum, `limit` is capped at 500, IPs must parse as real addresses; anything else gets 422 before reaching the database.
- **Response models** define exactly which fields leave the API.
- **Read-only API:** no upload, edit or delete endpoints.
- **Parameterised SQL everywhere.** A test passes `x' OR '1'='1` as an IP filter and confirms it returns nothing.
- **Allow-listed identifiers** where placeholders cannot be used (table names).
- **Idempotent ingest:** each log line is fingerprinted with SHA-256, so the same log can be loaded twice safely.
- **No secrets in the repository.** Databases, reports and `.env` files are ignored by Git.

## Quick start

````
git clone https://github.com/vagif693/ssh-detection-lab.git
cd ssh-detection-lab
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
sshlab data/OpenSSH_2k.log
````

Options: `--window` (minutes, default 10), `--threshold` (default 5), `--db` (default `sshlab.db`), `--output` (default `report.json`).

## Tests

````
pytest -v
````

45 tests cover every log-line shape, true and false positives for all three rules, storage idempotency, SQL-injection resistance, and API authentication and input validation.

## Project structure

````
src/sshlab/
  parser.py    log lines -> events
  rules.py     brute force, password spraying, compromised account
  store.py     SQLite storage
  report.py    JSON report
  api.py       read-only API with API-key auth
  cli.py       the sshlab command
tests/         pytest suite
data/          real OpenSSH log (Loghub) and a sample attack log
````

## Roadmap

- [x] Parser with real-log edge cases
- [x] Brute-force, password-spraying and compromised-account rules
- [x] SQLite storage with idempotent ingest
- [x] Read-only API with API-key authentication
- [ ] CI with pytest, Bandit, Semgrep and pip-audit
- [ ] Docker
- [ ] Incident report for a single IP

## Data

`data/OpenSSH_2k.log` comes from the [Loghub](https://github.com/logpai/loghub) dataset collection, used for study and research. `data/sample_attack.log` is synthetic and uses documentation IP ranges (RFC 5737).

## License

MIT
