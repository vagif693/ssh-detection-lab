# Incident report: 203.0.113.50

Generated 2026-11-16T18:00:33 by ssh-detection-lab.

## Summary

**Verdict:** Account compromised: failed guesses were followed by a successful login.

| | |
| --- | --- |
| Highest severity | CRITICAL |
| First seen | 2024-01-15 09:15:10 |
| Last seen | 2024-01-15 09:15:52 |
| Duration | 0:00:42 |
| Failed password attempts | 8 |
| Successful logins | 1 |
| Usernames tried | 1 |

## Alerts

| Severity | Rule | ATT&CK | Attempts | First seen | Last seen |
| --- | --- | --- | --- | --- | --- |
| CRITICAL | ssh_compromised_account | T1078 | 8 | 2024-01-15 09:15:10 | 2024-01-15 09:15:52 |
| MEDIUM | ssh_brute_force | T1110.001 | 8 | 2024-01-15 09:15:10 | 2024-01-15 09:15:38 |

## Timeline

| Time | Event | User | Port |
| --- | --- | --- | --- |
| 2024-01-15 09:15:10 | Failed password | `admin` | 41000 |
| 2024-01-15 09:15:14 | Failed password | `admin` | 41001 |
| 2024-01-15 09:15:18 | Failed password | `admin` | 41002 |
| 2024-01-15 09:15:22 | Failed password | `admin` | 41003 |
| 2024-01-15 09:15:26 | Failed password | `admin` | 41004 |
| 2024-01-15 09:15:30 | Failed password | `admin` | 41005 |
| 2024-01-15 09:15:34 | Failed password | `admin` | 41006 |
| 2024-01-15 09:15:38 | Failed password | `admin` | 41007 |
| 2024-01-15 09:15:52 | **SUCCESSFUL LOGIN** | `admin` | 41008 |

## Recommended response

1. Block the source IP at the firewall (or with fail2ban) and watch for the same pattern from new IPs.
2. Treat `admin` as compromised: reset the password and end all active sessions.
3. Review what happened after the login: shell history, sudo use, files changed, outbound connections.
4. Check for persistence: new users, `~/.ssh/authorized_keys`, cron jobs, systemd services.
5. Rotate any secrets stored on or reachable from this host.
6. Disable SSH password authentication and require keys, so guessing cannot succeed.
7. Confirm no other IP logged in successfully during the same period.

## Evidence

Original log lines that triggered the alerts:

```
Jan 15 09:15:10 lab01 sshd[4200]: Failed password for admin from 203.0.113.50 port 41000 ssh2
Jan 15 09:15:14 lab01 sshd[4201]: Failed password for admin from 203.0.113.50 port 41001 ssh2
Jan 15 09:15:18 lab01 sshd[4202]: Failed password for admin from 203.0.113.50 port 41002 ssh2
Jan 15 09:15:22 lab01 sshd[4203]: Failed password for admin from 203.0.113.50 port 41003 ssh2
Jan 15 09:15:26 lab01 sshd[4204]: Failed password for admin from 203.0.113.50 port 41004 ssh2
Jan 15 09:15:30 lab01 sshd[4205]: Failed password for admin from 203.0.113.50 port 41005 ssh2
Jan 15 09:15:34 lab01 sshd[4206]: Failed password for admin from 203.0.113.50 port 41006 ssh2
Jan 15 09:15:38 lab01 sshd[4207]: Failed password for admin from 203.0.113.50 port 41007 ssh2
Jan 15 09:15:52 lab01 sshd[4208]: Accepted password for admin from 203.0.113.50 port 41008 ssh2
```
