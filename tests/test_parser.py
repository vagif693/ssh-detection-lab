from datetime import datetime

from sshlab.parser import parse_line


def test_failed_password_for_invalid_user():
    line = ("Dec 10 06:55:48 LabSZ sshd[24200]: Failed password for invalid user "
            "webmaster from 173.234.31.186 port 38926 ssh2")
    event = parse_line(line)
    assert event is not None
    assert event.event_type == "failed_password"
    assert event.user == "webmaster"
    assert event.src_ip == "173.234.31.186"
    assert event.port == 38926
    assert event.timestamp == datetime(2024, 12, 10, 6, 55, 48)


def test_failed_password_for_real_user():
    line = ("Dec 10 07:11:42 LabSZ sshd[24224]: Failed password for root "
            "from 112.95.230.3 port 49992 ssh2")
    event = parse_line(line)
    assert event is not None
    assert event.event_type == "failed_password"
    assert event.user == "root"


def test_accepted_login():
    line = ("Dec 10 09:32:20 LabSZ sshd[24680]: Accepted password for fztu "
            "from 119.137.62.142 port 49116 ssh2")
    event = parse_line(line)
    assert event is not None
    assert event.event_type == "accepted"
    assert event.user == "fztu"


def test_invalid_user_without_port():
    line = "Dec 10 06:55:46 LabSZ sshd[24200]: Invalid user webmaster from 173.234.31.186"
    event = parse_line(line)
    assert event is not None
    assert event.event_type == "invalid_user"
    assert event.port is None


def test_noise_line_is_skipped():
    line = ("Dec 10 06:55:46 LabSZ sshd[24200]: pam_unix(sshd:auth): check pass; "
            "user unknown")
    assert parse_line(line) is None


def test_garbage_line_is_skipped():
    assert parse_line("this is not a log line") is None


def test_repeated_message_counts_every_attempt():
    line = ("Dec 10 07:13:56 LabSZ sshd[24227]: message repeated 5 times: "
            "[ Failed password for root from 5.36.59.76 port 42393 ssh2]")
    event = parse_line(line)
    assert event is not None
    assert event.event_type == "failed_password"
    assert event.user == "root"
    assert event.count == 5


def test_username_with_leading_space():
    line = ("Dec 10 08:24:35 LabSZ sshd[24361]: Failed password for invalid user "
            " 0101 from 5.188.10.180 port 36279 ssh2")
    event = parse_line(line)
    assert event is not None
    assert event.user == " 0101"
    assert event.src_ip == "5.188.10.180"
