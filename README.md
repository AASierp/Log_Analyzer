# Python Log Analyzer for Suspicious Authentication Activity

## Purpose

This project analyzes authentication logs for suspicious activity such as repeated failed logins, suspicious IP behavior, suspicious usernames, and privilege escalation events.

## Required Files

- log_analyzer.py
- sample_log.txt
- detection.py
- data_parser.py
- report.py

## How to Run

Run the program from the terminal:

python log_analyzer.py sample_log.txt

You may also hardcode the filename if needed for a beginner-friendly version.

## Detection Logic

This tool checks for:

- repeated failed login attempts
- suspicious IP activity
- privilege escalation events
- suspicious usernames
- successful access after repeated failed attempts

## Output

The program prints:

- a summary report
- a flagged events section

## Optional Features

Optional features implemented:

- privilege escalation risk filtering
- suspicious username detection
- correlation of suspicious IPs with successful login or privilege escalation
