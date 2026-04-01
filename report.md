# Log Analysis Report

## 1. Overview:

This project was created to analyze authentication and system log data for signs of suspicious activity. The tool was designed to identify repeated failed logins, suspicious IP behavior, privilege escalation events, and other indicators of possible compromise.

## 2. Log Source:

The dataset analyzed was "sample_log.txt", a log file provided with the assignment instructions. It contains structured entries with the following fields: timestamp, event type, username, source ip and message.

## 3. Parsing and Data Modeling:

First the file is read line by line. The lines are stripped of white space. Each field is split by tab separation. Then the data normalized, modeled added to a dictionary data structure and returned.

## 4. Detection Logic:

Detection logic was then applied in several areas:

- Failed login detection counted repeated "AUTH_FAIL" events, filtered by number of occurences per user and returned a dictionary count of usernames/ip pairs.
- Suspicious IP detection identified IPs with repeated failed login attempts, successful access after repeated failures, or privilege escalation activity. A dictionary data structure was also used in these cases to model and store returned data. The data then was compared and correlated with previously flagged records.
- Privilege escalation detection looked for "PRIV_CHANGE" events and filtered them by high-risk keywords such as "sudo", "administrator", "root", "elevated", and "privilege".
- Suspicious username detection flags usernames containing malformed or unusual character patterns.
  which may indicate bot activity, fuzzing attempts or invalid credential submissions.

## 5. Findings:

The analysis processed 1234 log records. It identified 169 failed login attempts, 4 suspicious IPs, 95 privilege escalation attempts, and 8 suspicious usernames. One external IP in particular, "51.185.130.223", stood out because it was tied to a high volume of failed login attempts, malformed usernames, and later successful access to multiple accounts. Another suspicious IP, "10.0.2.87", was associated with successful privilege escalation activity. These patterns suggest possible brute-force behavior, account compromise, and privilege abuse.

## 6. Recommendations:

Recommended actions include:

- investigate the suspicious IP addresses, especially "51.185.130.223"
- review accounts associated with successful access after repeated failures
- review privilege escalation events for unauthorized changes
- reset affected credentials and enable MFA where possible
- improve alerting for repeated failures, abnormal usernames, and privilege changes

## 7. Reflection:

This project worked well for practicing file reading, parsing, dictionaries, loops, and detection logic in Python. As well as getting in to the "analyst mindset". I think I struggled more with that than the actual code. One challenge was deciding how to structure the return values from the detection functions and how to present the findings clearly in the report. If I continued improving the project, I would add stronger error handling and csv export. I may also tighten up, or add some additional, filtering logic for greater precision. It would also be nice to make some the filtering thresholds adjustable via the cli.
