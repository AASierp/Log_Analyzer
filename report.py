

def build_report_txt(report_data): 
    total_records = report_data.get("total_records", 0) #int
    total_failed_logins = report_data.get("total_failed_logins", 0) #int
    failed_login_records = report_data.get("failed_login_records", []) #list of full records(dict)
    repeat_failed_logins = report_data.get("repeat_failed_logins", {}) #dict
    priv_esc = report_data.get("priv_esc", []) #list full records (dict)
    flagged_ips = report_data.get("flagged_ips", {}) #dict
    priv_esc_success = report_data.get("priv_esc_success", {}) #dict
    suspicious_users = report_data.get("suspicious_users", {}) #dict
    potential_breach = report_data.get("success_after_failure", {}) #dict
    priv_change_filtered = report_data.get("priv_change_filtered", ([], [])) #tuple, 2 lists
    
    repeat_failed_logins_formatted = ""
    for key, value in repeat_failed_logins.items():
        user, ip = key
        repeat_failed_logins_formatted += f"          - User: {user}, IP: {ip}, Failed Attempts: {value}\n"

    flagged_ips_formatted = ""
    for key, value in flagged_ips.items():
        flagged_ips_formatted += f"          - IP: {key}, Failed Attempts: {value}\n"

    suspicious_users_formatted = ""
    for key, value in suspicious_users.items():
        user, ip, auth = key
        suspicious_users_formatted += f"          - User: {user}, IP: {ip}, AUTH: {auth}, Number of Times Attempted: {value}\n"

    potential_breach_formatted = ""
    for key, value in potential_breach.items():
        ip = key
        for i in value:
            potential_breach_formatted += f"          - IP: {ip}, User: {i}\n"

    priv_esc_success_formatted = ""
    for key, value in priv_esc_success.items():
        ip, user = key
        priv_esc_success_formatted += f"        - IP: {ip}, User: {user}, Auth: {value}\n"

    high, low = priv_change_filtered
    
    


    totals = f"""
    Log Analysis Summary Report
    ============================

    Records Scanned: {total_records}

    Failed Login Attempts: {total_failed_logins}

    Suspicious IPs: {len(flagged_ips)}

    Privilege Escalation Attempts: {len(priv_esc)}

    Suspicious Users: {len(suspicious_users)}

    Combined Flag Indicators: {total_failed_logins + len(flagged_ips) + len(priv_esc) + len(suspicious_users)}


    Flagged Events
    ============================

    Failed Login Activity:

        Repeated failed login attempts may indicate brute forcing, partial credential theft or password spraying.

        Total failed logins: {total_failed_logins}

        Example Record: {failed_login_records[0], None}

        Users with greater than five failed attempts:\n\n{repeat_failed_logins_formatted}

    Suspicious IPs:

        Repeated failed attempts from the same IP but utilizing different credentials, particularly from an external source, can 
        indicate malicious behavior. IPs that achieved access after five failed attempts or that achieved a privilege change,
        were deemed suspicious and added to the following list.

        IPs with many failed login attempts:\n\n{flagged_ips_formatted}

    Suspicious Users:

        User names that contain unusual characters or appear malformed may indicate bot activity, fuzzing attempts or SQL injection.
        The following names were flagged based on unusual character usage and the absence of typically required characters.

        Abnormal User Names Detected:\n\n{suspicious_users_formatted}

    Privilege Escalation Activity:

        Total Privilege Escalations: {len(priv_esc)}
        High-Risk Escalations: {len(high)}
        Low-Risk Escalations: {len(low)}

    Potential Breach Indicators:

        These successful attempts, when viewed in the context of earlier findings, seem to indicate a possible breach in security.
        One IP in particular (51.185.130.223) can be tracked through the records as being associated with particularly malicious behavior.
        The notably external IP in question appears to have gained access to four user accounts, while also logging numerous failed attempts
        under other usernames, eighty in total. From here, the user may have moved laterally and gained access to other accounts and achieved
        privilege escalation in at least one case, as noted below. This warrants additional attention and investigation.

        IPs/Users that achieved access in addition to many failed attempts:\n\n{potential_breach_formatted}

        IPs/Users that achieved privilege escalation:\n\n{priv_esc_success_formatted}

    """ 

    return totals