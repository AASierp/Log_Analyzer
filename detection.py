from data_parser import *
import re

def find_failed_logins(modeled_data):
    failed_login_attempts = []
    failed_users_count = {}
    repeat_failed_users = {}
    for record in modeled_data:
        if record.get("AUTH") == "AUTH_FAIL":
            failed_login_attempts.append(record)
    
    for record in failed_login_attempts:
        user = record.get("User")
        ip = record.get("IP")
        key = (user, ip)
        failed_users_count[key] = failed_users_count.get(key, 0) + 1
    for key, value in failed_users_count.items():
        if value > 5:
            repeat_failed_users[key] = value
        

    total_failed_logins = len(failed_login_attempts)

    # with open("test_output/failed_logins.txt", "w") as file:
    #     file.write(f"Count: {total_failed_logins}\n")
    #     for item in failed_login_attempts:
    #         file.write(f"Record: {item}\n")

    return {"count": total_failed_logins, "records": failed_login_attempts, "repeat_offenders": repeat_failed_users}
    
        
def find_priv_esc(modeled_data):
    escalated_users = []
    for record in modeled_data:
        if record.get("AUTH") == "PRIV_CHANGE":
            escalated_users.append(record)
    
    return escalated_users

    # with open("test_output/priv_escalation.txt", "w") as file:
    #     for item in escalated_users:
    #         file.write(str(item) + '\n')

    
def find_suspicious_ips(modeled_data):
    suspicious_ips = {}
    flagged_suspicious_ips = {}
    suspicious_ips_whole_record = []

    for record in modeled_data:
        if record.get("AUTH") == "AUTH_FAIL" or record.get("AUTH") == "PRIV_CHANGE" :
            key = record.get("IP")
            suspicious_ips[key] = suspicious_ips.get(key, 0) + 1
            suspicious_ips_whole_record.append(record)
    for key, count in suspicious_ips.items():
        if count > 5:
            flagged_suspicious_ips[key] = suspicious_ips.get(key, count)

    return flagged_suspicious_ips, suspicious_ips_whole_record

    # with open("test_output/sus_ips.txt", "w") as file:
    #     for key, count in flagged_suspicious_ips.items():
    #         file.write(f" IP: {key}, Count: {count}\n")

def find_success_after_failure(modeled_data, flagged_suspicious_ips):
    breach_confirmed = {} #this should be a dict of ips and associated accounts that ip gained access to.

    for record in modeled_data:
        ip = record.get("IP")
        if ip in flagged_suspicious_ips:
            auth = record.get("AUTH")
            users = record.get("User")
            if auth == "AUTH_SUCCESS":
                if ip not in breach_confirmed:
                    breach_confirmed[ip] = set()
                breach_confirmed[ip].add(users)

    # with open("test_output/breach_confirmed_list", "w") as file:
    #     for ip, users in breach_confirmed.items():
    #         file.write("IPs and Associated Users that successfully logged in after multiple failures \n")
    #         file.write(f"  IP: {ip}\n")
    #         for user in users:
    #             file.write(f"    - User: {user}\n")

    return breach_confirmed

def find_priv_esc_success(modeled_data, flagged_suspicious_ips):
    breach_with_priv_esc = {}

    for record in modeled_data:
        auth = record.get("AUTH")
        ip = record.get("IP")
        user = record.get("User")
        message = record.get("Message")
        key = (ip, user, auth)
        if ip in flagged_suspicious_ips and auth == "PRIV_CHANGE":
            breach_with_priv_esc[key] = message
    
    with open("test_output/breach_with_priv_esc.txt", "w")as file:
        for ip, auth in breach_with_priv_esc.items():
            file.write(f"IP: {ip} - AUTH: {auth}\n")
    
    return breach_with_priv_esc

def priv_change_filter(modeled_data):
    
    high_risk = []
    low_risk = []

    message_keyword_options = ["sudo", "administrator", "root", "elevated", "privilege", "admin", "added"]

    for record in modeled_data:
        auth = record.get("AUTH")
        message = record.get("Message", "").lower()

        if auth == "PRIV_CHANGE" and any(keyword in message for keyword in message_keyword_options):
            high_risk.append(record)
        elif auth == "PRIV_CHANGE" and not any(keyword in message for keyword in message_keyword_options):
            low_risk.append(record)

    with open("test_output/filtered_by_risk.txt", "w") as file:
        for record in high_risk:
            file.write("HIGH RISK" + " " + str(record) + "\n")
        for record in low_risk:
            file.write("LOW RISK" + " " + str(record) + "\n")

    return high_risk, low_risk

def find_suspicious_users(modeled_data):
    suspicious_users = {}
    suspicious_users_record = []
    for record in modeled_data:
        user = record.get("User")
        ip = record.get("IP")
        auth = record.get("AUTH")
        key = (user, ip, auth)
        if not re.fullmatch(r"(?!.*@.*@)[A-Za-z0-9_.@-]+", user):
            suspicious_users[key] = suspicious_users.get(key, 0) + 1
            suspicious_users_record.append(record)

    # with open("test_output/sus_users.txt", "w") as file:
    #     for key, value in suspicious_users.items():
    #         file.write(f"{key}: {value}\n")

    return suspicious_users, suspicious_users_record

def total_flagged_indicators(failed_login_attempts, escalated_users, suspicious_ips_whole_record, suspicious_users_whole_record ):
    unique_records = set()
    total_records = []
    total_records.extend(failed_login_attempts)
    total_records.extend(escalated_users)
    total_records.extend(suspicious_ips_whole_record)
    total_records.extend(suspicious_users_whole_record)

    for record in total_records:
        record_key = (
            record.get("Timestamp"),
            record.get("AUTH"),
            record.get("User"),
            record.get("IP"),
            record.get("Message"),
        )
        
        unique_records.add(record_key)
    
    return len(unique_records)