from data_parser import *
from detection import *
from report import *

def main():
    
    file_path = "sample_log.txt"

    cleaned_data = read_and_clean_data(file_path)

    modeled_data = model_data(cleaned_data)

    total_records = len(modeled_data)

    failed_login_data = find_failed_logins(modeled_data)

    total_failed_logins = failed_login_data["count"]

    failed_login_records = failed_login_data["records"]

    repeat_failed_logins = failed_login_data["repeat_offenders"]

    priv_esc = find_priv_esc(modeled_data)

    flagged_ips = find_suspicious_ips(modeled_data)

    success_after_failure = find_success_after_failure(modeled_data, flagged_ips)

    priv_esc_success = find_priv_esc_success(modeled_data, flagged_ips)

    suspicious_users = find_suspicious_users(modeled_data)

    priv_change_filtered = priv_change_filter(modeled_data)


    report_data = {
        "failed_login_records": failed_login_records,
        "total_failed_logins": total_failed_logins,
        "priv_esc": priv_esc,
        "flagged_ips": flagged_ips,
        "success_after_failure": success_after_failure,
        "priv_esc_success": priv_esc_success,
        "total_records": total_records,
        "suspicious_users": suspicious_users,
        "repeat_failed_logins": repeat_failed_logins,
        "priv_change_filtered": priv_change_filtered
    }

    report = build_report_txt(report_data)

    print(report)


if __name__ == "__main__":
    main()