from data_parser import *
from detection import *
from summary import *
import argparse

def main():

    def get_file_path():
        cli_parser = argparse.ArgumentParser()
        
        cli_parser.add_argument("filename", nargs="?")

        args = cli_parser.parse_args()

        return args.filename


    def user_interface():
        while True:

            print("Welcome to Log Analyzer\n")
            print("Please make a selection:\n")
            print("1. Use Default Log File\n")
            print("2. Enter Custom Log File\n")
            print("3. Quit\n")

            user_input = input(": ")
        
            if user_input == "1":
                return "sample_log.txt"
            elif user_input == "2":
                file_path = input("Please provide the name of the file: ")
                return file_path
            elif user_input == "3":
                return None
            else:
                print("That is an invalid selection, please choose 1, 2 or 3")

    file_path = get_file_path()
    2
    if not file_path:

        file_path = user_interface()
        if file_path is None:
            quit()

    cleaned_data = read_and_clean_data(file_path)

    modeled_data = model_data(cleaned_data)

    total_records = len(modeled_data)

    failed_login_data = find_failed_logins(modeled_data)

    total_failed_logins = failed_login_data["count"]

    failed_login_records = failed_login_data["records"]

    repeat_failed_logins = failed_login_data["repeat_offenders"]

    priv_esc = find_priv_esc(modeled_data)

    flagged_ips, suspicious_ips_record = find_suspicious_ips(modeled_data)

    success_after_failure = find_success_after_failure(modeled_data, flagged_ips)

    priv_esc_success = find_priv_esc_success(modeled_data, flagged_ips)

    suspicious_users, suspicious_users_record = find_suspicious_users(modeled_data)

    priv_change_filtered = priv_change_filter(modeled_data)

    total__flagged_indicators = total_flagged_indicators(failed_login_records, priv_esc, suspicious_ips_record, suspicious_users_record)


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
        "priv_change_filtered": priv_change_filtered,
        "total_flagged_indicators": total__flagged_indicators
    }

    summary = build_report(report_data)

    def cli_summary_format():
        while True:

            print("How would you like your output formatted?\n")
            print("1. To Console\n")
            print("2. To a Text File\n")
            print("3. To a Markdown File\n")

            output_format = input(": ")

            if output_format == "1":
                print_summary_console(summary)
                break
            elif output_format == "2":
                write_report_txt(summary)
                print("Your summary has been written to root/summary.txt\n")
                break
            elif output_format == "3":
                write_summary_md(summary)
                print("Your summary has been written to root/summary.md\n")
                break
            else:
                print("That is not a valid selection, please choose 1, 2 or 3")

    cli_summary_format()


if __name__ == "__main__":
    main()