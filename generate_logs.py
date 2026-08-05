from datetime import datetime
import argparse


def fmt_ts(dt): 

    # Format a datetime object into a syslog-style timestamp like 'Jul 25 09:14:32' (fmt_ts  = format timestamp)
    # the `%b` code in strftime means "abbreviated month name"
    # instead of using the `%e` code in strftime, we manually format the day with space-padding using `{dt.day:2d}` in an f-string 
    return f"{dt.strftime('%b')} {dt.day:2d} {dt.strftime('%H:%M:%S')}"



def failed_password(user, ip, port):
    # Given a `user`, `ip`, and `port`, returns a string formated like a standard sys-log failed password attempt
    return f"Failed password for {user} from {ip} port {port} ssh2"

def main():
    parser = argparse.ArgumentParser(description="the parser for the command-line args when a SOC analyst uses this tool to triage auth logs")
    parser.add_argument(
        "--scenario", 
        required=True,
        choices=["benign", "brute_force", "credential_stuffing", "privilege_escalation", "off_hours", "lateral_movement", "mixed"],
        help="a type of potential threat scenario which the synthetic auth logs will reflect once generated"
    )
    parser.add_argument(
        "--output",
        required=True, 
        type=str,
        help="the filepath in which synthesized auth logs will be output to"
    )
    parser.add_argument(
        "--lines",
        required=False,
        type=int,
        default=5000,        
        help="the desired number of synthetic auth log lines to be generated and output into the log file"
    )
    parser.add_argument(
        "--seed", 
        required=False,            type=int,
        default=None
    )
    args = parser.parse_args()
    print(args)
if __name__ == "__main__":
    main()
    