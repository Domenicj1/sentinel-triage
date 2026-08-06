from datetime import datetime, timedelta
import argparse
import random

# Format Timestamp function
def fmt_ts(dt): 

    # Format a datetime object into a syslog-style timestamp like 'Jul 25 09:14:32' (fmt_ts  = format timestamp)
    # the `%b` code in strftime means "abbreviated month name"
    # instead of using the `%e` code in strftime, we manually format the day with space-padding using `{dt.day:2d}` in an f-string 
    return f"{dt.strftime('%b')} {dt.day:2d} {dt.strftime('%H:%M:%S') }"


# Message Builder functions
def failed_password(user, ip, port):
    # Given a `user`, `ip`, and `port`, returns a string formated like a standard sys-log failed password attempt
    return f"Failed password for {user} from {ip} port {port} ssh2"

def accepted_password(user, ip, port):
    # Given a `user`, `ip`, and `port`, returns a string formated like a standard sys-log accepted password attempt
    return f"Accepted password for {user} from {ip} port {port} ssh2"

def invalid_user(user, ip, port):
    return f"Invalid user {user} from {ip} port {port}"

def session_opened(user):
    return f"pam_unix(sshd:session): session opened for user {user}(uid=1000) by (uid=0)"

def session_closed(user):
    return f"pam_unix(sshd:session): session closed for user {user}"

def sudo_command(user, tty, pwd, target_user, command):
    return f"{user} : TTY={tty} ; PWD={pwd} ; USER={target_user} ; COMMAND={command}"


# benign scenario generator
def generate_benign(count):
    event_lines=[]
    timestamp = datetime.now()

    rand_users = ['dave', 'carol', 'domenicj', 'erin', 'brianna']
    rand_ips = ["10.0.0.12","10.0.0.14","10.0.1.5"]

    for i in range(0, count):
        user = random.choice(rand_users)
        ip = random.choice(rand_ips)
        port = random.randint(40000, 61000)

        timestamp += timedelta(seconds=random.randint(5, 500))


        event_lines.append((timestamp, accepted_password(user, ip, port)))
        event_lines.append((timestamp, session_opened(user)))

        timestamp += timedelta(seconds=random.randint(30, 600))

        event_lines.append((timestamp, session_closed(user))) 

    return event_lines

# brute_force scenario generator
def generate_brute_force(count_intensity):
    event_lines=[]
    timestamp = datetime.now()

    rand_users = ['domenicj','brianna','trey','emma', 'dave', 'carol','erin']
    rand_ips = ["127.4.3.82","203.0.113.45","198.51.100.23","102.4.3.94"]

    user = random.choice(rand_users)
    ip = random.choice(rand_ips)
    
    for i in range(0, count_intensity):
        timestamp += timedelta(seconds=random.randint(1,3))
        port = random.randint(40000,61000)

        event_lines.append((timestamp, failed_password(user, ip, port)))

    return event_lines






def main():
    parser = argparse.ArgumentParser(description="the parser for the command-line args when a SOC analyst uses this tool to triage auth logs")
    parser.add_argument(
        "--scenario", 
        required=True,
        choices=["benign", "brute_force", "credential_stuffing", "privilege_escalation", "off_hours", "lateral_movement", "mixed"],
        help="a type of potential threat scenario which the synthetic authlog lines will reflect once generated"
    )
    parser.add_argument(
        "--output",
        required=True, 
        type=str,
        help="the filepath for a log file in which synthesized authlogs will be output to"
    )
    parser.add_argument(
        "--lines",
        required=False,
        type=int,
        default=5000,        
        help="the desired number of synthetic authlog lines to be generated and output into the log file"
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
