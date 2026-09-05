from datetime import datetime as dt, timedelta
import argparse
import random


legit_users=['domenicj', 'brianna', 'trey', 'emma', 'dave', 'carol', 'erin']
HOSTNAME="web01"

# Format Timestamp function
def fmt_ts(dt): 

    # Format a datetime object into a syslog-style timestamp like 'Jul 25 09:14:32' (fmt_ts  = "format timestamp")
    # the `%b` code in strftime means "abbreviated month name"
    # instead of using the `%e` code in strftime, we manually format the day with space-padding using `{dt.day:2d}` in a f-string 
    return f"{dt.strftime('%b')} {dt.day:2d} {dt.strftime('%H:%M:%S')}"


# Message Builder functions
def failed_password(user, ip, port, invalid=False):
    # Given a `user`, `ip`, and `port`, returns a string formated like a standard sys-log failed password attempt
    if invalid:
        return f"Failed password for invalid user {user} from {ip} port {port} ssh2"
    else: # default if invalid parameter is false
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
    timestamp = dt.now()


    normal_ips = ["10.0.0.12","10.0.0.14","10.0.1.5"]

    # the defining signature of "benign" attack pattern is: one username + one IP address + one login attempt
    for i in range(0, count):
        user = random.choice(legit_users)
        ip = random.choice(normal_ips)
        port = random.randint(40000, 61000)

        timestamp += timedelta(seconds=random.randint(5, 500))


        event_lines.append((timestamp, "sshd", accepted_password(user, ip, port)))
        event_lines.append((timestamp, "sshd", session_opened(user)))

        timestamp += timedelta(seconds=random.randint(30, 600))

        event_lines.append((timestamp, "sshd", session_closed(user))) 

    return event_lines

# brute_force scenario generator
def generate_brute_force(intesity_count):
    event_lines=[]
    timestamp = dt.now()

    irreg_ips1 = ["127.4.3.82","203.0.113.45","198.51.100.23","102.4.3.94"]

    user = random.choice(legit_users)
    ip = random.choice(irreg_ips1)

    # the defining signature of "brute force" attack pattern is: one username + one IP address + many attempts
    for i in range(0, intesity_count):
        timestamp += timedelta(seconds=random.randint(1,3))
        port = random.randint(40000,61000)

        event_lines.append((timestamp, "sshd", failed_password(user, ip, port)))

    return event_lines

# credential_stuffing scenario generator
def generate_credential_stuffing(intesity_count):
    event_lines=[]
    timestamp = dt.now()

    irreg_ips2 = ["134.4.5.82","235.6.113.55","181.1.0.75","162.8.90.47"]

    guessed_usernames=['admin', 'root', 'test','guest', 'oracle', 'postgres', 'ubuntu']

    guessed_usernames = guessed_usernames + legit_users

    ip1, ip2 = random.sample(irreg_ips2, k=2)

    # the defining signature of the "credential stuffing" attack pattern is: many usernames + a couple IP adresses + many attempts
    for i in range(0, intesity_count):
        timestamp += timedelta(seconds=random.randint(1,4))

        random_ip = random.choice([ip1, ip2])
        random_port = random.randint(40000,61000)
        random_user = random.choice(guessed_usernames)

        if random_user in legit_users:
            event_lines.append((timestamp, "sshd", failed_password(random_user, random_ip, random_port)))
        else:
            event_lines.append((timestamp, "sshd", invalid_user(random_user, random_ip, random_port)))
            event_lines.append((timestamp, "sshd", failed_password(random_user, random_ip, random_port, invalid=True)))

    return event_lines

# privilege_escalation scenario generator
def generate_privilege_escalation():
    event_lines=[]

    timestamp=dt.now()

    guessed_usernames=['admin', 'root', 'test', 'guest', 'oracle', 'postgres', 'ubuntu']
    guessed_usernames = guessed_usernames + legit_users
    
    irreg_ips1 = ["127.4.3.82","203.0.113.45","198.51.100.23","102.4.3.94"]

    random_user = random.choice(legit_users)

    random_ip = random.choice(irreg_ips1)

    random_port = random.randint(40000,61000)

    event_lines.append((timestamp, "sshd", accepted_password(random_user, random_ip, random_port)))
    event_lines.append((timestamp, "sshd", session_opened(random_user)))

    suspicious_commands = [
        "/bin/cat /etc/shadow",
        "/usr/bin/vi /etc/sudoers",
        "/bin/su -",
        "/bin/chmod 777 /etc/passwd",
        "/usr/bin/passwd root"
    ]

    for command in suspicious_commands:
        timestamp += timedelta(seconds=random.randint(5, 30))
        event_lines.append((timestamp, "sudo", sudo_command(random_user, "pts/1", f"/home/{random_user}", "root", command)))

    return event_lines

# off_hours scenario generator
def generate_off_hours():
    event_lines=[]
    timestamp = dt.now()

    irreg_ips3 = ["127.4.3.82","203.0.113.45","198.51.100.23","102.4.3.94","134.4.5.82","235.6.113.55","181.1.0.75","162.8.90.47"]

    night = timestamp.replace(
        hour=random.choice([1,2,3,4]), 
        minute=random.randint(0,59),
        second=random.randint(0,59)
    )

    random_user = random.choice(legit_users)

    random_ip = random.choice(irreg_ips3)

    random_port = random.randint(40000, 61000)
    
    event_lines.append((night, "sshd", accepted_password(random_user, random_ip, random_port)))
    event_lines.append((night, "sshd", session_opened(random_user)))

    night += timedelta(minutes=random.randint(2,15))

    event_lines.append((night, "sshd", session_closed(random_user)))

    return event_lines

# lateral_movement scenario generator
def generate_lateral_movement():
    event_lines=[]

    random_user = random.choice(legit_users)

    internal_ips = ['10.84.215.3','172.22.149.88','192.168.1.145','10.2.114.237','172.30.91.12']

    hop_ips = random.sample(internal_ips, k=3)

    timestamp = dt.now()


    for ip in hop_ips:
        random_port = random.randint(40000, 61000)

        event_lines.append((timestamp, "sshd", accepted_password(random_user, ip, random_port)))
        event_lines.append((timestamp, "sshd", session_opened(random_user)))

        timestamp += timedelta(seconds=random.randint(10,60))

        event_lines.append((timestamp, "sshd", session_closed(random_user)))

        timestamp += timedelta(seconds=random.randint(5,20))

    return event_lines


# NEXT: implement interleave_and_write() to mix benign traffic with attack bursts

def write_fixtures(events, filepath):
    with open(filepath, 'w') as f:
        for timestamp, service, message in events:
            random_pid = random.randint(1000, 99999)
            f.write(f"{fmt_ts(timestamp)} {HOSTNAME} {service}[{random_pid}]: {message}\n")

def build_fixture(scenario, total_lines):
    if scenario == "benign":
        return generate_benign(total_lines // 3)
    
    elif scenario == "brute_force":
        background = generate_benign(int(0.95 * (total_lines // 3)))
        attack_lines = generate_brute_force(max( 10, int(0.05 * total_lines)))
            
    elif scenario == "credential_stuffing":
        background = generate_benign(int(0.95 * (total_lines // 3)))
        attack_lines = generate_credential_stuffing(max(10, int(0.05 * total_lines)))
            
    elif scenario == "privilege_escalation":
        background = generate_benign((total_lines // 3))
        attack_lines = generate_privilege_escalation()
            
    elif scenario == "off_hours":
        background = generate_benign((total_lines // 3))
        attack_lines = generate_off_hours()
        
    elif scenario == "lateral_movement":
        background = generate_benign((total_lines // 3))
        attack_lines = generate_lateral_movement()

    elif scenario == "mixed":
        background = generate_benign((total_lines // 3))
        attack_lines = generate_brute_force(max(10, int(0.02 * total_lines))) + generate_credential_stuffing(max(10, int(0.02 * total_lines))) + generate_privilege_escalation() + generate_off_hours() + generate_lateral_movement()

    events = background + attack_lines
    events.sort(key=lambda event: event[0])
    return events
            

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
        help="the desired number of synthetic authlog lines to be generated and output into the specified log file"
    )
    parser.add_argument(
        "--seed", 
        required=False,            
        type=int,
        default=None
    )

    args = parser.parse_args()
    random.seed(args.seed)




    print(args)
        


    events = build_fixture(args.scenario, args.lines)

    write_fixtures(events, args.output)

if __name__ == "__main__":
    main()
