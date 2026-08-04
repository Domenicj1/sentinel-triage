from datetime import datetime

def fmt_ts(dt): # Format a datetime object into a syslog-style timestamp (fmt_ts  = format timestamp)

    """Turn a datetime object into a syslog-style timestamp like 'Jul 25 09:14:32'."""



    # the `%b` code in strftime means "abbreviated month name"
    # instead of using the `%e` code in strftime, we manually format the day with space-padding using `{dt.day:2d}` in an f-string 
    return f"{dt.strftime('%b')} {dt.day:2d} {dt.strftime('%H:%M:%S')}"

dt = datetime.now()

print(fmt_ts(dt))

# now, on to the message-builder 

def failed_password(user, ip, port):
    return f"Failed password for {user} from {ip} port {port} ssh2"