from flask import Flask, request, jsonify
import subprocess
import json
import psutil
import logging
import win32evtlog
from datetime import datetime, timedelta
import bcrypt

app = Flask(__name__)

# Set up logging
logging.basicConfig(filename="flask_server.log", level=logging.INFO,
                    format="%(asctime)s - %(levelname)s - %(message)s")

# Load admin credentials
def load_credentials():
    try:
        with open("hashed_password.txt", "r") as file:
            username, stored_hash = file.read().strip().split(":")
            return username, stored_hash.encode()
    except FileNotFoundError:
        logging.error("Credentials file not found")
        return None, None
    except Exception as e:
        logging.error(f"Error loading credentials: {e}")
        return None, None

USERNAME, HASHED_PASSWORD = load_credentials()

# Get user login/logout history from Windows Event Viewer
def get_login_history(username=None, days_back=30):
    try:
        # Parameters
        server = 'localhost'
        log_type = 'Security'
        LOGON_EVENT_ID = 4624  # Successful login only
        
        # Calculate start time
        start_time = datetime.now() - timedelta(days=days_back)
        
        # Open event log
        handle = win32evtlog.OpenEventLog(server, log_type)
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        
        login_events = []
        
        # Read events in chunks
        while True:
            events = win32evtlog.ReadEventLog(handle, flags, 0)
            if not events:
                break
                
            for event in events:
                if event.EventID == LOGON_EVENT_ID:
                    # Skip events before start time
                    if event.TimeGenerated < start_time:
                        continue
                    
                    if event.StringInserts and len(event.StringInserts) > 5:
                        current_username = event.StringInserts[5]
                        
                        # Check if we should include this event
                        if not username or username.lower() in current_username.lower():
                            # Extract login type from StringInserts
                            login_type = "Unknown"
                            if len(event.StringInserts) > 8:
                                login_type_code = event.StringInserts[8]
                                login_types = {
                                    "2": "Local Login",
                                    "3": "Network Login",
                                    "4": "Batch Login",
                                    "5": "Service Login",
                                    "7": "Workstation Unlock",
                                    "8": "Network Cleartext",
                                    "9": "New Credentials",
                                    "10": "Remote Desktop",
                                    "11": "Cached Login"
                                }
                                login_type = login_types.get(login_type_code, "Unknown Login Type")
                            
                            login_events.append({
                                'time': event.TimeGenerated.strftime('%Y-%m-%d %H:%M:%S'),
                                'username': current_username,
                                'action': login_type
                            })
        
        # Close the event log
        win32evtlog.CloseEventLog(handle)
        
        # Sort by time (most recent first)
        login_events.sort(key=lambda x: x['time'], reverse=True)
        return login_events
        
    except Exception as e:
        logging.error(f"Error retrieving login history: {str(e)}")
        return []

# Get all Windows user accounts
def get_users():
    try:
        result = subprocess.run(["net", "user"], capture_output=True, text=True, shell=True)
        output_lines = result.stdout.strip().split("\n")

        # Remove header, separator, and footer lines
        user_lines = output_lines[2:-1]

        users = []
        for line in user_lines:
            clean_line = line.strip()
            if "----" not in clean_line and clean_line:
                users.extend(clean_line.split())  # Handle multi-column usernames

        return {"users": users}
    except Exception as e:
        logging.error(f"Error retrieving users: {str(e)}")
        return {"error": "Failed to fetch user list"}

# Get details of a specific user
def get_user_info(username):
    try:
        command = f'net user "{username}"'
        result = subprocess.run(command, capture_output=True, text=True, shell=True)
        
        if result.returncode != 0:
            return {"error": f"User '{username}' not found."}

        details = result.stdout.strip().split("\n")
        user_data = {"username": username}

        for line in details:
            if "Full Name" in line:
                user_data["full_name"] = line.split("Full Name")[1].strip()
            elif "Local Group Memberships" in line:
                user_data["groups"] = line.split("Local Group Memberships")[1].strip()
            elif "Account active" in line:
                user_data["active"] = line.split("Account active")[1].strip()
            elif "Password last set" in line:
                user_data["password_last_set"] = line.split("Password last set")[1].strip()

        return user_data
    except Exception as e:
        logging.error(f"Error retrieving details for {username}: {str(e)}")
        return {"error": f"Failed to fetch details for {username}"}

# Get active user sessions
def get_active_users():
    try:
        users = []
        for session in psutil.users():
            # Convert Unix timestamp to datetime
            started_time = datetime.fromtimestamp(session.started).strftime('%Y-%m-%d %H:%M:%S')
            users.append({
                "user": session.name,
                "host": session.host if session.host else "Local",
                "started": started_time
            })
        return {"active_users": users}
    except Exception as e:
        logging.error(f"Error retrieving active users: {str(e)}")
        return {"error": "Failed to fetch active users"}

# Remove a user account
def remove_user(username):
    try:
        users = get_users().get("users", [])
        if username not in users:
            return {"status": "error", "message": f"User '{username}' does not exist."}

        command = f'net user "{username}" /delete'
        result = subprocess.run(command, capture_output=True, text=True, shell=True)

        if result.returncode == 0:
            return {"status": "success", "message": f"User '{username}' removed successfully."}
        else:
            return {"status": "error", "message": f"Failed to remove user: {result.stderr}"}

    except Exception as e:
        logging.error(f"Error removing user {username}: {str(e)}")
        return {"status": "error", "message": str(e)}

# Get system statistics
def get_system_stats():
    try:
        stats = {}
        
        # CPU Information
        try:
            cpu_percent = psutil.cpu_percent(interval=1)
            cpu_count = psutil.cpu_count()
            cpu_freq = psutil.cpu_freq()
            stats["cpu"] = {
                "percent": cpu_percent,
                "count": cpu_count,
                "frequency": {
                    "current": cpu_freq.current if cpu_freq else 0,
                    "min": cpu_freq.min if cpu_freq else 0,
                    "max": cpu_freq.max if cpu_freq else 0
                }
            }
        except Exception as e:
            logging.error(f"Error getting CPU stats: {str(e)}")
            stats["cpu"] = {"error": str(e)}
        
        # Memory Information
        try:
            memory = psutil.virtual_memory()
            swap = psutil.swap_memory()
            stats["memory"] = {
                "total": memory.total,
                "available": memory.available,
                "used": memory.used,
                "percent": memory.percent,
                "swap_total": swap.total,
                "swap_used": swap.used,
                "swap_percent": swap.percent
            }
        except Exception as e:
            logging.error(f"Error getting memory stats: {str(e)}")
            stats["memory"] = {"error": str(e)}
        
        # Disk Information
        try:
            disk = psutil.disk_usage('/')
            disk_io = psutil.disk_io_counters()
            stats["disk"] = {
                "total": disk.total,
                "used": disk.used,
                "free": disk.free,
                "percent": disk.percent,
                "read_bytes": disk_io.read_bytes if disk_io else 0,
                "write_bytes": disk_io.write_bytes if disk_io else 0
            }
        except Exception as e:
            logging.error(f"Error getting disk stats: {str(e)}")
            stats["disk"] = {"error": str(e)}
        
        # Network Information
        try:
            net_io = psutil.net_io_counters()
            stats["network"] = {
                "bytes_sent": net_io.bytes_sent if net_io else 0,
                "bytes_recv": net_io.bytes_recv if net_io else 0,
                "packets_sent": net_io.packets_sent if net_io else 0,
                "packets_recv": net_io.packets_recv if net_io else 0
            }
        except Exception as e:
            logging.error(f"Error getting network stats: {str(e)}")
            stats["network"] = {"error": str(e)}
        
        # System Information
        try:
            boot_time = datetime.fromtimestamp(psutil.boot_time())
            uptime = datetime.now() - boot_time
            stats["system"] = {
                "boot_time": boot_time.strftime('%Y-%m-%d %H:%M:%S'),
                "uptime": str(uptime),
                "process_count": len(list(psutil.process_iter()))
            }
        except Exception as e:
            logging.error(f"Error getting system stats: {str(e)}")
            stats["system"] = {"error": str(e)}
        
        # Check if any critical component failed
        if any("error" in stats[component] for component in ["cpu", "memory", "disk"]):
            logging.error("Critical system stats collection failed")
            return {"error": "Failed to collect critical system statistics"}
        
        logging.info("Successfully retrieved system statistics")
        return stats
        
    except Exception as e:
        logging.error(f"Critical error in get_system_stats: {str(e)}")
        return {"error": f"Failed to fetch system statistics: {str(e)}"}

# Routes
@app.route("/")
def home():
    return jsonify({"message": "Windows User Manager API is running"})

@app.route("/logs", methods=["GET"])
def login_logs():
    username = request.args.get('username')
    days_back = request.args.get('days', default=30, type=int)
    logs = get_login_history(username, days_back)
    return jsonify({"logs": logs})

@app.route("/users", methods=["GET"])
def list_users():
    return jsonify(get_users())

@app.route("/user/<username>", methods=["GET"])
def get_specific_user(username):
    return jsonify(get_user_info(username))

@app.route("/active_users", methods=["GET"])
def active_users():
    return jsonify(get_active_users())

@app.route("/remove_user", methods=["POST"])
def delete_user():
    data = request.json
    username = data.get("username")
    admin_password = data.get("admin_password")
    
    if not username:
        return jsonify({"status": "error", "message": "Username required"}), 400
    
    if not admin_password:
        return jsonify({"status": "error", "message": "Admin password required"}), 400
    
    # Verify admin password
    if not USERNAME or not HASHED_PASSWORD:
        return jsonify({"status": "error", "message": "Admin credentials not properly loaded"}), 500
    
    if not bcrypt.checkpw(admin_password.encode(), HASHED_PASSWORD):
        return jsonify({"status": "error", "message": "Invalid admin password"}), 401
    
    return jsonify(remove_user(username))

@app.route("/system_stats", methods=["GET"])
def system_stats():
    try:
        stats = get_system_stats()
        if "error" in stats:
            logging.error(f"Error in system stats: {stats['error']}")
            return jsonify(stats), 500
        return jsonify(stats)
    except Exception as e:
        logging.error(f"Error in system_stats endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

# Add debug endpoint to check Windows Event Log directly
@app.route("/debug_events", methods=["GET"])
def debug_events():
    try:
        days_back = request.args.get('days', default=1, type=int)
        logging.info(f"Debug: Fetching raw events for past {days_back} days")
        
        events = get_login_history(days_back=days_back)
        logging.info(f"Debug: Retrieved {len(events)} raw events")
        
        # Return first 10 events for debugging
        sample_events = events[:10] if events else []
        return jsonify({
            "total_events": len(events),
            "sample_events": sample_events
        })
    except Exception as e:
        logging.error(f"Error in debug_events endpoint: {str(e)}")
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
