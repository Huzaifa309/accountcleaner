from flask import Flask, request, jsonify
import subprocess
import json
import psutil
import logging

app = Flask(__name__)

# Set up logging
logging.basicConfig(filename="flask_server.log", level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")


# Get user login/logout history from Windows Event Viewer
def get_login_history():
    try:
        powershell_script = '''
        $events = Get-WinEvent -LogName Security | Where-Object {($_.Id -eq 4624) -or ($_.Id -eq 4647)} | 
        Select-Object TimeCreated, Id, Message | ConvertTo-Json -Compress
        '''
        result = subprocess.run(["powershell", "-Command", powershell_script], capture_output=True, text=True)
        
        if result.returncode != 0 or not result.stdout:
            logging.error(f"PowerShell Error: {result.stderr}")
            return {"error": "Failed to fetch login history"}
        
        return json.loads(result.stdout)
    except Exception as e:
        logging.error(f"Error retrieving login history: {str(e)}")
        return {"error": "Failed to fetch login history"}



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
            users.append({
                "user": session.name,
                "host": session.host if session.host else "Local",
                "started": session.started
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


# Flask Routes
@app.route("/", methods=["GET"])
def home():
    return jsonify({"message": "Windows Account Management API is running!"})


@app.route("/logs", methods=["GET"])
def fetch_logs():
    return jsonify(get_login_history())


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
    if not username:
        return jsonify({"status": "error", "message": "Username required"}), 400
    return jsonify(remove_user(username))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
