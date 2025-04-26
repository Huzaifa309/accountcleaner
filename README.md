# Windows User Management System

A comprehensive system for managing Windows user accounts, monitoring system statistics, and tracking user activity.

## Features

- User Management
  - View all system users
  - Remove users
  - View user details
  - Track active users
- System Monitoring
  - Real-time CPU usage
  - Memory utilization
  - Disk space monitoring
  - Network statistics
- Login Activity Tracking
  - View login/logout history
  - Filter by username
  - Track login types

## Prerequisites

- Python 3.7+
- Windows operating system
- Administrative privileges

## Installation

1. Clone the repository
2. Install required packages:
```bash
pip install -r requirements.txt
```

## Configuration

Default credentials:
```
username = admin
password = admin123
```

## Usage

1. Start the Flask server:
```bash
python server.py
```

2. Start the Streamlit application:
```bash
streamlit run app.py
```

3. Access the web interface at `http://localhost:8501`

## Server Management

To stop the server:
```bash
python server_delete.py
```

## Project Structure

```
.
├── app.py              # Streamlit web application
├── server.py           # Flask API server
├── server_delete.py    # Server termination script
├── config.py           # Configuration settings
├── requirements.txt    # Python dependencies
└── hashed_password.txt # Stored credentials
```

## Security Notes

- The system requires administrative privileges to function properly
- All sensitive operations are logged
- Password is stored using bcrypt hashing

## Troubleshooting

1. If the server fails to start:
   - Ensure you have administrative privileges
   - Check if port 5000 is available
   - Verify all dependencies are installed

2. If user removal fails:
   - Run both server and application as administrator
   - Check server logs for detailed error messages

## Logging

- Server logs are stored in `flask_server.log`
- All critical operations are logged with timestamps
- Error messages are captured for debugging

## API Endpoints

- `/users` - Get all system users
- `/user/<username>` - Get specific user details
- `/active_users` - Get currently active users
- `/remove_user` - Remove a user account
- `/system_stats` - Get system statistics
- `/logs` - Get login activity logs

## System Requirements

- Windows 10 or later
- Python 3.7+
- 4GB RAM minimum
- 100MB free disk space

## License

This project is a part of IS,Audit and Control semester project from NATIONAL UNIVERSITY OF COMPUTER AND EMERGING SCIENCES, KARACHI,
Developed by: 21K-3403 (Syed Huzaifa Ahmed)

