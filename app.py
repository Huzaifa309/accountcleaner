import streamlit as st
import bcrypt
import requests
import pandas as pd
import time
import plotly.graph_objects as go
from config import API_CONFIG
from functools import lru_cache
import json
from datetime import datetime, timedelta

# Add pagination configuration at the top of the file
PAGINATION_CONFIG = {
    "page_size": 10,  # Number of rows per page
    "max_rows": 1000,  # Maximum number of rows to display
    "height": 400  # Height of the DataFrame display
}

# Load Hashed Password from File with caching
@st.cache_data
def load_credentials():
    try:
        with open("hashed_password.txt", "r") as file:
            username, stored_hash = file.read().strip().split(":")
            return username, stored_hash.encode()
    except FileNotFoundError:
        st.error("Credentials file not found. Please contact administrator.")
        return None, None
    except Exception as e:
        st.error(f"Error loading credentials: {e}")
        return None, None

# Initialize credentials
USERNAME, HASHED_PASSWORD = load_credentials()

# Enable caching for API responses
@st.cache_data(ttl=300)  # Cache for 5 minutes
def fetch_data(endpoint, key, params=None):
    try:
        url = f"{API_CONFIG['FLASK_API_URL']}/{endpoint}"
        response = requests.get(
            url,
            params=params,
            timeout=API_CONFIG['TIMEOUT']
        )
        response.raise_for_status()
        
        if response.status_code == 200:
            data = response.json()
            if key in data and isinstance(data[key], list) and len(data[key]) > 0:
                df = pd.DataFrame(data[key])
                if endpoint == "logs" and "Id" in df.columns:
                    df = df[df["Id"] == 4624]
                return df
        return None
    except requests.Timeout:
        st.error("Request timed out. Please try again.")
    except requests.RequestException as e:
        st.error(f"Network error: {e}")
    except Exception as e:
        st.error(f"Unexpected error: {e}")
    return None

# Session State Initialization
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False
if "login_attempts" not in st.session_state:
    st.session_state.login_attempts = 0
if "last_activity" not in st.session_state:
    st.session_state.last_activity = time.time()
if "data_cache" not in st.session_state:
    st.session_state.data_cache = {}

# Input Validation with improved error messages
def validate_username(username):
    if not username:
        return False, "Username cannot be empty"
    if len(username) < 3:
        return False, "Username must be at least 3 characters long"
    invalid_chars = '\\/:*?"<>|'
    if any(c in username for c in invalid_chars):
        return False, f"Username cannot contain these characters: {invalid_chars}"
    return True, ""

# Login Function with improved security
def login(username, password):
    if not USERNAME or not HASHED_PASSWORD:
        st.error("Credentials not properly loaded. Please contact administrator.")
        return False

    if st.session_state.login_attempts >= API_CONFIG['MAX_LOGIN_ATTEMPTS']:
        st.error("Too many failed attempts. Please try again later.")
        return False

    if username == USERNAME and bcrypt.checkpw(password.encode(), HASHED_PASSWORD):
        st.session_state.authenticated = True
        st.session_state.login_attempts = 0
        st.session_state.last_activity = time.time()
        st.success("Login successful!")
        time.sleep(1)  # Show success message
        st.rerun()
        return True
    else:
        st.session_state.login_attempts += 1
        st.error("Invalid Username or Password")
        return False

# Logout Function
def logout():
    st.session_state.authenticated = False
    st.session_state.clear()
    st.rerun()

# Session Timeout Check
def check_session_timeout():
    if "last_activity" in st.session_state:
        if time.time() - st.session_state.last_activity > API_CONFIG['SESSION_TIMEOUT']:
            st.session_state.authenticated = False
            st.warning("Session expired. Please login again.")
            st.rerun()
    st.session_state.last_activity = time.time()

# Login Page with improved UI
def login_page():
    st.markdown("""
        <div style='text-align: center; margin-bottom: 30px;'>
            <h1 style='color: #4A90E2;'>Login</h1>
            <p style='color: #666;'>Please enter your credentials to access the system</p>
        </div>
    """, unsafe_allow_html=True)
    
    with st.form("login_form"):
        username = st.text_input("Username", key="login_username")
        password = st.text_input("Password", type="password", key="login_password")
        submitted = st.form_submit_button("Login")
        
        if submitted:
            is_valid, error_msg = validate_username(username)
            if is_valid:
                login(username, password)
            else:
                st.error(error_msg)
    
    if st.session_state.login_attempts > 0:
        st.warning(f"Failed Login Attempts: {st.session_state.login_attempts}")

def format_bytes(size):
    """Convert bytes to human readable format"""
    power = 2**10
    n = 0
    power_labels = {0: 'B', 1: 'KB', 2: 'MB', 3: 'GB', 4: 'TB'}
    while size > power:
        size /= power
        n += 1
    return f"{size:.2f} {power_labels[n]}"

def get_system_stats():
    max_retries = 3
    retry_delay = 1  # seconds
    
    for attempt in range(max_retries):
        try:
            response = requests.get(
                f"{API_CONFIG['FLASK_API_URL']}/system_stats",
                timeout=API_CONFIG['TIMEOUT']
            )
            
            if response.status_code == 200:
                data = response.json()
                if "error" in data:
                    st.error(f"Server Error: {data['error']}")
                    return None
                return data
            else:
                st.error(f"Server returned status code: {response.status_code}")
                if attempt < max_retries - 1:
                    time.sleep(retry_delay)
                    continue
                return None
                
        except requests.exceptions.ConnectionError:
            st.error("Could not connect to the server. Please ensure the server is running.")
            if attempt < max_retries - 1:
                time.sleep(retry_delay)
                continue
            return None
        except requests.exceptions.Timeout:
            st.error("Request timed out. The server is taking too long to respond.")
            if attempt < max_retries - 1:
                time.sleep(retry_delay)
                continue
            return None
        except Exception as e:
            st.error(f"Error fetching system stats: {str(e)}")
            if attempt < max_retries - 1:
                time.sleep(retry_delay)
                continue
            return None
    
    return None

# Dashboard with improved UI
def dashboard():
    if not st.session_state.authenticated:
        login_page()
        return

    check_session_timeout()

    # Main header with improved styling
    st.markdown("""
        <div style='text-align: center; margin-bottom: 20px;'>
            <h1 style='color: #4A90E2;'>Windows User Management</h1>
            <p style='color: #666;'>Manage user accounts, check login activity, and remove accounts</p>
        </div>
    """, unsafe_allow_html=True)

    # Center the logout button
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        if st.button("Logout", key="logout_btn", use_container_width=True):
            logout()

    st.markdown("---")
    
    # Create tabs for better organization
    tab1, tab2, tab3 = st.tabs(["📊 User Management", "🔍 User Details", "📈 System Monitor"])

    with tab1:
        st.subheader("User Information")
        
        # Create columns for better layout
        col1, col2 = st.columns([1, 1])

        with col1:
            st.markdown("### 📋 User Data")
            
            # Fetch Users with loading state
            if st.button("Fetch Users", key="fetch_users_btn"):
                with st.spinner('Fetching users...'):
                    df = fetch_data("users", "users")
                    if df is not None:
                        # Add pagination controls
                        total_rows = len(df)
                        if total_rows > PAGINATION_CONFIG["max_rows"]:
                            st.warning(f"Showing first {PAGINATION_CONFIG['max_rows']} rows out of {total_rows}")
                            df = df.head(PAGINATION_CONFIG["max_rows"])
                        
                        st.dataframe(
                            df,
                            use_container_width=True,
                            height=PAGINATION_CONFIG["height"],
                            hide_index=True
                        )
                    else:
                        st.warning("No users found or server error.")

            # Fetch Active Users with loading state
            if st.button("Fetch Active Users", key="fetch_active_users_btn"):
                with st.spinner('Fetching active users...'):
                    df = fetch_data("active_users", "active_users")
                    if df is not None:
                        # Add pagination controls
                        total_rows = len(df)
                        if total_rows > PAGINATION_CONFIG["max_rows"]:
                            st.warning(f"Showing first {PAGINATION_CONFIG['max_rows']} rows out of {total_rows}")
                            df = df.head(PAGINATION_CONFIG["max_rows"])
                        
                        st.dataframe(
                            df,
                            use_container_width=True,
                            height=PAGINATION_CONFIG["height"],
                            hide_index=True
                        )
                    else:
                        st.warning("No active users found or server error.")

        with col2:
            st.markdown("### 📊 Login Logs")
            
            # Input fields with improved validation
            username = st.text_input("Enter username to filter logs (leave empty for all users)", 
                                   key="logs_username",
                                   help="Leave empty to see all users' logs")
            
            days = st.number_input("Days to look back", 
                                 min_value=1, 
                                 max_value=365, 
                                 value=30, 
                                 key="logs_days",
                                 help="Select how many days of logs to view")
            
            if st.button("Fetch Login Logs", key="fetch_logs_btn"):
                with st.spinner('Fetching login logs...'):
                    params = {}
                    if username:
                        params['username'] = username
                    params['days'] = days
                    
                    df = fetch_data("logs", "logs", params)
                    if df is not None:
                        # Add pagination controls
                        total_rows = len(df)
                        if total_rows > PAGINATION_CONFIG["max_rows"]:
                            st.warning(f"Showing first {PAGINATION_CONFIG['max_rows']} rows out of {total_rows}")
                            df = df.head(PAGINATION_CONFIG["max_rows"])
                        
                        st.dataframe(
                            df,
                            use_container_width=True,
                            height=PAGINATION_CONFIG["height"],
                            hide_index=True
                        )
                    else:
                        st.warning("No login logs found")

    with tab2:
        st.subheader("User Details")
        
        # User Details section with improved validation
        username = st.text_input("Enter Username to Fetch Details", 
                               key="user_details_username",
                               help="Enter the username to view detailed information")

        if st.button("Get User Info", key="get_user_info_btn") and username:
            is_valid, error_msg = validate_username(username)
            if is_valid:
                with st.spinner('Fetching user details...'):
                    try:
                        response = requests.get(
                            f"{API_CONFIG['FLASK_API_URL']}/user/{username}",
                            timeout=API_CONFIG['TIMEOUT']
                        )
                        if response.status_code == 200:
                            data = response.json()
                            if data and "error" not in data:
                                st.json(data)
                            else:
                                st.warning(data.get("error", "User not found!"))
                        else:
                            st.error("Failed to fetch user details.")
                    except Exception as e:
                        st.error(f"Error connecting to server: {e}")
            else:
                st.error(error_msg)

        # Remove User section with improved validation and password verification
        st.markdown("### 🗑️ Remove User")
        user_to_remove = st.text_input("Enter Username to Remove", 
                                     key="remove_user_username",
                                     help="Enter the username to remove")

        if st.button("Remove User", key="remove_user_btn") and user_to_remove:
            is_valid, error_msg = validate_username(user_to_remove)
            if is_valid:
                # First confirmation
                if st.session_state.get("confirm_removal") != user_to_remove:
                    st.session_state.confirm_removal = user_to_remove
                    st.warning(f"Are you sure you want to remove user '{user_to_remove}'?")
                    st.info("This action cannot be undone. Please enter your admin password to confirm.")
                    
                    # Password verification
                    admin_password = st.text_input("Enter Admin Password to Confirm", 
                                                 type="password",
                                                 key="admin_password_confirm")
                    
                    if st.button("Confirm Removal", key="confirm_removal_btn"):
                        if bcrypt.checkpw(admin_password.encode(), HASHED_PASSWORD):
                            with st.spinner('Removing user...'):
                                try:
                                    response = requests.post(
                                        f"{API_CONFIG['FLASK_API_URL']}/remove_user",
                                        json={"username": user_to_remove},
                                        timeout=API_CONFIG['TIMEOUT']
                                    )
                                    if response.status_code == 200:
                                        result = response.json()
                                        if result.get("status") == "success":
                                            st.success(f"User '{user_to_remove}' removed successfully!")
                                            st.session_state.confirm_removal = None
                                        else:
                                            st.error(result.get("message", "Failed to remove user"))
                                    else:
                                        st.error("Failed to remove user")
                                except Exception as e:
                                    st.error(f"Error connecting to server: {e}")
                        else:
                            st.error("Invalid admin password. Please try again.")
                else:
                    # Clear the confirmation state if user cancels
                    if st.button("Cancel Removal", key="cancel_removal_btn"):
                        st.session_state.confirm_removal = None
                        st.rerun()
            else:
                st.error(error_msg)

    with tab3:
        st.markdown("### 🖥️ System Statistics")
        
        # Auto-refresh every 5 seconds
        if 'last_refresh' not in st.session_state:
            st.session_state.last_refresh = time.time()
        
        if time.time() - st.session_state.last_refresh > 5:
            st.session_state.last_refresh = time.time()
            st.rerun()
        
        stats = get_system_stats()
        if stats and "error" not in stats:
            # System Overview
            col1, col2, col3 = st.columns(3)
            with col1:
                if "cpu" in stats and "percent" in stats["cpu"]:
                    st.metric("CPU Usage", f"{stats['cpu']['percent']}%")
                else:
                    st.metric("CPU Usage", "N/A")
            with col2:
                if "memory" in stats and "percent" in stats["memory"]:
                    st.metric("Memory Usage", f"{stats['memory']['percent']}%")
                else:
                    st.metric("Memory Usage", "N/A")
            with col3:
                if "disk" in stats and "percent" in stats["disk"]:
                    st.metric("Disk Usage", f"{stats['disk']['percent']}%")
                else:
                    st.metric("Disk Usage", "N/A")
            
            # CPU and Memory Charts
            col1, col2 = st.columns(2)
            with col1:
                # CPU Usage Gauge
                if "cpu" in stats and "percent" in stats["cpu"]:
                    fig_cpu = go.Figure(go.Indicator(
                        mode="gauge+number",
                        value=stats['cpu']['percent'],
                        title={'text': "CPU Usage"},
                        gauge={'axis': {'range': [0, 100]},
                              'bar': {'color': "#4A90E2"}}
                    ))
                    st.plotly_chart(fig_cpu, use_container_width=True)
                else:
                    st.warning("CPU usage data not available")
            
            with col2:
                # Memory Usage Gauge
                if "memory" in stats and "percent" in stats["memory"]:
                    fig_mem = go.Figure(go.Indicator(
                        mode="gauge+number",
                        value=stats['memory']['percent'],
                        title={'text': "Memory Usage"},
                        gauge={'axis': {'range': [0, 100]},
                              'bar': {'color': "#4A90E2"}}
                    ))
                    st.plotly_chart(fig_mem, use_container_width=True)
                else:
                    st.warning("Memory usage data not available")
            
            # Detailed System Information
            st.markdown("### 📊 Detailed System Information")
            
            # CPU Details
            st.markdown("#### CPU")
            col1, col2, col3 = st.columns(3)
            with col1:
                if "cpu" in stats and "count" in stats["cpu"]:
                    st.metric("CPU Cores", stats['cpu']['count'])
                else:
                    st.metric("CPU Cores", "N/A")
            with col2:
                if "cpu" in stats and "frequency" in stats["cpu"] and "current" in stats["cpu"]["frequency"]:
                    st.metric("Current Frequency", f"{stats['cpu']['frequency']['current']:.2f} MHz")
                else:
                    st.metric("Current Frequency", "N/A")
            with col3:
                if "cpu" in stats and "frequency" in stats["cpu"] and "max" in stats["cpu"]["frequency"]:
                    st.metric("Max Frequency", f"{stats['cpu']['frequency']['max']:.2f} MHz")
                else:
                    st.metric("Max Frequency", "N/A")
            
            # Memory Details
            st.markdown("#### Memory")
            col1, col2, col3 = st.columns(3)
            with col1:
                if "memory" in stats and "total" in stats["memory"]:
                    st.metric("Total Memory", format_bytes(stats['memory']['total']))
                else:
                    st.metric("Total Memory", "N/A")
            with col2:
                if "memory" in stats and "available" in stats["memory"]:
                    st.metric("Available Memory", format_bytes(stats['memory']['available']))
                else:
                    st.metric("Available Memory", "N/A")
            with col3:
                if "memory" in stats and "used" in stats["memory"]:
                    st.metric("Used Memory", format_bytes(stats['memory']['used']))
                else:
                    st.metric("Used Memory", "N/A")
            
            # Disk Details
            st.markdown("#### Disk")
            col1, col2, col3 = st.columns(3)
            with col1:
                if "disk" in stats and "total" in stats["disk"]:
                    st.metric("Total Space", format_bytes(stats['disk']['total']))
                else:
                    st.metric("Total Space", "N/A")
            with col2:
                if "disk" in stats and "free" in stats["disk"]:
                    st.metric("Free Space", format_bytes(stats['disk']['free']))
                else:
                    st.metric("Free Space", "N/A")
            with col3:
                if "disk" in stats and "used" in stats["disk"]:
                    st.metric("Used Space", format_bytes(stats['disk']['used']))
                else:
                    st.metric("Used Space", "N/A")
            
            # Network Details
            st.markdown("#### Network")
            col1, col2 = st.columns(2)
            with col1:
                if "network" in stats and "bytes_sent" in stats["network"]:
                    st.metric("Bytes Sent", format_bytes(stats['network']['bytes_sent']))
                else:
                    st.metric("Bytes Sent", "N/A")
            with col2:
                if "network" in stats and "bytes_recv" in stats["network"]:
                    st.metric("Bytes Received", format_bytes(stats['network']['bytes_recv']))
                else:
                    st.metric("Bytes Received", "N/A")
        else:
            st.error("Failed to fetch system statistics")

# Conditional Rendering
if st.session_state.authenticated:
    dashboard()
else:
    login_page()
