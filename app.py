import streamlit as st
import bcrypt
import requests
import pandas as pd

# Load Hashed Password from File
def load_credentials():
    try:
        with open("hashed_password.txt", "r") as file:
            username, stored_hash = file.read().strip().split(":")
            return username, stored_hash.encode()
    except FileNotFoundError:
        return None, None

USERNAME, HASHED_PASSWORD = load_credentials()

# Session State Initialization
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False
if "login_attempts" not in st.session_state:
    st.session_state.login_attempts = 0

# Login Function
def login(username, password):
    if username == USERNAME and bcrypt.checkpw(password.encode(), HASHED_PASSWORD):
        st.session_state.authenticated = True
        st.session_state.login_attempts = 0
        st.rerun()
    else:
        st.session_state.login_attempts += 1
        st.error("Invalid Username or Password")

# Logout Function
def logout():
    st.session_state.authenticated = False
    st.rerun()

# Login Page
def login_page():
    st.title("Login")
    with st.form("login_form"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Login")
        if submitted:
            login(username, password)
    if st.session_state.login_attempts > 0:
        st.warning(f"Failed Login Attempts: {st.session_state.login_attempts}")

# Dashboard
def dashboard():
    if not st.session_state.authenticated:
        login_page()
        return
    
    st.markdown("<h1 style='text-align: center; color: #4A90E2;'>Windows User Management</h1>", unsafe_allow_html=True)
    st.write("Manage user accounts, check login activity, and remove accounts.")
    
    st.markdown("<div class='logout-btn' style='text-align: center;'><button onclick='window.location.reload();'>Logout</button></div>", unsafe_allow_html=True)
    
    FLASK_API_URL = "http://192.168.0.104:5000"
    
    # Fetch Data Functions
    def fetch_data(endpoint, key):
        response = requests.get(f"{FLASK_API_URL}/{endpoint}")
        if response.status_code == 200:
            data = response.json()
            if key in data and isinstance(data[key], list) and len(data[key]) > 0:
                return pd.DataFrame(data[key])
            else:
                return None
        else:
            return None
    
    st.markdown("---")
    st.subheader("User Information")
    
    col1, col2 = st.columns([1, 1])
    
    with col1:
        st.markdown("### 📋 Fetch User Data")
        if st.button("Fetch Users"):
            df = fetch_data("users", "users")
            if df is not None:
                st.dataframe(df)
            else:
                st.warning("No users found.")
        
        if st.button("Fetch Active Users"):
            df = fetch_data("active_users", "active_users")
            if df is not None:
                st.dataframe(df)
            else:
                st.warning("No active users found.")
        
        if st.button("Fetch Login Logs"):
            df = fetch_data("logs", "logs")
            if df is not None:
                st.dataframe(df)
            else:
                st.warning("No login logs found.")
    
    with col2:
        st.markdown("### 🔍 Search User Details")
        username = st.text_input("Enter Username to Fetch Details")
        if st.button("Get User Info") and username:
            response = requests.get(f"{FLASK_API_URL}/user/{username}")
            if response.status_code == 200:
                data = response.json()
                if data:
                    st.json(data)
                else:
                    st.warning("User not found!")
            else:
                st.error("Failed to fetch user details.")
        
        st.markdown("### 🗑️ Remove User")
        user_to_remove = st.text_input("Enter Username to Remove")
        if st.button("Remove User") and user_to_remove:
            response = requests.post(f"{FLASK_API_URL}/remove_user", json={"username": user_to_remove})
            if response.status_code == 200:
                result = response.json()
                if "message" in result:
                    st.success(result["message"])
                else:
                    st.warning("Unexpected response from server.")
            else:
                st.error("Failed to remove user")
    
    st.markdown("<div style='text-align: center; margin-top: 20px; font-size: 14px; color: gray;'>Developed for Windows Account Management by Huzaifa</div>", unsafe_allow_html=True)

# Conditional Rendering
if st.session_state.authenticated:
    dashboard()
else:
    login_page()
