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

    st.markdown(
        "<h1 style='text-align: center; color: #4A90E2;'>Windows User Management</h1>",
        unsafe_allow_html=True
    )
    st.write("Manage user accounts, check login activity, and remove accounts.")

    # Styled Logout Button
    st.markdown(
        """
        <style>
        .logout-btn {
            display: flex;
            justify-content: center;
        }
        </style>
        """,
        unsafe_allow_html=True
    )

    st.markdown('<div class="logout-btn">', unsafe_allow_html=True)
    if st.button("Logout", key="logout", help="Click to logout"):
        logout()
    st.markdown('</div>', unsafe_allow_html=True)

    FLASK_API_URL = "http://192.168.0.104:5000"

    # Layout Sections
    st.markdown("---")
    st.subheader("User Information")

    col1, col2 = st.columns([1, 1])  # Equal width columns

    with col1:
        st.markdown("### 📋 Fetch User Data")

        fetch_users = st.button("Fetch Users", key="fetch_users")
        fetch_active_users = st.button("Fetch Active Users", key="fetch_active_users")
        fetch_logs = st.button("Fetch Login Logs", key="fetch_logs")

        if fetch_users:
            response = requests.get(f"{FLASK_API_URL}/users")
            if response.status_code == 200:
                st.dataframe(pd.DataFrame(response.json(), columns=["Username"]))
            else:
                st.error("Failed to fetch users")

        if fetch_active_users:
            response = requests.get(f"{FLASK_API_URL}/active_users")
            if response.status_code == 200:
                st.dataframe(pd.DataFrame(response.json()))
            else:
                st.error("Failed to fetch active users")

        if fetch_logs:
            response = requests.get(f"{FLASK_API_URL}/logs")
            if response.status_code == 200:
                st.dataframe(pd.DataFrame(response.json()))
            else:
                st.error("Failed to fetch login logs")

    with col2:
        st.markdown("### 🔍 Search User Details")

        username = st.text_input("Enter Username to Fetch Details", key="fetch_user_input")
        if st.button("Get User Info", key="fetch_user") and username:
            response = requests.get(f"{FLASK_API_URL}/user/{username}")
            if response.status_code == 200:
                st.json(response.json())
            else:
                st.error("User not found!")

        st.markdown("### 🗑️ Remove User")

        user_to_remove = st.text_input("Enter Username to Remove", key="remove_user_input")
        if st.button("Remove User", key="remove_user") and user_to_remove:
            response = requests.post(f"{FLASK_API_URL}/remove_user", json={"username": user_to_remove})
            if response.status_code == 200:
                st.success(response.json()["message"])
            else:
                st.error("Failed to remove user")

    # Custom Footer
    st.markdown(
        """
        <div style="text-align: center; margin-top: 20px; font-size: 14px; color: gray;">
        Developed for Windows Account Management by Huzaifa
        </div>
        """,
        unsafe_allow_html=True
    )

# Conditional Rendering
if st.session_state.authenticated:
    dashboard()
else:
    login_page()
