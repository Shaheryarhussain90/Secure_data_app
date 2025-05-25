import streamlit as st
import hashlib
import json
import os
import time
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode
from hashlib import pbkdf2_hmac

# Data information
Data_file = "Secure_Data.json"
SALT = b"secure_Data_value"
Lockout_Duration = 60

# Session state setup
if "authenticated_user" not in st.session_state:
    st.session_state.authenticated_user = None

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = 0

# Load and save data
def load_data():
    if os.path.exists(Data_file):
        with open(Data_file, "r") as f:
            return json.load(f)
    return {}

def save_data(data):
    with open(Data_file, "w") as f:
        json.dump(data, f)

# Encryption functions
def generate_key(passkey):
    key = pbkdf2_hmac("sha256", passkey.encode(), SALT, 100000)
    return urlsafe_b64encode(key)

def hash_password(password):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), SALT, 100000).hex()

def encrypt_text(text, key):
    cipher = Fernet(generate_key(key))
    return cipher.encrypt(text.encode()).decode()

def decrypt_text(encrypted_text, key):
    try:
        cipher = Fernet(generate_key(key))
        return cipher.decrypt(encrypted_text.encode()).decode()
    except:
        return None

stored_data = load_data()

# Navigation
st.title("🔐 Secure Data Encryption System")
menu = ["Home", "Register", "Login", "Store Data", "Retrieve Data"]
choice = st.sidebar.selectbox("Navigation", menu)

if choice == "Home":
    st.subheader("Welcome to the Secure Data Encryption System!")
    st.markdown("""
    - Store data securely with encryption.
    - Retrieve data using a passkey.
    - Failed attempts trigger a lockout.
    """)

elif choice == "Register":
    st.subheader("Register New User")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Register"):
        if username and password:
            if username in stored_data:
                st.error("Username already exists!")
            else:
                stored_data[username] = {
                    "password": hash_password(password),
                    "data": []
                }
                save_data(stored_data)
                st.success("Registration successful!")
        else:
            st.error("Username and password are required.")

elif choice == "Login":
    st.subheader("Login")
    if time.time() < st.session_state.lockout_time:
        remaining = int(st.session_state.lockout_time - time.time())
        st.error(f"Account locked. Try again in {remaining} seconds.")
    else:
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")

        if st.button("Login"):
            if username in stored_data and stored_data[username]["password"] == hash_password(password):
                st.session_state.authenticated_user = username
                st.session_state.failed_attempts = 0
                st.success("Login successful!")
            else:
                st.session_state.failed_attempts += 1
                if st.session_state.failed_attempts >= 3:
                    st.session_state.lockout_time = time.time() + Lockout_Duration
                    st.error("Too many failed attempts. Account locked for 60 seconds.")
                else:
                    st.error(f"Invalid credentials. {3 - st.session_state.failed_attempts} attempts left.")

elif choice == "Store Data":
    if not st.session_state.authenticated_user:
        st.warning("Please login first")
    else:
        st.subheader("Store Encrypted Data")
        data = st.text_area("Data to encrypt")
        passkey = st.text_input("Encryption passkey", type="password")

        if st.button("Encrypt and Save"):
            if data and passkey:
                encrypted_data = encrypt_text(data, passkey)
                stored_data[st.session_state.authenticated_user]["data"].append(encrypted_data)
                save_data(stored_data)
                st.success("Data encrypted and stored!")
            else:
                st.error("Data and passkey are required.")

elif choice == "Retrieve Data":
    if not st.session_state.authenticated_user:
        st.warning("Please login first")
    else:
        st.subheader("Retrieve Data")
        user_data = stored_data.get(st.session_state.authenticated_user, {}).get("data", [])

        if not user_data:
            st.info("No data found")
        else:
            st.write("Your encrypted data entries:")
            for item in user_data:
                st.code(item)

            st.subheader("Decrypt Data")
            encrypted_input = st.text_area("Paste encrypted data here")
            passkey = st.text_input("Decryption passkey", type="password")

            if st.button("Decrypt"):
                if encrypted_input and passkey:
                    decrypted = decrypt_text(encrypted_input, passkey)
                    if decrypted:
                        st.success("Decrypted data:")
                        st.write(decrypted)
                    else:
                        st.error("Wrong passkey or corrupted data")
                else:
                    st.error("Encrypted data and passkey are required")