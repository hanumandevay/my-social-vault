import streamlit as st
from streamlit_gsheets import GSheetsConnection
import pandas as pd
import hashlib, os, json

# --- 1. CLOUD CONNECTION ---
conn = st.connection("gsheets", type=GSheetsConnection)

def load_cloud_users():
    try:
        # Read the Google Sheet
        df = conn.read(ttl=0) 
        if df.empty: return []
        # Ensure ID is always a string
        df['id'] = df['id'].astype(str)
        return df.to_dict('records')
    except Exception as e:
        return []

def save_user_to_cloud(new_user):
    existing_users = load_cloud_users()
    existing_users.append(new_user)
    df = pd.DataFrame(existing_users)
    # Push update to Google Sheet
    conn.update(data=df)

# --- 2. APP SETUP ---
st.set_page_config(page_title="Arnav Cloud Social", layout="wide")
def hash_pass(password): return hashlib.sha256(str.encode(password)).hexdigest()

if "auth" not in st.session_state:
    st.session_state.update({"auth": False, "username": None, "uid": None, "role": "Guest"})

# --- 3. LOGIN & REGISTER ---
st.title("🛡️ Arnav Cloud-Sync Portal")
tab1, tab2 = st.tabs(["🔓 Login", "📝 Register"])

all_users = load_cloud_users()

with tab2:
    st.subheader("Create Account")
    r_id = st.text_input("9-Digit ID:", max_chars=9, key="reg_id")
    r_name = st.text_input("Full Name:", key="reg_name")
    r_role = st.selectbox("Role:", ["Admin", "Me", "Guest"], key="reg_role")
    
    # Secret Codes
    r_key = ""
    if r_role != "Guest":
        r_key = st.text_input(f"Enter {r_role} Code:", type="password")
    
    r_pass = st.text_input("Set Private Password:", type="password", key="reg_pass")
    
    if st.button("Register to Cloud"):
        valid = (r_role=="Admin" and r_key=="6419A") or (r_role=="Me" and r_key=="6419C") or (r_role=="Guest")
        
        if any(u['id'] == str(r_id) for u in all_users):
            st.error("❌ ID already exists in the Sheet!")
        elif valid and r_id and r_name and r_pass:
            new_user = {
                "id": str(r_id), 
                "name": r_name, 
                "password": hash_pass(r_pass), 
                "roles": r_role
            }
            save_user_to_cloud(new_user)
            st.success("✅ Saved to Google Sheet! Please Login.")
        else:
            st.error("❌ Invalid Code or missing info.")

with tab1:
    st.subheader("Login")
    l_id = st.text_input("Enter ID:", key="l_id")
    l_p = st.text_input("Enter Password:", type="password", key="l_p")
    if st.button("Secure Login"):
        user = next((u for u in all_users if str(u['id']) == l_id and u['password'] == hash_pass(l_p)), None)
        if user:
            st.session_state.update({"auth": True, "username": user['name'], "uid": l_id, "role": user['roles']})
            st.rerun()
        else:
            st.error("❌ Invalid ID or Password.")

# --- 4. MAIN APP ---
if st.session_state.auth:
    st.sidebar.title(f"👤 {st.session_state.username}")
    st.sidebar.info(f"Role: {st.session_state.role}")
    if st.sidebar.button("Logout"):
        st.session_state.auth = False
        st.rerun()
    
    st.header(f"Welcome to the Feed, {st.session_state.username}!")
    st.write("Your data is now safely synced with Google Sheets.")
