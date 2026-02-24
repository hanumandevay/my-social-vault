import streamlit as st
import pandas as pd
import gspread
from google.oauth2.service_account import Credentials
import hashlib, os, datetime

# --- 1. SUPER-SAFE CLOUD CONNECTION ---
def get_gspread_client():
    try:
        # Pull the raw secrets
        s = st.secrets["connections"]["gsheets"]
        
        # FIX: The "Self-Healing" Key Repair
        # This fixes the Byte 92 (\), Double Backslash (\\n), and Padding errors
        raw_key = s["private_key"]
        cleaned_key = raw_key.replace("\\n", "\n").replace("\\\\n", "\n").strip()
        
        # Build credentials dictionary manually
        creds_dict = {
            "type": s["type"],
            "project_id": s["project_id"],
            "private_key_id": s["private_key_id"],
            "private_key": cleaned_key,
            "client_email": s["client_email"],
            "client_id": s["client_id"],
            "auth_uri": s["auth_uri"],
            "token_uri": s["token_uri"],
            "auth_provider_x509_cert_url": s["auth_provider_x509_cert_url"],
            "client_x509_cert_url": s["client_x509_cert_url"]
        }
        
        scopes = ["https://www.googleapis.com", "https://www.googleapis.com"]
        creds = Credentials.from_service_account_info(creds_dict, scopes=scopes)
        return gspread.authorize(creds)
    except Exception as e:
        st.error(f"❌ CONNECTION ERROR: {e}")
        st.stop()

# Initialize Client and Spreadsheet
client = get_gspread_client()
# Use your specific Spreadsheet ID from the URL
SHEET_ID = "1LS2b2CIVSReYgoyMuPhYqKjQGfzKexfskxpjKve5HRU"
sh = client.open_by_key(SHEET_ID)

def load_sheet(name):
    try:
        worksheet = sh.worksheet(name)
        return pd.DataFrame(worksheet.get_all_records())
    except: return pd.DataFrame()

def save_to_sheet(df, name):
    try:
        worksheet = sh.worksheet(name)
        worksheet.clear()
        # Ensure IDs stay as strings
        if 'id' in df.columns: df['id'] = df['id'].astype(str)
        worksheet.update([df.columns.values.tolist()] + df.values.tolist())
        return True
    except Exception as e:
        st.error(f"❌ Cloud Sync Failed: {e}")
        return False

# --- 2. CONFIG & STATE ---
st.set_page_config(page_title="Arnav Social Cloud", layout="wide")
def hash_pass(p): return hashlib.sha256(str.encode(p)).hexdigest()

if "auth" not in st.session_state:
    st.session_state.update({"auth": False, "username": None, "uid": None, "role": "Guest", "all_roles": [], "active_tab": "🏠 Feed"})

# Load Global Data
users_df = load_sheet("Users")
social_df = load_sheet("Social")
follow_df = load_sheet("Followers")
msg_df = load_sheet("Messages")
posts_df = load_sheet("Posts")

# --- 3. AUTHENTICATION & RECOVERY ---
if not st.session_state.auth:
    st.title("🛡️ Arnav Secure Social")
    t1, t2, t3 = st.tabs(["🔓 Login", "📝 Register", "🔧 Recovery"])
    
    with t2:
        r_id = st.text_input("9-Digit ID:", max_chars=9, key="reg_id")
        r_name = st.text_input("Name:", key="reg_name")
        r_role = st.selectbox("Role:", ["Admin", "Me", "Guest"])
        r_key = st.text_input("Code:", type="password") if r_role != "Guest" else ""
        r_pass = st.text_input("Password:", type="password")
        if st.button("Register"):
            if not users_df.empty and str(r_id) in users_df['id'].astype(str).values: st.error("❌ ID exists!")
            elif r_id and r_name:
                valid = (r_role=="Admin" and r_key=="6419A") or (r_role=="Me" and r_key=="6419C") or (r_role=="Guest")
                if valid:
                    u_roles = "Admin,Me,Guest" if r_role=="Admin" else f"{r_role},Guest"
                    new_u = pd.DataFrame([{"id":str(r_id), "name":r_name, "password":hash_pass(r_pass), "roles":u_roles}])
                    save_to_sheet(pd.concat([users_df, new_u], ignore_index=True) if not users_df.empty else new_u, "Users")
                    st.success("✅ Registered! Switch to Login."); st.rerun()

    with t1:
        l_id = st.text_input("Enter ID:", key="l_id")
        l_p = st.text_input("Password:", type="password", key="l_p")
        if st.button("Login"):
            if not users_df.empty:
                u = users_df[(users_df['id'].astype(str) == str(l_id)) & (users_df['password'] == hash_pass(l_p))]
                if not u.empty:
                    st.session_state.update({"auth": True, "username": u.iloc[0]['name'], "uid": str(l_id), "all_roles": u.iloc[0]['roles'].split(",")})
                    st.rerun()
            st.error("❌ Login Failed.")
    st.stop()

# --- 4. SIDEBAR & SOCIAL FEATURES ---
with st.sidebar:
    st.title(f"👤 {st.session_state.username}")
    f_count = len(follow_df[follow_df['followed_id'].astype(str) == st.session_state.uid]) if not follow_df.empty else 0
    st.metric("Followers", f_count)
    st.divider()
    st.session_state.active_tab = st.radio("Navigate", ["🏠 Feed", "🔍 Find People", "📩 Messenger"])
    if st.button("Logout"): st.session_state.auth = False; st.rerun()

if st.session_state.active_tab == "🏠 Feed":
    st.header("🌎 Social Feed")
    if not posts_df.empty:
        for _, p in posts_df.iloc[::-1].iterrows():
            with st.container(border=True):
                st.subheader(f"👤 {p['uploader']}")
                st.write(f"📁 {p['name']}")
                l_count = len(social_df[(social_df['post_id']==p['post_id']) & (social_df['type']=='like')]) if not social_df.empty else 0
                if st.button(f"❤️ {l_count} Likes", key=f"lk_{p['post_id']}"):
                    new_l = pd.DataFrame([{"post_id":p['post_id'], "type":"like", "user":st.session_state.username, "content":""}])
                    save_to_sheet(pd.concat([social_df, new_l], ignore_index=True), "Social"); st.rerun()
