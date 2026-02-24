import streamlit as st
import pandas as pd
import gspread
from google.oauth2.service_account import Credentials
import hashlib, os, datetime

# --- 1. BULLETPROOF CONNECTION ENGINE ---
def get_gspread_client():
    try:
        s = st.secrets["connections"]["gsheets"]
        # AUTO-FIX PADDING & NEWLINES
        raw_key = s["private_key"]
        cleaned_key = raw_key.replace("\\n", "\n").replace("\\\\n", "\n").strip()
        
        # Ensure correct PEM headers/footers
        if not cleaned_key.startswith("-----BEGIN"):
            cleaned_key = "-----BEGIN PRIVATE KEY-----\n" + cleaned_key
        if not cleaned_key.endswith("-----END PRIVATE KEY-----"):
            cleaned_key = cleaned_key + "\n-----END PRIVATE KEY-----"
            
        creds_dict = {
            "type": s["type"], "project_id": s["project_id"], "private_key_id": s["private_key_id"],
            "private_key": cleaned_key, "client_email": s["client_email"], "client_id": s["client_id"],
            "auth_uri": s["auth_uri"], "token_uri": s["token_uri"],
            "auth_provider_x509_cert_url": s["auth_provider_x509_cert_url"], "client_x509_cert_url": s["client_x509_cert_url"]
        }
        
        scopes = ["https://www.googleapis.com", "https://www.googleapis.com"]
        creds = Credentials.from_service_account_info(creds_dict, scopes=scopes)
        return gspread.authorize(creds)
    except Exception as e:
        st.error(f"❌ CONNECTION ERROR: {e}")
        st.stop()

# Initialize Client
client = get_gspread_client()
SHEET_ID = "1LS2b2CIVSReYgoyMuPhYqKjQGfzKexfskxpjKve5HRU"
sh = client.open_by_key(SHEET_ID)

def load_sheet(name):
    try:
        worksheet = sh.worksheet(name)
        data = worksheet.get_all_records()
        return pd.DataFrame(data) if data else pd.DataFrame()
    except: return pd.DataFrame()

def save_to_sheet(df, name):
    try:
        worksheet = sh.worksheet(name)
        worksheet.clear()
        if 'id' in df.columns: df['id'] = df['id'].astype(str)
        # Convert all data to string to avoid JSON serialisation errors
        df_str = df.astype(str)
        worksheet.update([df_str.columns.values.tolist()] + df_str.values.tolist())
        return True
    except Exception as e:
        st.error(f"❌ Cloud Sync Failed: {e}")
        return False

# --- 2. CONFIG & STATE ---
st.set_page_config(page_title="Arnav Social Cloud", layout="wide")
def hash_pass(p): return hashlib.sha256(str.encode(p)).hexdigest()

if "auth" not in st.session_state:
    st.session_state.update({"auth": False, "username": None, "uid": None, "all_roles": [], "active_tab": "🏠 Feed", "role": "Guest"})

# Load Global Data (Users, Social, Followers, Messages, Posts)
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
                    st.success("✅ Registered!"); st.rerun()

    with t3:
        st.subheader("🔧 Recovery / Delete")
        c_id = st.text_input("ID:", key="c_id")
        c_p = st.text_input("Pass:", type="password", key="c_p")
        confirm_del = st.checkbox("🗑️ DELETE ACCOUNT")
        if st.button("Apply / Delete"):
            if not users_df.empty and str(c_id) in users_df['id'].astype(str).values:
                idx = users_df.index[users_df['id'].astype(str) == str(c_id)]
                if users_df.at[idx.tolist()[0], 'password'] == hash_pass(c_p):
                    if confirm_del:
                        save_to_sheet(users_df.drop(idx), "Users"); st.warning("Deleted!"); st.rerun()

    with t1:
        l_id = st.text_input("Enter ID:", key="l_id")
        l_p = st.text_input("Password:", type="password", key="l_p")
        if st.button("Login"):
            if not users_df.empty:
                u = users_df[(users_df['id'].astype(str) == str(l_id)) & (users_df['password'] == hash_pass(l_p))]
                if not u.empty:
                    st.session_state.update({"auth": True, "username": u.iloc[0]['name'], "uid": str(l_id), "all_roles": u.iloc[0]['roles'].split(","), "role": u.iloc[0]['roles'].split(",")[0]})
                    st.rerun()
            st.error("❌ Login Failed.")
    st.stop()

# --- 4. SIDEBAR ---
with st.sidebar:
    st.title(f"👤 {st.session_state.username}")
    f_count = len(follow_df[follow_df['followed_id'].astype(str) == st.session_state.uid]) if not follow_df.empty else 0
    st.metric("Followers", f_count)
    st.divider()
    st.session_state.role = st.selectbox("🔄 Mode", st.session_state.all_roles)
    st.session_state.active_tab = st.radio("Navigate", ["🏠 Feed", "🔍 Find People", "📩 Messenger", "📤 Dashboard"])
    if st.button("Logout"): st.session_state.auth = False; st.rerun()

# --- 5. SOCIAL FEATURES (Likes, Comments, Followers, Messenger) ---
if st.session_state.active_tab == "🏠 Feed":
    st.header("🌎 Global Social Feed")
    if not posts_df.empty:
        for _, p in posts_df.iloc[::-1].iterrows():
            with st.container(border=True):
                st.subheader(f"👤 {p['uploader']}")
                st.write(f"📁 {p['name']}")
                l_count = len(social_df[(social_df['post_id']==p['post_id']) & (social_df['type']=='like')]) if not social_df.empty else 0
                if st.button(f"❤️ {l_count} Likes", key=f"lk_{p['post_id']}"):
                    new_l = pd.DataFrame([{"post_id":p['post_id'], "type":"like", "user":st.session_state.username, "content":""}])
                    save_to_sheet(pd.concat([social_df, new_l], ignore_index=True), "Social"); st.rerun()

elif st.session_state.active_tab == "🔍 Find People":
    st.header("🔍 Find People")
    for _, r in users_df.iterrows():
        if str(r['id']) != st.session_state.uid:
            c1, c2 = st.columns()
            c1.write(f"**{r['name']}**")
            is_f = not follow_df.empty and len(follow_df[(follow_df['follower_id'].astype(str)==st.session_state.uid) & (follow_df['followed_id'].astype(str)==str(r['id']))]) > 0
            if c2.button("Unfollow" if is_f else "Follow", key=f"f_{r['id']}"):
                if is_f: 
                    follow_df = follow_df.drop(follow_df[(follow_df['follower_id'].astype(str)==st.session_state.uid) & (follow_df['followed_id'].astype(str)==str(r['id']))].index)
                else: 
                    follow_df = pd.concat([follow_df, pd.DataFrame([{"follower_id":st.session_state.uid, "followed_id":str(r['id'])}])])
                save_to_sheet(follow_df, "Followers"); st.rerun()

elif st.session_state.active_tab == "📩 Messenger":
    st.header("📩 Private Messenger")
    target = st.selectbox("Select User:", [f"{r['id']} - {r['name']}" for _, r in users_df.iterrows() if str(r['id'])!=st.session_state.uid])
    if target:
        t_id = target.split(" - ")[0]
        cid = "-".join(sorted([st.session_state.uid, t_id]))
        if not msg_df.empty and 'chat_id' in msg_df.columns:
            for _, m in msg_df[msg_df['chat_id'] == cid].iterrows(): st.caption(f"**{m['sender']}**: {m['text']}")
        m_txt = st.text_input("Message...", key="msg_in")
        if st.button("Send"):
            new_m = pd.DataFrame([{"chat_id":cid, "sender":st.session_state.username, "text":m_txt}])
            save_to_sheet(pd.concat([msg_df, new_m], ignore_index=True), "Messages"); st.rerun()

elif st.session_state.active_tab == "📤 Dashboard":
    st.header("📤 Dashboard")
    if st.session_state.role in ["Admin", "Me"]:
        up = st.file_uploader("Upload", type=["png", "jpg", "mp4"])
        if up and st.button("Post Now"):
            new_p = pd.DataFrame([{"post_id":hashlib.md5(up.name.encode()).hexdigest(), "name":up.name, "uploader":st.session_state.username, "uid":st.session_state.uid}])
            save_to_sheet(pd.concat([posts_df, new_p], ignore_index=True), "Posts"); st.success("✅ Posted!")
