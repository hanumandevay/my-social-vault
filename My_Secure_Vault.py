import streamlit as st
from streamlit_gsheets import GSheetsConnection
import pandas as pd
import hashlib, os, sys

# --- 1. CLOUD CONNECTION ---
try:
    conn = st.connection("gsheets", type=GSheetsConnection)
except Exception as e:
    st.error("❌ SECRETS ERROR: Your Private Key is formatted incorrectly.")
    st.info("Ensure private_key in Secrets has quotes and all \\n symbols.")
    st.stop()

def load_sheet(name):
    try:
        df = conn.read(worksheet=name, ttl=0)
        return df if not df.empty else pd.DataFrame()
    except: return pd.DataFrame()

def save_to_sheet(df, name):
    try:
        if 'id' in df.columns: df['id'] = df['id'].astype(str)
        conn.update(worksheet=name, data=df)
    except Exception as e:
        st.error(f"❌ Failed to save to {name}. Check Service Account permissions.")

# --- 2. CONFIG & STATE ---
st.set_page_config(page_title="Arnav Social Cloud", layout="wide")
def hash_pass(p): return hashlib.sha256(str.encode(p)).hexdigest()

if "auth" not in st.session_state:
    st.session_state.update({
        "auth": False, "username": None, "uid": None, 
        "role": "Guest", "all_roles": [], "active_tab": "🏠 Feed"
    })

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
        r_id = st.text_input("9-Digit ID:", max_chars=9, key="r_id")
        r_name = st.text_input("Name:", key="r_n")
        r_role = st.selectbox("Role:", ["Admin", "Me", "Guest"], key="r_r")
        r_key = st.text_input("Code:", type="password") if r_role != "Guest" else ""
        r_pass = st.text_input("Private Password:", type="password", key="r_p")
        if st.button("Register"):
            if not users_df.empty and str(r_id) in users_df['id'].astype(str).values: st.error("❌ ID exists!")
            elif r_id and r_name and r_pass:
                valid = (r_role=="Admin" and r_key=="6419A") or (r_role=="Me" and r_key=="6419C") or (r_role=="Guest")
                if valid:
                    u_roles = "Admin,Me,Guest" if r_role=="Admin" else f"{r_role},Guest"
                    new_u = pd.DataFrame([{"id":str(r_id), "name":r_name, "password":hash_pass(r_pass), "roles":u_roles}])
                    save_to_sheet(pd.concat([users_df, new_u], ignore_index=True) if not users_df.empty else new_u, "Users")
                    st.success("✅ Registered! Switch to Login.")
                else: st.error("❌ Invalid Code.")

    with t3:
        st.subheader("🔧 Recovery")
        c_id = st.text_input("ID:", key="c_id")
        c_p = st.text_input("Pass:", type="password", key="c_p")
        tick_n = st.checkbox("Change Name")
        new_n = st.text_input("New Name:", disabled=not tick_n)
        confirm_del = st.checkbox("🗑️ DELETE ACCOUNT")
        if st.button("Apply / Delete"):
            if not users_df.empty and str(c_id) in users_df['id'].astype(str).values:
                idx = users_df.index[users_df['id'].astype(str) == str(c_id)].tolist()[0]
                if users_df.at[idx, 'password'] == hash_pass(c_p):
                    if confirm_del:
                        save_to_sheet(users_df.drop(idx), "Users"); st.warning("Deleted!"); st.rerun()
                    elif tick_n:
                        users_df.at[idx, 'name'] = new_n
                        save_to_sheet(users_df, "Users"); st.success("Updated!")

    with t1:
        l_id = st.text_input("ID:", key="l_id")
        l_p = st.text_input("Pass:", type="password", key="l_p")
        if st.button("Login"):
            if not users_df.empty:
                u = users_df[(users_df['id'].astype(str) == str(l_id)) & (users_df['password'] == hash_pass(l_p))]
                if not u.empty:
                    u_data = u.iloc[0]
                    st.session_state.update({
                        "auth": True, "username": u_data['name'], "uid": str(l_id), 
                        "role": u_data['roles'].split(",")[0], "all_roles": u_data['roles'].split(",")
                    })
                    st.rerun()
            st.error("❌ Login Failed.")
    st.stop()

# --- 4. SIDEBAR & MESSENGER ---
with st.sidebar:
    st.title(f"👤 {st.session_state.username}")
    st.caption(f"ID: {st.session_state.uid} | Mode: {st.session_state.role}")
    st.divider()
    st.session_state.role = st.selectbox("🔄 Switch Mode", st.session_state.all_roles, index=0)
    st.session_state.active_tab = st.radio("Navigate", ["🏠 Feed", "📤 Dashboard", "🔍 Find People", "📩 Messenger"])
    if st.button("Logout"): st.session_state.auth = False; st.rerun()

# --- 5. PAGE LOGIC ---
if st.session_state.active_tab == "📩 Messenger":
    st.header("📩 Messenger")
    target = st.selectbox("Select User:", [f"{r['id']} - {r['name']}" for _, r in users_df.iterrows() if str(r['id'])!=st.session_state.uid])
    if target:
        t_id = target.split(" - ")[0]
        cid = "-".join(sorted([st.session_state.uid, t_id]))
        if not msg_df.empty and 'chat_id' in msg_df.columns:
            for _, m in msg_df[msg_df['chat_id'] == cid].iterrows(): st.caption(f"**{m['sender']}**: {m['text']}")
        m_txt = st.text_input("Message...")
        if st.button("Send"):
            new_m = pd.DataFrame([{"chat_id":cid, "sender":st.session_state.username, "text":m_txt}])
            save_to_sheet(pd.concat([msg_df, new_m], ignore_index=True), "Messages"); st.rerun()

elif st.session_state.active_tab == "🔍 Find People":
    st.header("🔍 Find People")
    for _, r in users_df.iterrows():
        if str(r['id']) != st.session_state.uid:
            c1, c2 = st.columns([3, 1])
            c1.write(f"**{r['name']}**")
            is_f = not follow_df.empty and len(follow_df[(follow_df['follower_id'].astype(str)==st.session_state.uid) & (follow_df['followed_id'].astype(str)==str(r['id']))]) > 0
            if c2.button("Unfollow" if is_f else "Follow", key=f"f_{r['id']}"):
                if is_f: 
                    follow_df = follow_df.drop(follow_df[(follow_df['follower_id'].astype(str)==st.session_state.uid) & (follow_df['followed_id'].astype(str)==str(r['id']))].index)
                else: 
                    follow_df = pd.concat([follow_df, pd.DataFrame([{"follower_id":st.session_state.uid, "followed_id":str(r['id'])}])])
                save_to_sheet(follow_df, "Followers"); st.rerun()

elif st.session_state.active_tab == "🏠 Feed":
    st.header("🌎 Global Feed")
    if not posts_df.empty:
        for _, p in posts_df.iloc[::-1].iterrows():
            with st.container(border=True):
                st.subheader(f"👤 {p['uploader']}")
                st.write(f"📁 {p['name']}")
                st.button("❤️ Like", key=f"lk_{p['post_id']}")
    else: st.info("Feed is empty.")

elif st.session_state.active_tab == "📤 Dashboard":
    st.header("📤 My Dashboard")
    if st.session_state.role in ["Admin", "Me"]:
        up = st.file_uploader("Upload", type=["png", "jpg", "mp4"])
        if up and st.button("Post Now"):
            new_p = pd.DataFrame([{"post_id":hashlib.md5(up.name.encode()).hexdigest(), "name":up.name, "uploader":st.session_state.username, "uid":st.session_state.uid}])
            save_to_sheet(pd.concat([posts_df, new_p], ignore_index=True), "Posts"); st.success("✅ Posted!")
