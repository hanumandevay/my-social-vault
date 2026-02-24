import streamlit as st
from streamlit_gsheets import GSheetsConnection
import pandas as pd
import hashlib, os, datetime

# --- 1. CLOUD CONNECTION ---
conn = st.connection("gsheets", type=GSheetsConnection)

def load_sheet(name):
    try: return conn.read(worksheet=name, ttl=0)
    except: return pd.DataFrame()

def save_to_sheet(df, name):
    conn.update(worksheet=name, data=df)

# --- 2. CONFIG & STATE ---
st.set_page_config(page_title="Arnav Social Cloud", layout="wide")
def hash_pass(p): return hashlib.sha256(str.encode(p)).hexdigest()

if "auth" not in st.session_state:
    st.session_state.update({"auth": False, "username": None, "uid": None, "role": "Guest", "tab": "🏠 Feed"})

# Load Data
users_df = load_sheet("Users")
social_df = load_sheet("Social")
follow_df = load_sheet("Followers") # New Tab: follower_id, followed_id

# --- 3. AUTH & RECOVERY ---
if not st.session_state.auth:
    st.title("🛡️ Arnav Secure Social")
    t1, t2, t3 = st.tabs(["🔓 Login", "📝 Register", "🔧 Recovery"])
    
    with t2:
        r_id = st.text_input("9-Digit ID:", max_chars=9)
        r_name = st.text_input("Name:")
        r_role = st.selectbox("Role:", ["Admin", "Me", "Guest"])
        r_key = st.text_input("Code:", type="password") if r_role != "Guest" else ""
        r_pass = st.text_input("Password:", type="password")
        if st.button("Register"):
            if not users_df.empty and str(r_id) in users_df['id'].astype(str).values: st.error("Exists!")
            elif r_id and r_name and r_pass:
                valid = (r_role=="Admin" and r_key=="6419A") or (r_role=="Me" and r_key=="6419C") or (r_role=="Guest")
                if valid:
                    new_u = pd.DataFrame([{"id":str(r_id), "name":r_name, "password":hash_pass(r_pass), "role":r_role}])
                    save_to_sheet(pd.concat([users_df, new_u], ignore_index=True), "Users")
                    st.success("Registered!")

    with t3:
        c_id = st.text_input("ID:", key="c_id")
        c_p = st.text_input("Pass:", type="password", key="c_p")
        if st.button("Delete Account"):
            if not users_df.empty and str(c_id) in users_df['id'].astype(str).values:
                idx = users_df.index[users_df['id'].astype(str) == str(c_id)]
                if users_df.at[idx[0], 'password'] == hash_pass(c_p):
                    save_to_sheet(users_df.drop(idx), "Users"); st.warning("Deleted!"); st.rerun()

    with t1:
        l_id = st.text_input("ID:", key="l_id")
        l_p = st.text_input("Pass:", type="password", key="l_p")
        if st.button("Login"):
            if not users_df.empty:
                u = users_df[(users_df['id'].astype(str) == str(l_id)) & (users_df['password'] == hash_pass(l_p))]
                if not u.empty:
                    st.session_state.update({"auth": True, "username": u.iloc[0]['name'], "uid": str(l_id), "role": u.iloc[0]['role']})
                    st.rerun()
    st.stop()

# --- 4. SIDEBAR & FOLLOWERS ---
with st.sidebar:
    st.title(f"👤 {st.session_state.username}")
    # Show Follower Count
    f_count = len(follow_df[follow_df['followed_id'].astype(str) == st.session_state.uid]) if not follow_df.empty else 0
    st.metric("Followers", f_count)
    
    st.session_state.tab = st.radio("Menu", ["🏠 Feed", "📤 Dashboard", "🔍 Find People"])
    if st.button("Logout"): st.session_state.auth = False; st.rerun()

# --- 5. APP PAGES ---
if st.session_state.tab == "🔍 Find People":
    st.header("🔍 Find People to Follow")
    for _, row in users_df.iterrows():
        if str(row['id']) != st.session_state.uid:
            c1, c2 = st.columns([3,1])
            c1.write(f"**{row['name']}** ({row['role']})")
            is_following = not follow_df.empty and len(follow_df[(follow_df['follower_id'].astype(str) == st.session_state.uid) & (follow_df['followed_id'].astype(str) == str(row['id']))]) > 0
            if c2.button("Unfollow" if is_following else "Follow", key=f"f_{row['id']}"):
                if is_following:
                    follow_df = follow_df.drop(follow_df[(follow_df['follower_id'].astype(str) == st.session_state.uid) & (follow_df['followed_id'].astype(str) == str(row['id']))].index)
                else:
                    new_f = pd.DataFrame([{"follower_id": st.session_state.uid, "followed_id": str(row['id'])}])
                    follow_df = pd.concat([follow_df, new_f], ignore_index=True)
                save_to_sheet(follow_df, "Followers"); st.rerun()

elif st.session_state.tab == "🏠 Feed":
    st.header("🌎 Social Feed")
    posts_df = load_sheet("Posts")
    if not posts_df.empty:
        for _, p in posts_df.iterrows():
            with st.container(border=True):
                st.subheader(f"👤 {p['uploader']}")
                st.write(f"📁 File: {p['name']}")
                # Likes
                lks = len(social_df[(social_df['post_id'] == p['post_id']) & (social_df['type'] == 'like')]) if not social_df.empty else 0
                if st.button(f"❤️ {lks} Likes", key=f"lk_{p['post_id']}"):
                    new_l = pd.DataFrame([{"post_id": p['post_id'], "type": "like", "user": st.session_state.username, "content": ""}])
                    save_to_sheet(pd.concat([social_df, new_l], ignore_index=True), "Social"); st.rerun()

elif st.session_state.tab == "📤 Dashboard":
    st.header("📤 My Dashboard")
    if st.session_state.role in ["Admin", "Me"]:
        up = st.file_uploader("Upload", type=["png", "jpg", "mp4"])
        if up and st.button("Post"):
            p_df = load_sheet("Posts")
            new_p = pd.DataFrame([{"post_id": hashlib.md5(up.name.encode()).hexdigest(), "name": up.name, "uploader": st.session_state.username}])
            save_to_sheet(pd.concat([p_df, new_p], ignore_index=True), "Posts"); st.success("Uploaded!")
