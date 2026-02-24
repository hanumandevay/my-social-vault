import streamlit as st
from streamlit_gsheets import GSheetsConnection
import pandas as pd
import hashlib, os, datetime
from streamlit.web import cli as stcli

# --- 1. AUTO-LAUNCHER ---
if __name__ == "__main__":
    if not st.runtime.exists():
        import sys
        sys.argv = ["streamlit", "run", os.path.abspath(__file__)]
        from streamlit.web import cli as stcli
        sys.exit(stcli.main())

# --- 2. CLOUD CONNECTION & DATA HELPERS ---
# Requires Service Account JSON in Streamlit Secrets
try:
    conn = st.connection("gsheets", type=GSheetsConnection)
except Exception as e:
    st.error("⚠️ Secrets Error: Check your Private Key formatting in Streamlit Settings.")
    st.stop()

def load_sheet(name):
    try:
        df = conn.read(worksheet=name, ttl=0)
        return df if not df.empty else pd.DataFrame()
    except:
        return pd.DataFrame()

def save_to_sheet(df, name):
    if 'id' in df.columns: df['id'] = df['id'].astype(str)
    conn.update(worksheet=name, data=df)

# --- 3. CONFIG & STATE ---
st.set_page_config(page_title="Arnav Social Cloud", layout="wide")
def hash_pass(p): return hashlib.sha256(str.encode(p)).hexdigest()

if "auth" not in st.session_state:
    st.session_state.update({
        "auth": False, "username": None, "uid": None, 
        "role": "Guest", "all_roles": [], "active_tab": "🏠 Feed"
    })

# Pre-load Data
users_df = load_sheet("Users")
social_df = load_sheet("Social") # post_id, type, user, content
follow_df = load_sheet("Followers") # follower_id, followed_id
msg_df = load_sheet("Messages") # chat_id, sender, text
posts_df = load_sheet("Posts") # post_id, name, uploader, uid

# --- 4. AUTHENTICATION & RECOVERY ---
if not st.session_state.auth:
    st.title("🛡️ Arnav Secure Social")
    t1, t2, t3 = st.tabs(["🔓 Login", "📝 Register", "🔧 Recovery & Delete"])
    
    with t2:
        st.subheader("Create Profile")
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
                else: st.error("❌ Invalid Role Code.")

    with t3:
        st.subheader("🔧 Recovery")
        c_id = st.text_input("ID:", key="c_id")
        c_p = st.text_input("Current Pass:", type="password", key="c_p")
        tick_n = st.checkbox("Change Name")
        new_n = st.text_input("New Name:", disabled=not tick_n)
        tick_p = st.checkbox("Change Password")
        new_p = st.text_input("New Password:", type="password", disabled=not tick_p)
        confirm_del = st.checkbox("🗑️ DELETE ACCOUNT PERMANENTLY")
        
        if st.button("Apply / Delete"):
            if not users_df.empty and str(c_id) in users_df['id'].astype(str).values:
                idx = users_df.index[users_df['id'].astype(str) == str(c_id)]
                if users_df.at[idx.tolist()[0], 'password'] == hash_pass(c_p):
                    if confirm_del:
                        save_to_sheet(users_df.drop(idx), "Users"); st.warning("Deleted!"); st.rerun()
                    else:
                        if tick_n:
                            if new_n == users_df.at[idx.tolist()[0], 'name']: st.warning("Same Name!")
                            else: users_df.at[idx.tolist()[0], 'name'] = new_n
                        if tick_p: users_df.at[idx.tolist()[0], 'password'] = hash_pass(new_p)
                        save_to_sheet(users_df, "Users"); st.success("Updated!")
                else: st.error("Wrong Password")

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

# --- 5. SIDEBAR (SWIPE PANEL) ---
with st.sidebar:
    st.title(f"👤 {st.session_state.username}")
    st.caption(f"ID: {st.session_state.uid}")
    f_count = len(follow_df[follow_df['followed_id'].astype(str) == st.session_state.uid]) if not follow_df.empty else 0
    st.metric("Followers", f_count)
    st.divider()
    # TRIPLE ROLE SWITCHER
    st.session_state.role = st.radio("🔄 Switch Mode", st.session_state.all_roles, index=st.session_state.all_roles.index(st.session_state.role))
    st.divider()
    st.session_state.active_tab = st.radio("Navigate", ["🏠 Feed", "📤 Dashboard", "🔍 Find People", "📩 Messenger"])
    if st.button("Logout"): st.session_state.auth = False; st.rerun()

# --- 6. PAGE LOGIC ---
if st.session_state.active_tab == "📩 Messenger":
    st.header("📩 Messenger")
    target = st.selectbox("Chat with:", [f"{r['id']} - {r['name']}" for _, r in users_df.iterrows() if str(r['id'])!=st.session_state.uid])
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
            c1, c2 = st.columns([3,1])
            c1.write(f"**{r['name']}**")
            is_f = not follow_df.empty and len(follow_df[(follow_df['follower_id'].astype(str)==st.session_state.uid) & (follow_df['followed_id'].astype(str)==str(r['id']))]) > 0
            if c2.button("Unfollow" if is_f else "Follow", key=f"f_{r['id']}"):
                if is_f: follow_df = follow_df.drop(follow_df[(follow_df['follower_id'].astype(str)==st.session_state.uid) & (follow_df['followed_id'].astype(str)==str(r['id']))].index)
                else: follow_df = pd.concat([follow_df, pd.DataFrame([{"follower_id":st.session_state.uid, "followed_id":str(r['id'])}])])
                save_to_sheet(follow_df, "Followers"); st.rerun()

elif st.session_state.active_tab == "🏠 Feed":
    st.header("🌎 Global Feed")
    if not posts_df.empty:
        for _, p in posts_df.iloc[::-1].iterrows():
            with st.container(border=True):
                st.subheader(f"👤 {p['uploader']}")
                st.write(f"Post ID: {p['post_id']}") # In cloud, use URL if using S3/ImgBB
                # Likes/Comments logic here as per previous steps
                st.button(f"❤️ Like", key=f"l_{p['post_id']}")

elif st.session_state.active_tab == "📤 Dashboard":
    st.header("🏠 My Dashboard")
    if st.session_state.role in ["Admin", "Me"]:
        up = st.file_uploader("Upload", type=["png", "jpg", "mp4"])
        if up and st.button("Post"):
            new_p = pd.DataFrame([{"post_id":hashlib.md5(up.name.encode()).hexdigest(), "name":up.name, "uploader":st.session_state.username, "uid":st.session_state.uid}])
            save_to_sheet(pd.concat([posts_df, new_p], ignore_index=True), "Posts"); st.success("Uploaded!")
