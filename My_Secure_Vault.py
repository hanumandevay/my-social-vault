import streamlit as st
import os, sys, json, hashlib
from datetime import datetime
from streamlit.web import cli as stcli

# --- 1. AUTO-LAUNCHER (Works on Local & Cloud) ---
if __name__ == "__main__":
    if not st.runtime.exists():
        sys.argv = ["streamlit", "run", os.path.abspath(__file__)]
        sys.exit(stcli.main())

# --- 2. CLOUD STORAGE SETUP ---
# On the Cloud, we use relative paths (no C:\ drive)
VAULT, PENDING = "public_vault", "pending_files"
AUTH_FILE, DB_FILE, SOCIAL_FILE = "user_auth.json", "file_info.json", "social_data.json"

for p in [VAULT, PENDING]: 
    if not os.path.exists(p): os.makedirs(p)

def load_data(file, default):
    if os.path.exists(file):
        try:
            with open(file, "r") as f: return json.load(f)
        except: return default
    return default

def save_data(file, data):
    with open(file, "w") as f: json.dump(data, f, indent=4)

def hash_pass(password): return hashlib.sha256(str.encode(password)).hexdigest()

# --- 3. CONFIG & SAFE DATA INITIALIZATION ---
st.set_page_config(page_title="Arnav Social Vault", layout="wide")

users = load_data(AUTH_FILE, {})
db = load_data(DB_FILE, {})
social = load_data(SOCIAL_FILE, {})

# Fix for KeyError: Automatically add missing keys
for key in ["likes", "chats", "followers", "msgs"]:
    if key not in social: social[key] = {}

if "auth" not in st.session_state:
    st.session_state.update({"auth": False, "username": None, "uid": None, "all_roles": [], "active_tab": "🏠 My Dashboard"})

# --- 4. AUTHENTICATION (LOGIN / REGISTER / RECOVERY) ---
if not st.session_state.auth:
    st.title("🛡️ Arnav Secure Social Portal")
    t1, t2, t3 = st.tabs(["🔓 Login", "📝 Register", "🔧 Recovery & Delete"])

    with t2:
        st.subheader("New Registration")
        r_id = st.text_input("9-Digit ID:", max_chars=9, key="reg_id")
        r_name = st.text_input("Full Name:", key="reg_name")
        r_role = st.selectbox("Register As:", ["Admin", "Me", "Guest"], key="reg_role")
        r_key = st.text_input("Secret Code:", type="password", key="reg_k") if r_role != "Guest" else ""
        r_pass = st.text_input("Set Private Password:", type="password", key="reg_p")
        
        if st.button("Complete Registration"):
            if r_id in users: st.error("❌ ID already exists.")
            else:
                valid = (r_role=="Admin" and r_key=="6419A") or (r_role=="Me" and r_key=="6419C") or (r_role=="Guest")
                if valid and r_id and r_name and r_pass:
                    u_roles = ["Admin", "Me", "Guest"] if r_role == "Admin" else [r_role, "Guest"]
                    users[r_id] = {"password": hash_pass(r_pass), "name": r_name, "roles": u_roles}
                    save_data(AUTH_FILE, users); st.success("✅ Registered! Switch to Login.")
                else: st.error("❌ Invalid Code or missing info.")

    with t3:
        st.subheader("🔧 Recovery & 🗑️ Delete")
        c_id = st.text_input("Enter ID:", key="c_id")
        c_pass = st.text_input("Enter Password:", type="password", key="c_pass")
        st.divider()
        tick_n = st.checkbox("Change Name", key="tn")
        new_n = st.text_input("New Name:", disabled=not tick_n, key="vn")
        tick_p = st.checkbox("Change Password", key="tp")
        new_p = st.text_input("New Password:", type="password", disabled=not tick_p, key="vp")
        
        col1, col2 = st.columns(2)
        if col1.button("Apply Changes"):
            if c_id in users and users[c_id]["password"] == hash_pass(c_pass):
                if tick_n and new_n: users[c_id]["name"] = new_n
                if tick_p and new_p: users[c_id]["password"] = hash_pass(new_p)
                save_data(AUTH_FILE, users); st.success("✅ Updated!")
            else: st.error("Invalid ID/Password")

        st.divider()
        st.error("Danger Zone")
        confirm_del = st.checkbox("Confirm Permanent Deletion", key="del_tick")
        if col2.button("🗑️ Delete Account"):
            if confirm_del and c_id in users and users[c_id]["password"] == hash_pass(c_pass):
                del users[c_id]; save_data(AUTH_FILE, users); st.warning("Account Deleted."); st.rerun()
            else: st.error("Failed: Check password and tick box.")

    with t1:
        st.subheader("Login")
        l_id = st.text_input("Enter ID:", key="l_id")
        l_p = st.text_input("Private Password:", type="password", key="l_p")
        if st.button("Login"):
            if l_id in users and users[l_id]["password"] == hash_pass(l_p):
                u = users[l_id]
                u_roles = u.get("roles", ["Guest"])
                st.session_state.update({"auth": True, "username": u["name"], "uid": l_id, "all_roles": u_roles, "active_role": u_roles[0]})
                st.rerun()
            else: st.error("❌ Invalid ID or Password.")
    st.stop()

# --- 5. SIDEBAR (NAVIGATION & MESSENGER) ---
with st.sidebar:
    st.title(f"👤 {st.session_state.username}")
    st.caption(f"ID: {st.session_state.uid}")
    my_f = len(social["followers"].get(st.session_state.uid, []))
    st.write(f"🏆 **Followers:** {my_f}")
    st.divider()
    
    st.session_state.active_tab = st.radio("Navigate", ["🏠 My Dashboard", "🌎 Public Feed"])
    
    st.divider()
    st.subheader("📩 Messenger")
    chat_list = [f"{uid} ({users[uid]['name']})" for uid in users if uid != st.session_state.uid]
    chat_with = st.selectbox("Chat with:", chat_list) if chat_list else None
    
    if chat_with:
        target_id = chat_with.split(" (")[0]
        chat_key = "-".join(sorted([st.session_state.uid, target_id]))
        
        chat_history = social["msgs"].get(chat_key, [])
        for m in chat_history:
            st.caption(f"**{m['s']}**: {m['t']}")
            
        m_txt = st.text_input("Type...", key=f"msg_in_{chat_key}")
        if st.button("Send", key=f"send_{chat_key}"):
            if chat_key not in social["msgs"]: social["msgs"][chat_key] = []
            social["msgs"][chat_key].append({"s": st.session_state.username, "t": m_txt})
            save_data(SOCIAL_FILE, social); st.rerun()

    st.divider()
    if st.button("Logout", use_container_width=True): 
        st.session_state.auth = False; st.rerun()

# --- 6. PAGE LOGIC ---
if st.session_state.active_tab == "🏠 My Dashboard":
    st.header("🏠 My Dashboard")
    
    with st.expander("📤 Upload New Post"):
        up = st.file_uploader("Media", type=["png", "jpg", "mp4"])
        if up and st.button("Post Now"):
            f_path = os.path.join(PENDING, up.name)
            with open(f_path, "wb") as b: b.write(up.getbuffer())
            fid = hashlib.md5(up.name.encode()).hexdigest()
            db[fid] = {"n": up.name, "u": st.session_state.username, "uid": st.session_state.uid, "s": "pending"}
            save_data(DB_FILE, db); st.toast("Sent for approval!")

    st.subheader("🖼️ My Posts")
    my_posts = [fid for fid, info in db.items() if info.get("uid") == st.session_state.uid and info.get("s") == "approved"]
    cols = st.columns(3)
    for i, fid in enumerate(my_posts):
        path = os.path.join(VAULT, db[fid]["n"])
        with cols[i % 3]:
            if db[fid]["n"].lower().endswith(('.png', '.jpg')): st.image(path)
            else: st.video(path)
            if st.button("🗑️ Delete", key=f"del_{fid}"):
                db[fid]["s"] = "deleted"; save_data(DB_FILE, db); st.rerun()

else:
    st.header("🌎 Social Feed")
    with st.expander("🔍 Find People"):
        for uid, uinfo in users.items():
            if uid != st.session_state.uid:
                c1, c2 = st.columns([3, 1])
                c1.write(f"**{uinfo['name']}**")
                if st.session_state.uid not in social["followers"].get(uid, []):
                    if c2.button("Follow", key=f"fol_{uid}"):
                        if uid not in social["followers"]: social["followers"][uid] = []
                        social["followers"][uid].append(st.session_state.uid)
                        save_data(SOCIAL_FILE, social); st.rerun()

    approved = [fid for fid, info in db.items() if info.get("s") == "approved" and not info["n"].lower().endswith('.json')]
    for fid in reversed(approved):
        info = db[fid]
        with st.container(border=True):
            st.subheader(f"👤 {info['u']}")
            path = os.path.join(VAULT, info["n"])
            if os.path.exists(path):
                if info["n"].lower().endswith(('.png', '.jpg')): st.image(path, use_container_width=True)
                else: st.video(path)
                
                lks = social["likes"].get(fid, 0)
                if st.button(f"❤️ {lks} Likes", key=f"lk_{fid}"):
                    social["likes"][fid] = lks + 1
                    save_data(SOCIAL_FILE, social); st.rerun()
                
                with st.expander(f"💬 Comments ({len(social['chats'].get(fid, []))})"):
                    for c in social["chats"].get(fid, []): st.write(f"**{c['user']}**: {c['text']}")
                    c_in = st.text_input("Comment...", key=f"cin_{fid}")
                    if st.button("Post", key=f"cbtn_{fid}"):
                        if fid not in social["chats"]: social["chats"][fid] = []
                        social["chats"][fid].append({"user": st.session_state.username, "text": c_in})
                        save_data(SOCIAL_FILE, social); st.rerun()

# --- ADMIN PANEL ---
if "Admin" in st.session_state.all_roles:
    with st.sidebar.expander("🛠️ Admin Tools"):
        for fid, info in list(db.items()):
            if info["s"] == "pending":
                st.write(f"📄 {info['n']} - {info['u']}")
                if st.button("Approve", key=f"adm_{fid}"):
                    if os.path.exists(os.path.join(PENDING, info['n'])):
                        os.rename(os.path.join(PENDING, info['n']), os.path.join(VAULT, info['n']))
                    db[fid]["s"] = "approved"; save_data(DB_FILE, db); st.rerun()
