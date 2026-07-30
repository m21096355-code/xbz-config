import os, json, uuid, sqlite3, secrets, base64, time
from flask import Flask, request, jsonify, send_from_directory, Response
from datetime import datetime

app = Flask(__name__, static_folder="static")
DB = "xbz.db"
VERSION = "2.0.1"

def init_db():
    c = sqlite3.connect(DB)
    c.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL,
        uuid TEXT NOT NULL,
        protocol TEXT DEFAULT 'vless',
        domain TEXT DEFAULT '',
        port INTEGER DEFAULT 443,
        sni TEXT DEFAULT '',
        network TEXT DEFAULT 'ws',
        security TEXT DEFAULT 'none',
        path TEXT DEFAULT '/ws',
        enable INTEGER DEFAULT 1,
        up INTEGER DEFAULT 0,
        down INTEGER DEFAULT 0,
        total INTEGER DEFAULT 0,
        expiry INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login TIMESTAMP DEFAULT ''
    )""")
    c.commit(); c.close()

def get_db():
    conn = sqlite3.connect(DB); conn.row_factory = sqlite3.Row; return conn

def build_link(u):
    proto = u["protocol"]; uid = u["uuid"]
    domain = u["domain"] or "your-domain.com"
    port = u["port"] or 443; sni = u["sni"] or domain
    path = u["path"] or "/ws"; net = u["network"] or "ws"
    sec = u["security"] or "none"; email = u["email"]
    if proto == "vless":
        p = f"host={sni}&path={path}&type={net}"
        if sec == "tls": p += f"&security=tls&sni={sni}&fp=chrome"
        return f"vless://{uid}@{domain}:{port}?{p}#{email}"
    elif proto == "vmess":
        obj = {"v":"2","ps":email,"add":domain,"port":str(port),"id":uid,
               "aid":"0","scy":"auto","net":net,"type":"tcp","host":sni,"path":path,"tls":sec,"sni":sni}
        return "vmess://" + base64.b64encode(json.dumps(obj).encode()).decode()
    elif proto == "trojan":
        return f"trojan://{uid}@{domain}:{port}?type={net}&host={sni}&path={path}&security=tls&sni={sni}#{email}"
    return ""

# === Routes ===

@app.route("/")
def index():
    return send_from_directory("static", "index.html")

@app.route("/api/login", methods=["POST"])
def api_login():
    d = request.json
    if d.get("username") == "xbz" and d.get("password") == "xbz2026":
        return jsonify({"ok": True})
    return jsonify({"ok": False, "error": "نام کاربری یا رمز اشتباه است"}), 401

@app.route("/api/users")
def api_users():
    db = get_db()
    users = [dict(r) for r in db.execute("SELECT * FROM users ORDER BY id DESC").fetchall()]
    db.close()
    for u in users:
        u["link"] = build_link(u)
        u["total_used"] = u["up"] + u["down"]
        u["total_str"] = f"{u['total']/1073741824:.1f} GB" if u["total"] else "∞"
        u["used_str"] = f"{u['total_used']/1073741824:.2f} GB"
        u["up_str"] = f"{u['up']/1073741824:.2f} GB"
        u["down_str"] = f"{u['down']/1073741824:.2f} GB"
        if u["total"] > 0:
            u["usage_pct"] = min(100, int(u["total_used"] * 100 / u["total"]))
        else:
            u["usage_pct"] = 0
        exp = u["expiry"]
        if exp > 0:
            u["expiry_str"] = datetime.fromtimestamp(u["created_at"] and time.mktime(
                datetime.strptime(u["created_at"], "%Y-%m-%d %H:%M:%S").timetuple()
            ) + exp).strftime("%Y/%m/%d") if u["created_at"] else "∞"
        else:
            u["expiry_str"] = "∞"
    return jsonify(users)

@app.route("/api/users/add", methods=["POST"])
def api_add_user():
    d = request.json
    email = d.get("email", "user")
    proto = d.get("protocol", "vless")
    domain = d.get("domain", "")
    port = int(d.get("port", 443))
    sni = d.get("sni", "")
    network = d.get("network", "ws")
    security = d.get("security", "none")
    path = d.get("path", "/ws")
    total_gb = int(d.get("total", 0))
    expiry_days = int(d.get("expiry", 30))
    uid = str(uuid.uuid4())
    db = get_db()
    db.execute("""INSERT INTO users (email,uuid,protocol,domain,port,sni,network,security,path,total,expiry)
        VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
        (email, uid, proto, domain, port, sni, network, security, path,
         total_gb * 1073741824, expiry_days * 86400))
    db.commit()
    user = dict(db.execute("SELECT * FROM users WHERE uuid=?", (uid,)).fetchone())
    db.close()
    user["link"] = build_link(user)
    return jsonify({"ok": True, "user": user})

@app.route("/api/users/delete/<int:uid>", methods=["POST"])
def api_del_user(uid):
    db = get_db(); db.execute("DELETE FROM users WHERE id=?", (uid,))
    db.commit(); db.close()
    return jsonify({"ok": True})

@app.route("/api/users/toggle/<int:uid>", methods=["POST"])
def api_toggle_user(uid):
    db = get_db()
    r = db.execute("SELECT enable FROM users WHERE id=?", (uid,)).fetchone()
    if r:
        db.execute("UPDATE users SET enable=? WHERE id=?", (0 if r["enable"] else 1, uid))
    db.commit(); db.close()
    return jsonify({"ok": True})

@app.route("/api/users/batch", methods=["POST"])
def api_batch():
    d = request.json; count = min(int(d.get("count", 5)), 50)
    prefix = d.get("prefix", "user")
    proto = d.get("protocol", "vless")
    domain = d.get("domain", "")
    port = int(d.get("port", 443))
    sni = d.get("sni", "")
    network = d.get("network", "ws")
    security = d.get("security", "none")
    path = d.get("path", "/ws")
    total_gb = int(d.get("total", 0))
    expiry_days = int(d.get("expiry", 30))
    db = get_db(); created = []
    for i in range(count):
        uid = str(uuid.uuid4()); email = f"{prefix}-{i+1}"
        db.execute("""INSERT INTO users (email,uuid,protocol,domain,port,sni,network,security,path,total,expiry)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (email, uid, proto, domain, port, sni, network, security, path,
             total_gb * 1073741824, expiry_days * 86400))
        created.append({"email": email, "uuid": uid})
    db.commit(); db.close()
    return jsonify({"ok": True, "count": len(created), "users": created})

# Subscription
@app.route("/sub/<token>")
def subscription(token):
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE uuid=? AND enable=1", (token,)).fetchone()
    if not user: db.close(); return "Not Found", 404
    u = dict(user)
    db.execute("UPDATE users SET last_login=? WHERE id=?", (datetime.now().isoformat(), u["id"]))
    db.commit(); db.close()
    link = build_link(u)
    if not link: return "No config", 404
    exp = int(u["created_at"] and time.mktime(
        datetime.strptime(u["created_at"], "%Y-%m-%d %H:%M:%S").timetuple()
    ) + u["expiry"]) if u["created_at"] and u["expiry"] else 0
    headers = {
        "Content-Type": "text/plain; charset=utf-8",
        "Content-Disposition": f'attachment; filename="{u["email"]}.txt"',
        "Profile-Update-Interval": "12",
        "Profile-Title": "XBZ_MUSEOD",
        "Subscription-Userinfo": f"upload={u['up']};download={u['down']};total={u['total']};expire={exp}"
    }
    return Response(link, headers=headers)

@app.route("/sub/<token>/info")
def sub_info(token):
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE uuid=?", (token,)).fetchone()
    db.close()
    if not user: return jsonify({"error": "not found"}), 404
    u = dict(user)
    return jsonify({"email": u["email"], "uuid": u["uuid"], "enable": bool(u["enable"]),
        "up": u["up"], "down": u["down"], "total": u["total"],
        "protocol": u["protocol"], "created_at": u["created_at"]})

init_db()
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)
