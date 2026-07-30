import os, json, uuid, sqlite3, secrets, base64, time
from flask import Flask, request, jsonify, send_from_directory, Response
from datetime import datetime

app = Flask(__name__, static_folder="static")
DB = "xbz.db"
VERSION = "2.0.6"

def init_db():
    c = sqlite3.connect(DB)
    c.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL, uuid TEXT NOT NULL,
        protocol TEXT DEFAULT 'vless', domain TEXT DEFAULT '',
        port INTEGER DEFAULT 443, sni TEXT DEFAULT '',
        network TEXT DEFAULT 'ws', security TEXT DEFAULT 'none',
        path TEXT DEFAULT '/ws', enable INTEGER DEFAULT 1,
        up INTEGER DEFAULT 0, down INTEGER DEFAULT 0,
        total INTEGER DEFAULT 0, expiry INTEGER DEFAULT 0,
        comment TEXT DEFAULT '', created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login TIMESTAMP DEFAULT ''
    )""")
    c.commit(); c.close()

def get_db():
    conn = sqlite3.connect(DB); conn.row_factory = sqlite3.Row; return conn

def build_link(u):
    proto, uid = u["protocol"], u["uuid"]
    domain = u["domain"] or "your-domain.com"
    port = u["port"] or 443; sni = u["sni"] or domain
    path = u["path"] or "/ws"; net = u["network"] or "ws"
    sec = u["security"] or "none"; email = u["email"]
    if proto == "vless":
        p = f"host={sni}&path={path}&type={net}"
        if sec == "tls": p += f"&security=tls&sni={sni}&fp=chrome"
        return f"vless://{uid}@{domain}:{port}?{p}#{email}"
    elif proto == "vmess":
        obj = {"v":"2","ps":email,"add":domain,"port":str(port),"id":uid,"aid":"0","scy":"auto","net":net,"type":"tcp","host":sni,"path":path,"tls":sec,"sni":sni}
        return "vmess://" + base64.b64encode(json.dumps(obj).encode()).decode()
    elif proto == "trojan":
        return f"trojan://{uid}@{domain}:{port}?type={net}&host={sni}&path={path}&security=tls&sni={sni}#{email}"
    return ""

def enrich(u):
    u = dict(u)
    u["link"] = build_link(u)
    u["total_used"] = u["up"] + u["down"]
    u["total_str"] = f"{u['total']/1073741824:.1f} GB" if u["total"] else "∞"
    u["used_str"] = f"{u['total_used']/1073741824:.2f} GB"
    u["up_str"] = f"{u['up']/1073741824:.2f} GB"
    u["down_str"] = f"{u['down']/1073741824:.2f} GB"
    u["usage_pct"] = min(100, int(u["total_used"] * 100 / u["total"])) if u["total"] > 0 else 0
    now = time.time()
    if u["expiry"] and u["created_at"]:
        try:
            created = time.mktime(datetime.strptime(u["created_at"], "%Y-%m-%d %H:%M:%S").timetuple())
            u["expiry_ts"] = int(created + u["expiry"])
            u["expiry_str"] = datetime.fromtimestamp(u["expiry_ts"]).strftime("%Y/%m/%d") if u["expiry_ts"] > now else "منقضی شده"
            u["is_expired"] = u["expiry_ts"] < now
        except: u["expiry_str"] = "∞"; u["is_expired"] = False
    else:
        u["expiry_str"] = "∞"; u["is_expired"] = False; u["expiry_ts"] = 0
    return u

@app.route("/")
def index(): return send_from_directory("static", "index.html")
@app.route("/share/<token>")
def share_page(token): return send_from_directory("static", "index.html")

# === API ===
@app.route("/api/login", methods=["POST"])
def api_login():
    d = request.json
    if d.get("username") == "xbz" and d.get("password") == "xbz2026":
        return jsonify({"ok": True})
    return jsonify({"ok": False, "error": "نام کاربری یا رمز اشتباه است"}), 401

@app.route("/api/users")
def api_users():
    db = get_db(); users = [enrich(r) for r in db.execute("SELECT * FROM users ORDER BY id DESC").fetchall()]; db.close()
    return jsonify(users)

@app.route("/api/users/add", methods=["POST"])
def api_add_user():
    d = request.json; uid = str(uuid.uuid4())
    db = get_db()
    db.execute("""INSERT INTO users (email,uuid,protocol,domain,port,sni,network,security,path,total,expiry,comment)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
        (d.get("email","user"), uid, d.get("protocol","vless"), d.get("domain",""),
         int(d.get("port",443)), d.get("sni",""), d.get("network","ws"), d.get("security","none"),
         d.get("path","/ws"), int(d.get("total",0))*1073741824, int(d.get("expiry",30))*86400, d.get("comment","")))
    db.commit()
    user = enrich(db.execute("SELECT * FROM users WHERE uuid=?", (uid,)).fetchone())
    db.close()
    return jsonify({"ok": True, "user": user})

@app.route("/api/users/update/<int:uid>", methods=["POST"])
def api_update_user(uid):
    d = request.json; db = get_db()
    fields = []; vals = []
    for k in ["email","protocol","domain","sni","network","security","path","comment"]:
        if k in d: fields.append(f"{k}=?"); vals.append(d[k])
    if "port" in d: fields.append("port=?"); vals.append(int(d["port"]))
    if "total" in d: fields.append("total=?"); vals.append(int(d["total"])*1073741824)
    if "expiry" in d: fields.append("expiry=?"); vals.append(int(d["expiry"])*86400)
    if fields: vals.append(uid); db.execute(f"UPDATE users SET {','.join(fields)} WHERE id=?", vals)
    db.commit(); db.close()
    return jsonify({"ok": True})

@app.route("/api/users/delete/<int:uid>", methods=["POST"])
def api_del_user(uid):
    db = get_db(); db.execute("DELETE FROM users WHERE id=?", (uid,)); db.commit(); db.close()
    return jsonify({"ok": True})

@app.route("/api/users/toggle/<int:uid>", methods=["POST"])
def api_toggle_user(uid):
    db = get_db(); r = db.execute("SELECT enable FROM users WHERE id=?", (uid,)).fetchone()
    if r: db.execute("UPDATE users SET enable=? WHERE id=?", (0 if r["enable"] else 1, uid))
    db.commit(); db.close()
    return jsonify({"ok": True})

@app.route("/api/users/batch", methods=["POST"])
def api_batch():
    d = request.json; count = min(int(d.get("count",5)), 50); prefix = d.get("prefix","user")
    db = get_db(); created = []
    for i in range(count):
        uid = str(uuid.uuid4()); email = f"{prefix}-{i+1}"
        db.execute("""INSERT INTO users (email,uuid,protocol,domain,port,sni,network,security,path,total,expiry)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (email, uid, d.get("protocol","vless"), d.get("domain",""), int(d.get("port",443)),
             d.get("sni",""), d.get("network","ws"), d.get("security","none"), d.get("path","/ws"),
             int(d.get("total",0))*1073741824, int(d.get("expiry",30))*86400))
        created.append({"email": email, "uuid": uid})
    db.commit(); db.close()
    return jsonify({"ok": True, "count": len(created), "users": created})

@app.route("/api/users/duplicate/<int:uid>", methods=["POST"])
def api_duplicate_user(uid):
    db = get_db()
    u = db.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    if not u: db.close(); return jsonify({"error":"not found"}), 404
    u = dict(u); new_uuid = str(uuid.uuid4()); new_email = u["email"] + "-copy"
    db.execute("""INSERT INTO users (email,uuid,protocol,domain,port,sni,network,security,path,total,expiry,comment)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
        (new_email, new_uuid, u["protocol"], u["domain"], u["port"], u["sni"],
         u["network"], u["security"], u["path"], u["total"], u["expiry"], u["comment"]))
    db.commit(); db.close()
    return jsonify({"ok": True, "uuid": new_uuid, "email": new_email})

@app.route("/api/users/delete-all", methods=["POST"])
def api_delete_all():
    db = get_db(); db.execute("DELETE FROM users"); db.commit(); db.close()
    return jsonify({"ok": True})

@app.route("/api/users/search")
def api_search_users():
    q = request.args.get("q", "").lower()
    db = get_db(); users = [enrich(r) for r in db.execute("SELECT * FROM users ORDER BY id DESC").fetchall()]; db.close()
    if q: users = [u for u in users if q in u["email"].lower() or q in u["uuid"].lower()]
    return jsonify(users)

@app.route("/api/stats")
def api_stats():
    db = get_db(); users = [enrich(r) for r in db.execute("SELECT * FROM users").fetchall()]; db.close()
    total = len(users); active = sum(1 for u in users if u["enable"])
    expired = sum(1 for u in users if u.get("is_expired"))
    traffic = sum(u["total_used"] for u in users)
    return jsonify({"total": total, "active": active, "expired": expired, "traffic_gb": round(traffic/1073741824, 2)})

@app.route("/api/link/<int:uid>")
def gen_link(uid):
    db = get_db(); u = db.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone(); db.close()
    if not u: return jsonify({"error": "not found"}), 404
    u = enrich(u)
    return jsonify({"link": u["link"], "email": u["email"], "uuid": u["uuid"]})

@app.route("/api/export")
def export_data():
    db = get_db(); users = [enrich(r) for r in db.execute("SELECT * FROM users").fetchall()]; db.close()
    return jsonify({"users": [{"email":u["email"],"uuid":u["uuid"],"protocol":u["protocol"],
        "domain":u["domain"],"port":u["port"],"sni":u["sni"],"network":u["network"],
        "security":u["security"],"enable":bool(u["enable"]),"total":u["total"],"expiry":u["expiry"]} for u in users], "version": VERSION})

@app.route("/api/import", methods=["POST"])
def import_data():
    d = request.json; users = d.get("users", []); db = get_db(); count = 0
    for u in users:
        uid = u.get("uuid", str(uuid.uuid4()))
        db.execute("""INSERT OR REPLACE INTO users (email,uuid,protocol,domain,port,sni,network,security,path,enable,total,expiry)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (u.get("email","imported"), uid, u.get("protocol","vless"), u.get("domain",""),
             int(u.get("port",443)), u.get("sni",""), u.get("network","ws"), u.get("security","none"),
             u.get("path","/ws"), 1 if u.get("enable",True) else 0, int(u.get("total",0)), int(u.get("expiry",0))))
        count += 1
    db.commit(); db.close()
    return jsonify({"ok": True, "imported": count})

# Subscription
@app.route("/sub/<token>")
def subscription(token):
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE uuid=? AND enable=1", (token,)).fetchone()
    if not user: db.close(); return "Not Found", 404
    u = dict(user); db.execute("UPDATE users SET last_login=? WHERE id=?", (datetime.now().isoformat(), u["id"]))
    db.commit(); db.close()
    link = build_link(u)
    if not link: return "No config", 404
    headers = {"Content-Type":"text/plain; charset=utf-8","Content-Disposition":f'attachment; filename="{u["email"]}.txt"',
        "Profile-Update-Interval":"12","Profile-Title":"XBZ_MUSEOD",
        "Subscription-Userinfo":f"upload={u['up']};download={u['down']};total={u['total']};expire={u.get('expiry_ts',0)}"}
    return Response(link, headers=headers)

@app.route("/sub/<token>/info")
def sub_info(token):
    db = get_db(); user = db.execute("SELECT * FROM users WHERE uuid=?", (token,)).fetchone(); db.close()
    if not user: return jsonify({"error":"not found"}), 404
    u = enrich(user)
    return jsonify({"email":u["email"],"uuid":u["uuid"],"enable":bool(u["enable"]),"up":u["up"],"down":u["down"],
        "total":u["total"],"protocol":u["protocol"],"expiry_str":u["expiry_str"],"usage_pct":u["usage_pct"]})

init_db()
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)
