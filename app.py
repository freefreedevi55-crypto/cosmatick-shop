import os, sqlite3, secrets, hashlib, hmac
from functools import wraps
from datetime import datetime
from io import BytesIO
from flask import Flask, g, render_template, request, redirect, url_for, session, flash, abort, send_file
from werkzeug.security import generate_password_hash, check_password_hash

APP_SECRET = os.environ.get("COSMATICK_SECRET_KEY")
if not APP_SECRET:
    # Set COSMATICK_SECRET_KEY in production; this fallback is for local demo only.
    APP_SECRET = secrets.token_hex(32)

app = Flask(__name__)
app.secret_key = APP_SECRET
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                  SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1")
DB_PATH = os.environ.get("COSMATICK_DB", os.path.join(os.path.dirname(__file__), "cosmatick.db"))

def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db

@app.teardown_appcontext
def close_db(error=None):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()

def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'owner',
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS settings (
      key TEXT PRIMARY KEY, value TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS customers (
      id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
      phone TEXT NOT NULL, stamps INTEGER NOT NULL DEFAULT 0,
      rewards INTEGER NOT NULL DEFAULT 0, notes TEXT DEFAULT '',
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS activity (
      id INTEGER PRIMARY KEY AUTOINCREMENT, customer_id INTEGER,
      message TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(customer_id) REFERENCES customers(id) ON DELETE SET NULL
    );
    CREATE TABLE IF NOT EXISTS products (
      id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
      description TEXT DEFAULT '', price REAL NOT NULL DEFAULT 0,
      active INTEGER NOT NULL DEFAULT 1
    );
    CREATE TABLE IF NOT EXISTS campaigns (
      id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
      prize TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    """)
    defaults = {
      "shop_name": "COSMATICK SHOP", "owner_name": "Shop Owner",
      "phone": "", "city": "", "description": "Your favourite shop for everyday essentials.",
      "instagram": "", "google_review_url": "", "stamp_target": "5",
      "stamp_reward": "10% off your next purchase", "plan": "Free"
    }
    for k, v in defaults.items():
        conn.execute("INSERT OR IGNORE INTO settings(key,value) VALUES(?,?)", (k,v))
    # Admin credentials are configured via environment variables. Seed once on first run.
    username = os.environ.get("COSMATICK_ADMIN_USER", "admin")
    password = os.environ.get("COSMATICK_ADMIN_PASSWORD", "ChangeMe123!")
    exists = conn.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
    if not exists:
        conn.execute("INSERT INTO users(username,password_hash,role) VALUES(?,?,?)",
                     (username, generate_password_hash(password), "admin"))
    if conn.execute("SELECT COUNT(*) FROM products").fetchone()[0] == 0:
        conn.executemany("INSERT INTO products(name,description,price) VALUES(?,?,?)", [
          ("Daily Care", "Everyday essentials", 199),
          ("Beauty Essentials", "Popular picks", 299),
          ("Special Offers", "Seasonal deals", 99)
        ])
    if conn.execute("SELECT COUNT(*) FROM campaigns").fetchone()[0] == 0:
        conn.execute("INSERT INTO campaigns(name,prize,active) VALUES(?,?,1)",
                     ("COSMATICK Surprise Gift", "10% OFF"))
    conn.commit()
    conn.close()

def get_setting(key, default=""):
    row = db().execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    return row["value"] if row else default

def set_setting(key, value):
    db().execute("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                 (key, str(value)))

@app.context_processor
def inject_globals():
    return {"shop_name": get_setting("shop_name", "COSMATICK SHOP"),
            "current_user": session.get("username"), "current_role": session.get("role")}

def login_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login", next=request.path))
        return fn(*args, **kwargs)
    return wrapped

def admin_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login", next=request.path))
        if session.get("role") != "admin":
            abort(403)
        return fn(*args, **kwargs)
    return wrapped

@app.route("/")
def index():
    if session.get("user_id"):
        return redirect(url_for("dashboard"))
    return render_template("landing.html")

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username","").strip()
        password = request.form.get("password","")
        user = db().execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            flash("Welcome back!", "success")
            target = request.args.get("next") or url_for("dashboard")
            if not target.startswith("/") or target.startswith("//"):
                target = url_for("dashboard")
            return redirect(target)
        flash("Username or password is incorrect.", "error")
    return render_template("login.html")

@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))

@app.route("/dashboard")
@login_required
def dashboard():
    conn = db()
    total = conn.execute("SELECT COUNT(*) FROM customers").fetchone()[0]
    stamps = conn.execute("SELECT COALESCE(SUM(stamps),0) FROM customers").fetchone()[0]
    rewards = conn.execute("SELECT COALESCE(SUM(rewards),0) FROM customers").fetchone()[0]
    activity = conn.execute("""SELECT a.*, c.name customer_name FROM activity a
      LEFT JOIN customers c ON c.id=a.customer_id ORDER BY a.id DESC LIMIT 7""").fetchall()
    return render_template("dashboard.html", total=total, stamps=stamps, rewards=rewards, activity=activity)

@app.route("/customers", methods=["GET","POST"])
@login_required
def customers():
    conn = db()
    if request.method == "POST":
        name = request.form.get("name","").strip()
        phone = request.form.get("phone","").strip()
        notes = request.form.get("notes","").strip()
        if not name or not phone:
            flash("Customer name and phone are required.", "error")
        elif len(name) > 100 or len(phone) > 30:
            flash("Please check the length of the name or phone number.", "error")
        else:
            cur = conn.execute("INSERT INTO customers(name,phone,notes) VALUES(?,?,?)", (name,phone,notes))
            conn.execute("INSERT INTO activity(customer_id,message) VALUES(?,?)", (cur.lastrowid, "Customer added"))
            conn.commit()
            flash("Customer added.", "success")
            return redirect(url_for("customers"))
    q = request.args.get("q","").strip()
    if q:
        rows = conn.execute("SELECT * FROM customers WHERE name LIKE ? OR phone LIKE ? ORDER BY id DESC",
                            (f"%{q}%", f"%{q}%")).fetchall()
    else:
        rows = conn.execute("SELECT * FROM customers ORDER BY id DESC").fetchall()
    return render_template("customers.html", customers=rows, q=q, target=int(get_setting("stamp_target","5")))

@app.route("/customers/<int:customer_id>/stamp", methods=["POST"])
@login_required
def add_stamp(customer_id):
    conn = db()
    customer = conn.execute("SELECT * FROM customers WHERE id=?", (customer_id,)).fetchone()
    if not customer:
        abort(404)
    target = max(1, min(100, int(get_setting("stamp_target","5") or 5)))
    stamps = customer["stamps"] + 1
    rewards = customer["rewards"]
    if stamps >= target:
        stamps = 0
        rewards += 1
        message = "Reward unlocked: " + get_setting("stamp_reward","Reward")
        flash(f"Reward unlocked for {customer['name']}!", "success")
    else:
        message = "Earned 1 stamp"
        flash(f"Stamp added for {customer['name']}.", "success")
    conn.execute("UPDATE customers SET stamps=?, rewards=? WHERE id=?", (stamps,rewards,customer_id))
    conn.execute("INSERT INTO activity(customer_id,message) VALUES(?,?)", (customer_id,message))
    conn.commit()
    return redirect(request.referrer or url_for("customers"))

@app.route("/customers/<int:customer_id>/delete", methods=["POST"])
@admin_required
def delete_customer(customer_id):
    conn = db()
    conn.execute("DELETE FROM customers WHERE id=?", (customer_id,))
    conn.execute("INSERT INTO activity(message) VALUES(?)", ("Customer record deleted",))
    conn.commit()
    flash("Customer deleted.", "success")
    return redirect(url_for("customers"))

@app.route("/stamp-card")
def public_stamp_card():
    return render_template("public_stamp.html")

@app.route("/scratch", methods=["GET","POST"])
@login_required
def scratch():
    conn = db()
    if request.method == "POST":
        name = request.form.get("name","").strip()
        prize = request.form.get("prize","").strip()
        active = 1 if request.form.get("active") == "on" else 0
        if name and prize:
            conn.execute("INSERT INTO campaigns(name,prize,active) VALUES(?,?,?)", (name,prize,active))
            conn.commit()
            flash("Scratch campaign created.", "success")
            return redirect(url_for("scratch"))
        flash("Campaign name and prize are required.", "error")
    campaigns = conn.execute("SELECT * FROM campaigns ORDER BY id DESC").fetchall()
    return render_template("scratch.html", campaigns=campaigns)

@app.route("/scratch/reveal/<int:campaign_id>")
def reveal(campaign_id):
    campaign = db().execute("SELECT * FROM campaigns WHERE id=? AND active=1", (campaign_id,)).fetchone()
    if not campaign:
        abort(404)
    return render_template("reveal.html", campaign=campaign)

@app.route("/menu")
def menu():
    products = db().execute("SELECT * FROM products WHERE active=1 ORDER BY id DESC").fetchall()
    return render_template("menu.html", products=products, public=True)

@app.route("/menu/manage", methods=["GET","POST"])
@login_required
def menu_manage():
    conn = db()
    if request.method == "POST":
        name = request.form.get("name","").strip()
        description = request.form.get("description","").strip()
        try:
            price = max(0, float(request.form.get("price","0")))
        except ValueError:
            price = -1
        if not name or price < 0:
            flash("Enter a product name and valid price.", "error")
        else:
            conn.execute("INSERT INTO products(name,description,price) VALUES(?,?,?)", (name,description,price))
            conn.commit()
            flash("Catalog item added.", "success")
            return redirect(url_for("menu_manage"))
    products = conn.execute("SELECT * FROM products ORDER BY id DESC").fetchall()
    return render_template("menu_manage.html", products=products)

@app.route("/menu/<int:product_id>/toggle", methods=["POST"])
@login_required
def toggle_product(product_id):
    conn = db()
    conn.execute("UPDATE products SET active=CASE active WHEN 1 THEN 0 ELSE 1 END WHERE id=?", (product_id,))
    conn.commit()
    return redirect(url_for("menu_manage"))

@app.route("/reviews", methods=["GET","POST"])
@login_required
def reviews():
    if request.method == "POST":
        link = request.form.get("google_review_url","").strip()
        if link and not (link.startswith("https://") or link.startswith("http://")):
            flash("Review link must start with http:// or https://.", "error")
        else:
            set_setting("google_review_url", link)
            db().commit()
            flash("Google review link saved.", "success")
            return redirect(url_for("reviews"))
    return render_template("reviews.html", link=get_setting("google_review_url",""))

@app.route("/qr")
@login_required
def qr():
    return render_template("qr.html", qr_url=url_for("public_stamp_card", _external=True))

@app.route("/qr.png")
@login_required
def qr_png():
    target_url = url_for("public_stamp_card", _external=True)
    try:
        import qrcode
        img = qrcode.make(target_url)
        buf = BytesIO()
        img.save(buf, format="PNG")
        buf.seek(0)
        return send_file(buf, mimetype="image/png", download_name="cosmatick-shop-qr.png")
    except ImportError:
        flash("Install the optional qrcode package to generate QR images.", "error")
        return redirect(url_for("qr"))

@app.route("/settings", methods=["GET","POST"])
@login_required
def settings():
    keys = ["shop_name","owner_name","phone","city","description","instagram","stamp_target","stamp_reward"]
    if request.method == "POST":
        for key in keys:
            val = request.form.get(key,"").strip()
            if key == "stamp_target":
                try: val = str(max(1, min(100, int(val))))
                except ValueError: val = "5"
            set_setting(key, val)
        db().commit()
        flash("Shop settings saved.", "success")
        return redirect(url_for("settings"))
    values = {key:get_setting(key,"") for key in keys}
    return render_template("settings.html", values=values)

@app.route("/admin", methods=["GET","POST"])
@admin_required
def admin():
    conn = db()
    if request.method == "POST":
        action = request.form.get("action")
        if action == "create_user":
            username = request.form.get("username","").strip()
            password = request.form.get("password","")
            role = request.form.get("role","owner")
            if len(username) < 3 or len(password) < 10 or role not in ("admin","owner"):
                flash("Username must be 3+ chars, password 10+ chars, and role must be valid.", "error")
            else:
                try:
                    conn.execute("INSERT INTO users(username,password_hash,role) VALUES(?,?,?)",
                                 (username,generate_password_hash(password),role))
                    conn.commit()
                    flash("Login account created.", "success")
                except sqlite3.IntegrityError:
                    flash("That username already exists.", "error")
        elif action == "change_password":
            new_password = request.form.get("new_password","")
            if len(new_password) < 10:
                flash("Password must be at least 10 characters.", "error")
            else:
                conn.execute("UPDATE users SET password_hash=? WHERE id=?",
                             (generate_password_hash(new_password), session["user_id"]))
                conn.commit()
                flash("Your password has been changed.", "success")
        return redirect(url_for("admin"))
    users = conn.execute("SELECT id,username,role,created_at FROM users ORDER BY id").fetchall()
    totals = {
      "customers": conn.execute("SELECT COUNT(*) FROM customers").fetchone()[0],
      "products": conn.execute("SELECT COUNT(*) FROM products").fetchone()[0],
      "campaigns": conn.execute("SELECT COUNT(*) FROM campaigns").fetchone()[0],
    }
    return render_template("admin.html", users=users, totals=totals)

@app.route("/plans")
@login_required
def plans():
    return render_template("plans.html", plan=get_setting("plan","Free"))

@app.errorhandler(403)
def forbidden(e):
    return render_template("error.html", code=403, message="You do not have permission to access this page."), 403
@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", code=404, message="That page could not be found."), 404

if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT","5000")), debug=False)
