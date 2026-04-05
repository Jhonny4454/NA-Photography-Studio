from flask import Flask, render_template, request, redirect, session, g, jsonify
import mysql.connector
import hashlib
import uuid
import os

app = Flask(__name__)
app.secret_key = "secret_key_123"

# ---------------- DATABASE CONFIG ----------------
DB_NAME = os.getenv("DB_NAME", "sumedh")
DB_USER = os.getenv("DB_USER", "root")
DB_PASS = os.getenv("DB_PASS", "sumedh2004")
DB_HOST = os.getenv("DB_HOST", "localhost")

# ---------------- DATABASE CONNECTION ----------------
def get_db():
    if "db" not in g:
        try:
            g.db = mysql.connector.connect(
                host=DB_HOST,
                user=DB_USER,
                password=DB_PASS,
                database=DB_NAME
            )
        except Exception as e:
            print("DB Error:", e)
            return None
    return g.db

@app.teardown_appcontext
def close_db(exception):
    db = g.pop("db", None)
    if db:
        db.close()

# ---------------- HASH PASSWORD ----------------
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# ---------------- SIGNUP ----------------
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        db = get_db()
        if not db:
            return "Database error"

        cursor = db.cursor()
        try:
            cursor.execute("""
                INSERT INTO users (first_name,last_name,email,mobile,gender,username,password)
                VALUES (%s,%s,%s,%s,%s,%s,%s)
            """, (
                request.form["first_name"],
                request.form["last_name"],
                request.form["email"],
                request.form["mobile"],
                request.form["gender"],
                request.form["username"],
                hash_password(request.form["password"])
            ))
            db.commit()
        except Exception as e:
            print("Signup Error:", e)
            return "Signup failed"

        cursor.close()
        return redirect("/")

    return render_template("signup.html")

# ---------------- LOGIN ----------------
@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        db = get_db()
        if not db:
            return "Database error"

        cursor = db.cursor(dictionary=True)

        cursor.execute(
            "SELECT * FROM users WHERE username=%s AND password=%s",
            (request.form["username"], hash_password(request.form["password"]))
        )

        user = cursor.fetchone()
        cursor.close()

        if user:
            session["user_id"] = user["id"]
            return redirect("/home")

        return render_template("login.html", error="Invalid login")

    return render_template("login.html")

# ---------------- HOME ----------------
@app.route("/home")
def home():
    if "user_id" not in session:
        return redirect("/")

    db = get_db()
    cursor = db.cursor(dictionary=True)

    cursor.execute("SELECT * FROM packages")
    packages = cursor.fetchall()

    cursor.execute("""
        SELECT 
            p.package_name,
            CONCAT(u.first_name, ' ', u.last_name) AS user_full_name,
            r.rating,
            r.comment,
            r.created_at
        FROM package_reviews r
        JOIN users u ON r.user_id = u.id
        JOIN packages p ON r.package_id = p.package_id
        ORDER BY r.created_at DESC
    """)
    package_reviews = cursor.fetchall()

    cursor.close()
    return render_template("home.html", packages=packages, package_reviews=package_reviews)

# ---------------- CART ----------------
@app.route("/cart")
def cart():
    if "user_id" not in session:
        return redirect("/")

    db = get_db()
    cursor = db.cursor(dictionary=True)

    cursor.execute("""
        SELECT up.id AS cart_id,
               p.package_name,
               p.package_price,
               p.duration,
               up.quantity,
               up.location,
               up.scheduled_date
        FROM user_packages up
        JOIN packages p ON up.package_id = p.package_id
        WHERE up.user_id=%s
    """, (session["user_id"],))

    cart_items = cursor.fetchall()
    total = sum(item["package_price"] * item["quantity"] for item in cart_items)

    cursor.close()
    return render_template("cart.html", cart_items=cart_items, total=total)

# ---------------- ADD TO CART ----------------
@app.route("/add_package/<int:package_id>", methods=["POST"])
def add_package(package_id):
    if "user_id" not in session:
        return jsonify({"status": "error"})

    db = get_db()
    cursor = db.cursor(dictionary=True)

    cursor.execute("SELECT * FROM user_packages WHERE user_id=%s AND package_id=%s",
                   (session["user_id"], package_id))
    existing = cursor.fetchone()

    if existing:
        cursor.execute("""
            UPDATE user_packages 
            SET quantity = quantity + 1 
            WHERE user_id=%s AND package_id=%s
        """, (session["user_id"], package_id))
    else:
        cursor.execute("""
            INSERT INTO user_packages (user_id, package_id, quantity) 
            VALUES (%s,%s,1)
        """, (session["user_id"], package_id))

    db.commit()
    cursor.close()

    return jsonify({"status": "success"})

# ---------------- REMOVE ITEM ----------------
@app.route("/remove/<int:id>", methods=["POST"])
def remove(id):
    if "user_id" not in session:
        return redirect("/")

    db = get_db()
    cursor = db.cursor(dictionary=True)

    cursor.execute("SELECT quantity FROM user_packages WHERE id=%s AND user_id=%s",
                   (id, session["user_id"]))
    item = cursor.fetchone()

    if item:
        if item["quantity"] > 1:
            cursor.execute("""
                UPDATE user_packages 
                SET quantity = quantity - 1 
                WHERE id=%s AND user_id=%s
            """, (id, session["user_id"]))
        else:
            cursor.execute("""
                DELETE FROM user_packages 
                WHERE id=%s AND user_id=%s
            """, (id, session["user_id"]))

    db.commit()
    cursor.close()

    return redirect("/cart")

# ---------------- EMPTY CART ----------------
@app.route("/empty_cart", methods=["POST"])
def empty_cart():
    if "user_id" not in session:
        return redirect("/")

    db = get_db()
    cursor = db.cursor()

    cursor.execute("DELETE FROM user_packages WHERE user_id=%s", (session["user_id"],))
    db.commit()

    cursor.close()
    return redirect("/cart")

# ---------------- UPDATE LOCATION ----------------
@app.route("/update_location/<int:cart_id>", methods=["POST"])
def update_location(cart_id):
    if "user_id" not in session:
        return redirect("/")

    db = get_db()
    cursor = db.cursor()

    cursor.execute("""
        UPDATE user_packages
        SET location=%s, scheduled_date=%s
        WHERE id=%s AND user_id=%s
    """, (
        request.form.get("location"),
        request.form.get("scheduled_date"),
        cart_id,
        session["user_id"]
    ))

    db.commit()
    cursor.close()
    return redirect("/cart")

# ---------------- CHECKOUT ----------------
@app.route("/checkout", methods=["GET", "POST"])
def checkout():
    if "user_id" not in session:
        return redirect("/")

    db = get_db()
    cursor = db.cursor(dictionary=True)

    cursor.execute("""
        SELECT up.id AS cart_id,
               p.package_name,
               p.package_price,
               p.duration,
               up.quantity,
               up.location,
               up.scheduled_date
        FROM user_packages up
        JOIN packages p ON up.package_id = p.package_id
        WHERE up.user_id=%s
    """, (session["user_id"],))

    items = cursor.fetchall()

    if not items:
        return redirect("/cart")

    total = sum(item["package_price"] * item["quantity"] for item in items)

    if request.method == "POST":
        order_id = str(uuid.uuid4())

        cursor.execute("""
            INSERT INTO orders (order_id, user_id, total_price, status, scheduled_date)
            VALUES (%s,%s,%s,'Confirmed',%s)
        """, (order_id, session["user_id"], total, items[0]["scheduled_date"]))

        for item in items:
            cursor.execute("""
                INSERT INTO order_items 
                (order_id, package_name, price, duration, location, quantity)
                VALUES (%s,%s,%s,%s,%s,%s)
            """, (
                order_id,
                item["package_name"],
                item["package_price"],
                item["duration"],
                item["location"],
                item["quantity"]
            ))

        cursor.execute("DELETE FROM user_packages WHERE user_id=%s", (session["user_id"],))

        db.commit()
        cursor.close()

        return render_template("order_success.html", total=total, order_id=order_id)

    cursor.close()
    return render_template("checkout.html", items=items, total=total)

# ---------------- ORDERS ----------------
@app.route("/orders")
def orders():
    if "user_id" not in session:
        return redirect("/")

    db = get_db()
    cursor = db.cursor(dictionary=True)

    cursor.execute("""
        SELECT 
            o.order_id,
            o.total_price,
            o.status,
            o.created_at,
            o.scheduled_date,
            GROUP_CONCAT(CONCAT(oi.package_name, ' (x', oi.quantity, ')')) AS packages
        FROM orders o
        JOIN order_items oi ON o.order_id = oi.order_id
        WHERE o.user_id=%s
        GROUP BY o.order_id, o.total_price, o.status, o.created_at, o.scheduled_date
        ORDER BY o.created_at DESC
    """, (session["user_id"],))

    orders = cursor.fetchall()
    cursor.close()

    return render_template("orders.html", orders=orders)

# ---------------- STATIC PAGES ----------------
@app.route("/terms")
def terms():
    return render_template("terms.html")

@app.route("/privacy")
def privacy():
    return render_template("privacy.html")

@app.route("/about")
def about():
    return render_template("about-us.html")

# ---------------- LOGOUT ----------------
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

# ---------------- EDIT PROFILE ----------------
@app.route("/edit-profile", methods=["GET", "POST"])
def edit_profile():
    if "user_id" not in session:
        return redirect("/")

    db = get_db()
    cursor = db.cursor(dictionary=True)

    if request.method == "POST":
        cursor.execute("""
            UPDATE users
            SET first_name=%s,
                last_name=%s,
                email=%s,
                mobile=%s,
                gender=%s
            WHERE id=%s
        """, (
            request.form["first_name"],
            request.form["last_name"],
            request.form["email"],
            request.form["mobile"],
            request.form["gender"],
            session["user_id"]
        ))

        db.commit()
        cursor.close()
        return redirect("/home")

    cursor.execute("SELECT * FROM users WHERE id=%s", (session["user_id"],))
    user = cursor.fetchone()

    cursor.close()
    return render_template("edit_profile.html", user=user)

# ---------------- RUN ----------------
if __name__ == "__main__":
    app.run(debug=True)