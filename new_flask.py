from flask import Flask, render_template, request, redirect, session, g, jsonify, flash
import mysql.connector
import hashlib
import uuid
import os
from datetime import datetime

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

#--------------- Admin Login-----------
@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        if request.form["username"] == "admin" and request.form["password"] == "admin123":
            session["admin_id"] = 1
            return redirect("/admin/dashboard")
        else:
            return render_template("admin_login.html", error="Invalid credentials")
    return render_template("admin_login.html")

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
                INSERT INTO users (first_name, last_name, email, mobile, gender, username, password, role)
                VALUES (%s, %s, %s, %s, %s, %s, %s, 'user')
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
            session["username"] = user["username"]
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

    cursor.execute("""
        SELECT 
            o.order_id,
            o.total_price,
            o.status,
            o.created_at
        FROM orders o
        WHERE o.user_id = %s
        ORDER BY o.created_at DESC
    """, (session["user_id"],))

    orders = cursor.fetchall()

    cursor.close()

    return render_template(
        "home.html",
        packages=packages,
        package_reviews=package_reviews,
        orders=orders
    )

# ---------------- CART ----------------
@app.route("/cart", methods=["GET", "POST"])
def cart():
    if "user_id" not in session:
        return redirect("/")
    user_id = session.get("user_id")
    db = get_db()
    cursor = db.cursor(dictionary=True)

    if request.method == "POST":
        for key, value in request.form.items():
            if key.startswith("photographer_"):
                try:
                    cart_item_id = int(key.split("_")[1])
                    photographer_id = int(value) if value else None
                    location = request.form.get(f"location_{cart_item_id}", "")
                    scheduled_date = request.form.get(f"date_{cart_item_id}", None)
                    cursor.execute("""
                        UPDATE user_packages
                        SET photographer_id=%s, location=%s, scheduled_date=%s
                        WHERE id=%s AND user_id=%s
                    """, (photographer_id, location, scheduled_date, cart_item_id, user_id))
                except ValueError:
                    continue
        db.commit()
        cursor.close()
        flash("✅ Cart updated successfully!", "success")
        return redirect("/cart")

    # Fetch cart items
    cursor.execute("""
        SELECT up.*, p.package_name, p.package_price, p.duration,
               ph.id AS photographer_id,
               CONCAT(ph.first_name, ' ', ph.last_name) AS photographer_name,
               ph.rating AS photographer_rating
        FROM user_packages up
        JOIN packages p ON up.package_id = p.package_id
        LEFT JOIN photographers ph ON up.photographer_id = ph.id
        WHERE up.user_id = %s
    """, (user_id,))
    cart_items = cursor.fetchall()

    # Fetch photographers for dropdown (only active ones)
    cursor.execute("""
        SELECT id, CONCAT(first_name, ' ', last_name) AS name, rating
        FROM photographers
        WHERE status = 'active' OR status IS NULL
        ORDER BY rating DESC
    """)
    photographers = cursor.fetchall()

    total = sum(item["package_price"] * item["quantity"] for item in cart_items)
    cursor.close()
    return render_template("cart.html", cart_items=cart_items, total=total, photographers=photographers)

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
            cursor.execute("DELETE FROM user_packages WHERE id=%s AND user_id=%s",
                           (id, session["user_id"]))
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

# ---------------- UPDATE INDIVIDUAL CART ITEM ----------------
@app.route("/update_item/<int:item_id>", methods=["POST"])
def update_item(item_id):
    if "user_id" not in session:
        return redirect("/")
    
    db = get_db()
    cursor = db.cursor()
    
    try:
        photographer_id = request.form.get(f"photographer_{item_id}")
        location = request.form.get(f"location_{item_id}")
        scheduled_date = request.form.get(f"date_{item_id}")
        
        photographer_id = int(photographer_id) if photographer_id and photographer_id != "" else None
        
        cursor.execute("""
            UPDATE user_packages
            SET photographer_id=%s, location=%s, scheduled_date=%s
            WHERE id=%s AND user_id=%s
        """, (photographer_id, location, scheduled_date, item_id, session["user_id"]))
        
        db.commit()
        flash("✅ Package details updated successfully!", "success")
        
    except Exception as e:
        print("Update Error:", e)
        db.rollback()
        flash("❌ Error updating package details", "error")
    
    cursor.close()
    return redirect("/cart")

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
        flash("✅ Profile updated successfully!", "success")
        return redirect("/home")
    cursor.execute("SELECT * FROM users WHERE id=%s", (session["user_id"],))
    user = cursor.fetchone()
    cursor.close()
    return render_template("edit_profile.html", user=user)

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

@app.route("/get-hired")
def get_hired():
    return render_template("get_hired.html")

#------------------ Orders Route--------
@app.route("/orders")
def orders():
    if "user_id" not in session:
        return redirect("/")

    db = get_db()
    cursor = db.cursor(dictionary=True)

    cursor.execute("""
        SELECT order_id, total_price, status, created_at, location, scheduled_date
        FROM orders
        WHERE user_id = %s
        ORDER BY created_at DESC
    """, (session["user_id"],))

    orders = cursor.fetchall()
    cursor.close()

    return render_template("orders.html", orders=orders)

#------------------ Order Details (Using order_items table)--------
@app.route("/order_details/<string:order_id>")
def order_details(order_id):
    if "user_id" not in session:
        return redirect("/")

    db = get_db()
    cursor = db.cursor(dictionary=True)

    cursor.execute("""
        SELECT 
            order_id,
            total_price,
            location,
            scheduled_date,
            payment_method,
            status,
            created_at
        FROM orders
        WHERE order_id = %s AND user_id = %s
    """, (order_id, session["user_id"]))

    order = cursor.fetchone()

    if not order:
        cursor.close()
        return render_template("order_details.html", order=None, items=[], grand_total=0)

    cursor.execute("""
        SELECT 
            oi.package_name,
            oi.price,
            oi.duration,
            oi.quantity,
            oi.location,
            CONCAT(ph.first_name, ' ', ph.last_name) AS photographer_name,
            ph.rating AS photographer_rating
        FROM order_items oi
        LEFT JOIN photographers ph ON oi.photographer_id = ph.id
        WHERE oi.order_id = %s
    """, (order_id,))
    
    items = cursor.fetchall()
    grand_total = sum(item["price"] * item["quantity"] for item in items)
    
    cursor.close()

    return render_template("order_details.html", order=order, items=items, grand_total=grand_total)

# ---------------- PHOTOGRAPHER APPLY ----------------
@app.route("/photographer/apply", methods=["POST"])
def apply_photographer():
    db = get_db()
    cursor = db.cursor()
    cursor.execute("""
        INSERT INTO photographers_applications 
        (first_name, last_name, email, phone, address, years_exp, months_exp)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
    """, (
        request.form["first_name"],
        request.form["last_name"],
        request.form["email"],
        request.form["phone"],
        request.form["address"],
        request.form["years"],
        request.form["months"]
    ))
    db.commit()
    cursor.close()
    flash("🎉 Your application has been submitted successfully!", "success")
    return redirect("/photographer/submitted")

# ---------------- PHOTOGRAPHER SUBMITTED PAGE ----------------
@app.route("/photographer/submitted")
def photographer_submitted():
    return render_template("photographer_submitted.html")

# ---------------- ADMIN DASHBOARD ----------------
@app.route("/admin/dashboard")
def admin_dashboard():
    if "admin_id" not in session:
        return redirect("/admin/login")
    
    db = get_db()
    cursor = db.cursor(dictionary=True)
    
    cursor.execute("SELECT COUNT(*) as count FROM orders")
    total_orders = cursor.fetchone()["count"]
    
    cursor.execute("SELECT SUM(total_price) as total FROM orders WHERE status = 'Confirmed'")
    revenue_result = cursor.fetchone()
    revenue = revenue_result["total"] if revenue_result["total"] else 0
    
    cursor.execute("SELECT COUNT(*) as count FROM users")
    total_users = cursor.fetchone()["count"]
    
    cursor.execute("SELECT COUNT(*) as count FROM photographers")
    total_photographers = cursor.fetchone()["count"]
    
    cursor.execute("""
        SELECT o.order_id, o.total_price, o.status, o.created_at,
               u.first_name, u.last_name
        FROM orders o
        JOIN users u ON o.user_id = u.id
        ORDER BY o.created_at DESC
        LIMIT 10
    """)
    recent_orders = cursor.fetchall()
    
    cursor.execute("""
        SELECT id, first_name, last_name, email, phone, years_exp, months_exp
        FROM photographers_applications
        ORDER BY id DESC
    """)
    applications = cursor.fetchall()
    
    cursor.close()
    
    return render_template("admin_dashboard.html", 
                         total_orders=total_orders,
                         revenue=revenue,
                         total_users=total_users,
                         total_photographers=total_photographers,
                         recent_orders=recent_orders,
                         applications=applications)

# ---------------- ADMIN ORDER DETAILS ----------------
@app.route("/admin/order_details/<string:order_id>")
def admin_order_details(order_id):
    if "admin_id" not in session:
        return redirect("/admin/login")
    
    db = get_db()
    cursor = db.cursor(dictionary=True)
    
    cursor.execute("""
        SELECT o.order_id, o.total_price, o.location, o.scheduled_date, 
               o.payment_method, o.status, o.created_at,
               u.first_name, u.last_name, u.email, u.mobile
        FROM orders o
        JOIN users u ON o.user_id = u.id
        WHERE o.order_id = %s
    """, (order_id,))
    
    order = cursor.fetchone()
    
    items = []
    if order:
        cursor.execute("""
            SELECT oi.package_name, oi.price, oi.duration, oi.quantity,
                   CONCAT(ph.first_name, ' ', ph.last_name) AS photographer_name,
                   ph.rating AS photographer_rating
            FROM order_items oi
            LEFT JOIN photographers ph ON oi.photographer_id = ph.id
            WHERE oi.order_id = %s
        """, (order_id,))
        items = cursor.fetchall()
    
    cursor.close()
    
    return render_template("admin_order_details.html", order=order, items=items)

# ---------------- ADMIN PHOTOGRAPHERS ----------------
@app.route("/admin/photographers")
def admin_photographers():
    if "admin_id" not in session:
        return redirect("/admin/login")
    db = get_db()
    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT * FROM photographers ORDER BY id DESC")
    photographers = cursor.fetchall()
    cursor.close()
    return render_template("admin_photographers.html", photographers=photographers)

# ---------------- ADMIN APPROVE PHOTOGRAPHER ----------------
@app.route("/admin/approve/<int:id>", methods=["POST"])
def approve_photographer(id):
    if "admin_id" not in session:
        return redirect("/admin/login")
    db = get_db()
    cursor = db.cursor()
    cursor.execute("""
        INSERT INTO photographers (first_name, last_name, email, phone, address, status, rating)
        SELECT first_name, last_name, email, phone, address, 'active', 0
        FROM photographers_applications WHERE id=%s
    """, (id,))
    cursor.execute("DELETE FROM photographers_applications WHERE id=%s", (id,))
    db.commit()
    cursor.close()
    flash("✅ Photographer approved successfully!", "success")
    return redirect("/admin/dashboard")

# ---------------- ADMIN REJECT PHOTOGRAPHER ----------------
@app.route("/admin/reject/<int:id>", methods=["POST"])
def reject_photographer(id):
    if "admin_id" not in session:
        return redirect("/admin/login")
    db = get_db()
    cursor = db.cursor()
    cursor.execute("DELETE FROM photographers_applications WHERE id=%s", (id,))
    db.commit()
    cursor.close()
    flash("❌ Application rejected!", "error")
    return redirect("/admin/dashboard")

# ---------------- ADMIN ORDERS ----------------
@app.route("/admin/orders")
def admin_orders():
    if "admin_id" not in session:
        return redirect("/admin/login")
    db = get_db()
    cursor = db.cursor(dictionary=True)
    cursor.execute("""
        SELECT o.order_id, o.total_price, o.status, o.created_at,
               u.first_name, u.last_name
        FROM orders o
        JOIN users u ON o.user_id = u.id
        ORDER BY o.created_at DESC
    """)
    orders = cursor.fetchall()
    cursor.close()
    return render_template("admin_orders.html", orders=orders)

# ---------------- ADMIN UPDATE ORDER STATUS ----------------
@app.route("/admin/update_order_status/<string:order_id>", methods=["POST"])
def update_order_status(order_id):
    if "admin_id" not in session:
        return redirect("/admin/login")
    
    new_status = request.form.get("status")
    db = get_db()
    cursor = db.cursor()
    cursor.execute("UPDATE orders SET status = %s WHERE order_id = %s", (new_status, order_id))
    db.commit()
    cursor.close()
    flash(f"✅ Order status updated to {new_status}!", "success")
    return redirect(f"/admin/order_details/{order_id}")

# ---------------- ADMIN PACKAGES ----------------
@app.route("/admin/packages", methods=["GET", "POST"])
def admin_packages():
    if "admin_id" not in session:
        return redirect("/admin/login")
    db = get_db()
    cursor = db.cursor(dictionary=True)
    if request.method == "POST":
        try:
            package_name = request.form.get("package_name")
            package_price = request.form.get("package_price")
            duration = request.form.get("duration")
            image_filename = request.form.get("image_filename")
            cursor.execute("""
                INSERT INTO packages (package_name, package_price, duration, image_filename)
                VALUES (%s, %s, %s, %s)
            """, (package_name, package_price, duration, image_filename))
            db.commit()
            flash("✅ Package added successfully!", "success")
        except Exception as e:
            print("Add Package Error:", e)
            flash("❌ Error adding package", "error")
        return redirect("/admin/packages")
    cursor.execute("SELECT * FROM packages ORDER BY package_id DESC")
    packages = cursor.fetchall()
    cursor.close()
    return render_template("admin_packages.html", packages=packages)

# ---------------- DELETE PACKAGE ----------------
@app.route("/admin/delete_package/<int:id>", methods=["POST"])
def delete_package(id):
    if "admin_id" not in session:
        return redirect("/admin/login")
    db = get_db()
    cursor = db.cursor()
    try:
        cursor.execute("DELETE FROM user_packages WHERE package_id=%s", (id,))
        cursor.execute("DELETE FROM packages WHERE package_id=%s", (id,))
        db.commit()
        flash("🗑️ Package deleted successfully!", "success")
    except Exception as e:
        print("Delete Error:", e)
        flash("❌ Cannot delete package", "error")
    cursor.close()
    return redirect("/admin/packages")

# ---------------- EDIT PACKAGE ----------------
@app.route("/admin/edit_package/<int:id>", methods=["GET", "POST"])
def edit_package(id):
    if "admin_id" not in session:
        return redirect("/admin/login")
    db = get_db()
    cursor = db.cursor(dictionary=True)
    if request.method == "POST":
        try:
            package_name = request.form.get("package_name")
            package_price = request.form.get("package_price")
            duration = request.form.get("duration")
            image_filename = request.form.get("image_filename")
            cursor.execute("""
                UPDATE packages
                SET package_name=%s, package_price=%s, duration=%s, image_filename=%s
                WHERE package_id=%s
            """, (package_name, package_price, duration, image_filename, id))
            db.commit()
            flash("✏️ Package updated successfully!", "success")
            return redirect("/admin/packages")
        except Exception as e:
            print("Update Error:", e)
            flash("❌ Error updating package", "error")
    cursor.execute("SELECT * FROM packages WHERE package_id=%s", (id,))
    package = cursor.fetchone()
    cursor.close()
    return render_template("edit_package.html", package=package)

# ---------------- ADMIN USERS ----------------
@app.route("/admin/users")
def admin_users():
    if "admin_id" not in session:
        return redirect("/admin/login")
    db = get_db()
    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT id, first_name, last_name, email, mobile, username, role, created_at FROM users ORDER BY id DESC")
    users = cursor.fetchall()
    cursor.close()
    return render_template("admin_users.html", users=users)

# ---------------- DELETE USER ----------------
@app.route("/admin/delete_user/<int:id>", methods=["POST"])
def delete_user(id):
    if "admin_id" not in session:
        return redirect("/admin/login")
    db = get_db()
    cursor = db.cursor()
    try:
        cursor.execute("DELETE FROM user_packages WHERE user_id=%s", (id,))
        cursor.execute("DELETE FROM orders WHERE user_id=%s", (id,))
        cursor.execute("DELETE FROM users WHERE id=%s", (id,))
        db.commit()
        flash("✅ User deleted successfully!", "success")
    except Exception as e:
        db.rollback()
        print("Delete Error:", e)
        flash("❌ Error deleting user!", "error")
    cursor.close()
    return redirect("/admin/users")

# ---------------- Order Success ----------------
@app.route("/order-success")
def order_success():
    order_id = request.args.get("order_id")
    total = request.args.get("total")
    return render_template("order_success.html", order_id=order_id, total=total)

#----------------- Check Out Route (Creates order_items)---------------
@app.route("/checkout", methods=["GET", "POST"])
def checkout():
    if "user_id" not in session:
        return redirect("/")

    db = get_db()
    cursor = db.cursor(dictionary=True)

    if request.method == "GET":
        cursor.execute("""
            SELECT 
                up.id AS cart_id,
                up.quantity,
                up.location,
                up.scheduled_date,
                p.package_name,
                p.package_price,
                p.duration,
                CONCAT(ph.first_name, ' ', ph.last_name) AS photographer_name,
                up.photographer_id
            FROM user_packages up
            JOIN packages p ON up.package_id = p.package_id
            LEFT JOIN photographers ph ON up.photographer_id = ph.id
            WHERE up.user_id = %s
        """, (session["user_id"],))

        items = cursor.fetchall()
        total = sum(item["package_price"] * item["quantity"] for item in items)

        cursor.close()
        return render_template("checkout.html", items=items, total=total)

    if request.method == "POST":
        payment_method = request.form.get("payment")

        cursor.execute("""
            SELECT up.*, p.package_name, p.package_price, p.duration
            FROM user_packages up
            JOIN packages p ON up.package_id = p.package_id
            WHERE up.user_id = %s
        """, (session["user_id"],))

        cart_items = cursor.fetchall()

        if not cart_items:
            cursor.close()
            flash("Your cart is empty!", "error")
            return redirect("/cart")

        total = sum(item["package_price"] * item["quantity"] for item in cart_items)
        location = cart_items[0]["location"] if cart_items else None
        scheduled_date = cart_items[0]["scheduled_date"] if cart_items else None

        order_code = str(uuid.uuid4())[:8]

        cursor.execute("""
            INSERT INTO orders 
            (user_id, total_price, location, payment_method, status, order_id, scheduled_date)
            VALUES (%s,%s,%s,%s,%s,%s,%s)
        """, (
            session["user_id"],
            total,
            location,
            payment_method,
            "Confirmed",
            order_code,
            scheduled_date
        ))

        db.commit()

        for item in cart_items:
            cursor.execute("""
                INSERT INTO order_items 
                (order_id, package_name, price, duration, location, quantity, photographer_id)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (
                order_code,
                item["package_name"],
                item["package_price"],
                item["duration"],
                item["location"],
                item["quantity"],
                item["photographer_id"]
            ))

        db.commit()
        cursor.execute("DELETE FROM user_packages WHERE user_id=%s", (session["user_id"],))
        db.commit()
        cursor.close()

        return redirect(f"/order-success?order_id={order_code}&total={total}")
    
# ---------------- ADMIN EDIT PHOTOGRAPHER ----------------
@app.route("/admin/edit_photographer/<int:id>", methods=["GET", "POST"])
def edit_photographer(id):
    if "admin_id" not in session:
        return redirect("/admin/login")
    
    db = get_db()
    cursor = db.cursor(dictionary=True)
    
    if request.method == "POST":
        try:
            first_name = request.form.get("first_name")
            last_name = request.form.get("last_name")
            email = request.form.get("email")
            phone = request.form.get("phone")
            experience = request.form.get("experience")
            rating = request.form.get("rating")
            status = request.form.get("status")
            
            cursor.execute("""
                UPDATE photographers 
                SET first_name=%s, last_name=%s, email=%s, phone=%s, 
                    experience=%s, rating=%s, status=%s
                WHERE id=%s
            """, (first_name, last_name, email, phone, experience, rating, status, id))
            db.commit()
            flash("✅ Photographer updated successfully!", "success")
            return redirect("/admin/photographers")
        except Exception as e:
            print("Update Error:", e)
            db.rollback()
            flash("❌ Error updating photographer", "error")
            return redirect(f"/admin/edit_photographer/{id}")
    
    # GET request - fetch photographer details
    cursor.execute("SELECT * FROM photographers WHERE id=%s", (id,))
    photographer = cursor.fetchone()
    cursor.close()
    
    if not photographer:
        flash("❌ Photographer not found!", "error")
        return redirect("/admin/photographers")
    
    return render_template("admin_edit_photographer.html", photographer=photographer)

# ---------------- ADMIN DELETE PHOTOGRAPHER ----------------
@app.route("/admin/delete_photographer/<int:id>", methods=["POST"])
def delete_photographer(id):
    if "admin_id" not in session:
        return redirect("/admin/login")
    
    db = get_db()
    cursor = db.cursor()
    
    try:
        # Check if photographer exists
        cursor.execute("SELECT first_name, last_name FROM photographers WHERE id=%s", (id,))
        photographer = cursor.fetchone()
        
        if photographer:
            # Delete photographer
            cursor.execute("DELETE FROM photographers WHERE id=%s", (id,))
            db.commit()
            flash(f"✅ Photographer {photographer[0]} {photographer[1]} deleted successfully!", "success")
        else:
            flash("❌ Photographer not found!", "error")
    except Exception as e:
        print("Delete Error:", e)
        db.rollback()
        flash("❌ Error deleting photographer", "error")
    
    cursor.close()
    return redirect("/admin/photographers")

@app.route('/admin/view_user/<int:user_id>')
def view_user(user_id):
    if 'admin_id' not in session:
        return redirect('/admin/login')

    db = get_db()
    cursor = db.cursor(dictionary=True)

    # Get user details
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    user = cursor.fetchone()

    if not user:
        flash("User not found", "error")
        return redirect('/admin/users')

    # Get user's orders
    cursor.execute("""
        SELECT order_id, total_price, status, created_at 
        FROM orders 
        WHERE user_id = %s 
        ORDER BY created_at DESC
    """, (user_id,))
    orders = cursor.fetchall()
    user['orders'] = orders

    cursor.close()
    db.close()

    return render_template('admin_view_user.html', user=user)

# ---------------- LOGOUT ----------------
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

# ---------------- RUN APP ----------------
if __name__ == "__main__":
    app.run(debug=True)