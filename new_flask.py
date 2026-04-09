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

    cursor.execute("""
        SELECT id, CONCAT(first_name, ' ', last_name) AS name, rating
        FROM photographers
        ORDER BY rating DESC
    """)
    photographers = cursor.fetchall()

    total = sum(item["package_price"] * item["quantity"] for item in cart_items)
    cursor.close()
    return render_template("cart.html", cart_items=cart_items, total=total, photographers=photographers)

# ---------------- UPDATE INDIVIDUAL CART ITEM ----------------
@app.route("/update_item/<int:item_id>", methods=["POST"])
def update_item(item_id):
    if "user_id" not in session:
        return redirect("/")
    db = get_db()
    cursor = db.cursor()
    photographer_id = request.form.get(f"photographer_{item_id}")
    location = request.form.get(f"location_{item_id}")
    scheduled_date = request.form.get(f"date_{item_id}")
    photographer_id = int(photographer_id) if photographer_id else None
    cursor.execute("""
        UPDATE user_packages
        SET photographer_id=%s, location=%s, scheduled_date=%s
        WHERE id=%s AND user_id=%s
    """, (photographer_id, location, scheduled_date, item_id, session["user_id"]))
    db.commit()
    cursor.close()
    return redirect("/cart")

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
# ---------------- ORDERS PAGE ----------------
@app.route("/orders")
def orders():
    if "user_id" not in session:
        return redirect("/")
    
    db = get_db()
    cursor = db.cursor(dictionary=True)
    
    # Treat each cart item as a pending order for now
    cursor.execute("""
        SELECT up.id AS order_id,
               (p.package_price * up.quantity) AS total_price,
               'Pending' AS status,
               up.scheduled_date AS created_at
        FROM user_packages up
        JOIN packages p ON up.package_id = p.package_id
        WHERE up.user_id = %s
        ORDER BY up.id DESC
    """, (session["user_id"],))
    
    orders = cursor.fetchall()
    cursor.close()
    
    return render_template("orders.html", orders=orders)

# ---------------- ORDER DETAILS PAGE ----------------
@app.route("/order_details/<int:order_id>")
def order_details(order_id):
    if "user_id" not in session:
        return redirect("/")
    
    db = get_db()
    cursor = db.cursor(dictionary=True)
    
    # Fetch the specific "order" items
    cursor.execute("""
        SELECT up.id AS order_id,
               p.package_name,
               p.package_price AS price,
               p.duration,
               up.quantity,
               up.location,
               up.scheduled_date
        FROM user_packages up
        JOIN packages p ON up.package_id = p.package_id
        WHERE up.id = %s AND up.user_id = %s
    """, (order_id, session["user_id"]))
    
    items = cursor.fetchall()
    cursor.close()
    
    return render_template("order_details.html", items=items)

# ---------------------------Application Submit Page Route--------
from flask import flash, render_template, redirect, request

@app.route("/photographer/apply", methods=["POST"])
def apply_photographer():
    db = get_db()
    cursor = db.cursor()
    
    # Save the submitted application to the DB
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

    # Flash a success message
    flash("Your application has been submitted successfully!", "success")
    
    # Redirect to a dedicated confirmation page route
    return redirect("/photographer/submitted")

# ---------------------------Application Submitted Page Route--------
@app.route("/photographer/submitted")
def photographer_submitted():
    return render_template("photographer_submitted.html")

#----------------------------Checkout------------------

@app.route("/checkout", methods=["GET", "POST"])
def checkout():
    if "user_id" not in session:
        return redirect("/login")

    db = get_db()
    cursor = db.cursor(dictionary=True)

    # Fetch cart items from user_packages
    cursor.execute("""
        SELECT up.id AS cart_id, p.package_name, p.package_price, up.quantity,
               up.location, up.scheduled_date,
               ph.id AS photographer_id, ph.first_name, ph.last_name
        FROM user_packages up
        JOIN packages p ON up.package_id = p.package_id
        LEFT JOIN photographers ph ON up.photographer_id = ph.id
        WHERE up.user_id = %s
    """, (session["user_id"],))
    
    cart_items = cursor.fetchall()

    # Construct photographer_name
    for item in cart_items:
        if item["first_name"] and item["last_name"]:
            item["photographer_name"] = f"{item['first_name']} {item['last_name']}"
        else:
            item["photographer_name"] = None

    # Calculate total
    total = sum(item["package_price"] * item["quantity"] for item in cart_items)

    if request.method == "POST":
        payment_method = request.form.get("payment")
        for item in cart_items:
            scheduled_date = request.form.get(f"scheduled_date_{item['cart_id']}")
            cursor.execute("UPDATE user_packages SET scheduled_date=%s WHERE id=%s",
                           (scheduled_date, item["cart_id"]))
        db.commit()
        return redirect("/confirm_booking")  # or /orders

    cursor.close()
    return render_template("checkout.html", items=cart_items, total=total)
from flask import flash

# ---------------- ADMIN LOGIN ----------------
@app.route("/admin-login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        db = get_db()
        cursor = db.cursor(dictionary=True)

        username = request.form.get("username")
        password = request.form.get("password")

        cursor.execute("SELECT * FROM admin WHERE username=%s", (username,))
        admin = cursor.fetchone()
        cursor.close()

        if admin and admin["password"] == hash_password(password):
            session["admin_id"] = admin["id"]
            return redirect("/admin/dashboard")

        return render_template("admin_login.html", error="Invalid username or password")

    return render_template("admin_login.html")


# ---------------- ADMIN DASHBOARD ----------------
@app.route("/admin/dashboard")
def admin_dashboard():
    if "admin_id" not in session:
        return redirect("/admin-login")

    db = get_db()
    cursor = db.cursor(dictionary=True)

    cursor.execute("SELECT COUNT(*) AS total_orders FROM user_packages")
    total_orders = cursor.fetchone()["total_orders"]

    cursor.execute("""
        SELECT SUM(package_price * quantity) AS revenue 
        FROM user_packages 
        JOIN packages ON user_packages.package_id = packages.package_id
    """)
    revenue = cursor.fetchone()["revenue"] or 0

    cursor.execute("SELECT COUNT(*) AS total_users FROM users")
    total_users = cursor.fetchone()["total_users"]

    cursor.execute("""
        SELECT up.id AS order_id, u.first_name, u.last_name,
               (p.package_price * up.quantity) AS total_price,
               'Pending' AS status
        FROM user_packages up
        JOIN users u ON up.user_id = u.id
        JOIN packages p ON up.package_id = p.package_id
        ORDER BY up.id DESC LIMIT 5
    """)
    recent_orders = cursor.fetchall()

    cursor.execute("SELECT * FROM photographers_applications ORDER BY id DESC")
    applications = cursor.fetchall()

    cursor.close()

    return render_template("admin_dashboard.html",
        total_orders=total_orders,
        revenue=revenue,
        total_users=total_users,
        recent_orders=recent_orders,
        applications=applications
    )


# ---------------- ADMIN PHOTOGRAPHERS (NEW) ----------------
@app.route("/admin/photographers")
def admin_photographers():
    if "admin_id" not in session:
        return redirect("/admin-login")

    db = get_db()
    cursor = db.cursor(dictionary=True)

    cursor.execute("SELECT * FROM photographers")
    photographers = cursor.fetchall()

    cursor.close()
    return render_template("admin_photographers.html", photographers=photographers)


# ---------------- APPROVE PHOTOGRAPHER ----------------
@app.route("/admin/approve/<int:id>", methods=["POST"])
def approve_photographer(id):
    if "admin_id" not in session:
        return redirect("/admin-login")

    db = get_db()
    cursor = db.cursor()

    cursor.execute("""
        INSERT INTO photographers (first_name, last_name, email)
        SELECT first_name, last_name, email
        FROM photographers_applications WHERE id=%s
    """, (id,))

    cursor.execute("DELETE FROM photographers_applications WHERE id=%s", (id,))
    db.commit()

    cursor.close()
    return redirect("/admin/dashboard")


# ---------------- REJECT PHOTOGRAPHER ----------------
@app.route("/admin/reject/<int:id>", methods=["POST"])
def reject_photographer(id):
    if "admin_id" not in session:
        return redirect("/admin-login")

    db = get_db()
    cursor = db.cursor()

    cursor.execute("DELETE FROM photographers_applications WHERE id=%s", (id,))
    db.commit()

    cursor.close()
    return redirect("/admin/dashboard")


# ---------------- ADMIN ORDERS ----------------
@app.route("/admin/orders")
def admin_orders():
    if "admin_id" not in session:
        return redirect("/admin-login")

    db = get_db()
    cursor = db.cursor(dictionary=True)

    cursor.execute("""
        SELECT up.id AS order_id, u.first_name, u.last_name,
               (p.package_price * up.quantity) AS total_price,
               'Pending' AS status
        FROM user_packages up
        JOIN users u ON up.user_id = u.id
        JOIN packages p ON up.package_id = p.package_id
        ORDER BY up.id DESC
    """)
    orders = cursor.fetchall()

    cursor.close()
    return render_template("admin_orders.html", orders=orders)


# ---------------- ADMIN PACKAGES ----------------
@app.route("/admin/packages", methods=["GET", "POST"])
def admin_packages():
    if "admin_id" not in session:
        return redirect("/admin-login")

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
            flash("✅ Package added successfully!")

        except Exception as e:
            print("Add Package Error:", e)
            flash("❌ Error adding package")

        return redirect("/admin/packages")

    cursor.execute("SELECT * FROM packages ORDER BY package_id DESC")
    packages = cursor.fetchall()

    cursor.close()
    return render_template("admin_packages.html", packages=packages)


# ---------------- DELETE PACKAGE ----------------
@app.route("/admin/delete_package/<int:id>", methods=["POST"])
def delete_package(id):
    if "admin_id" not in session:
        return redirect("/admin-login")

    db = get_db()
    cursor = db.cursor()

    try:
        cursor.execute("DELETE FROM user_packages WHERE package_id=%s", (id,))
        cursor.execute("DELETE FROM packages WHERE package_id=%s", (id,))

        db.commit()
        flash("🗑️ Package deleted successfully!")

    except Exception as e:
        print("Delete Error:", e)
        flash("❌ Cannot delete package")

    cursor.close()
    return redirect("/admin/packages")


# ---------------- EDIT PACKAGE ----------------
@app.route("/admin/edit_package/<int:id>", methods=["GET", "POST"])
def edit_package(id):
    if "admin_id" not in session:
        return redirect("/admin-login")

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
            flash("✏️ Package updated successfully!")

            return redirect("/admin/packages")

        except Exception as e:
            print("Update Error:", e)
            flash("❌ Error updating package")

    cursor.execute("SELECT * FROM packages WHERE package_id=%s", (id,))
    package = cursor.fetchone()

    cursor.close()
    return render_template("edit_package.html", package=package)


# ---------------- ADMIN USERS ----------------
@app.route("/admin/users")
def admin_users():
    if "admin_id" not in session:
        return redirect("/admin-login")

    db = get_db()
    cursor = db.cursor(dictionary=True)

    cursor.execute("SELECT * FROM users")
    users = cursor.fetchall()

    cursor.close()
    return render_template("admin_users.html", users=users)


# ---------------- ORDER DETAILS (FIXED) ----------------
@app.route("/admin/order_details/<int:order_id>")
def admin_order_details(order_id):
    if "admin_id" not in session:
        return redirect("/admin-login")

    db = get_db()
    cursor = db.cursor(dictionary=True)

    cursor.execute("""
        SELECT p.package_name,
               p.package_price AS price,
               p.duration,
               up.quantity,
               up.location,
               (p.package_price * up.quantity) AS total
        FROM user_packages up
        JOIN packages p ON up.package_id = p.package_id
        WHERE up.id=%s
    """, (order_id,))

    items = cursor.fetchall()

    cursor.close()
    return render_template("admin_order_details.html", items=items)


# ---------------- DELETE USER ----------------
@app.route("/admin/delete_user/<int:id>", methods=["POST"])
def delete_user(id):
    if "admin_id" not in session:
        return redirect("/admin-login")

    db = get_db()
    cursor = db.cursor()

    try:
        cursor.execute("DELETE FROM user_packages WHERE user_id=%s", (id,))
        cursor.execute("DELETE FROM users WHERE id=%s", (id,))
        db.commit()

    except Exception as e:
        db.rollback()
        print("Delete Error:", e)

    cursor.close()
    return redirect("/admin/users")

# ---------------- LOGOUT ----------------
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

# ---------------- RUN APP ----------------
if __name__ == "__main__":
    app.run(debug=True)