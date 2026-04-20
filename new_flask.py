from flask import Flask, render_template, request, redirect, session, g, jsonify, flash
import mysql.connector
from mysql.connector import Error
import hashlib
import uuid
import os
from datetime import datetime
import time
from functools import wraps

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "secret_key_123")

# ---------------- DATABASE CONFIG ----------------
DB_HOST = os.getenv("DB_HOST")
DB_NAME = os.getenv("DB_NAME")
DB_USER = os.getenv("DB_USER")
DB_PASS = os.getenv("DB_PASS")
DB_PORT = os.getenv("DB_PORT")

# Detect cloud (Render/Railway/etc.)
ON_RENDER = DB_HOST is not None

# Fallback for local development
if not all([DB_HOST, DB_NAME, DB_USER, DB_PASS]):
    print("⚠️ Running locally (MySQL localhost)")
    DB_HOST = "localhost"
    DB_NAME = "sumedh"
    DB_USER = "root"
    DB_PASS = "sumedh2004"
    DB_PORT = 3306
    ON_RENDER = False
else:
    DB_PORT = int(DB_PORT) if DB_PORT else 3306
    print(f"📊 Cloud DB Connected → {DB_HOST}:{DB_PORT} | {DB_NAME}")

# ---------------- DECORATORS FOR AUTH ----------------
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            flash("Please login to access this page", "error")
            return redirect("/")
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "admin_id" not in session:
            flash("Please login as admin to access this page", "error")
            return redirect("/admin/login")
        return f(*args, **kwargs)
    return decorated_function

# ---------------- DATABASE CONNECTION WITH RETRY ----------------
def get_db():
    if "db" not in g:
        max_retries = 3
        retry_delay = 2

        for attempt in range(max_retries):
            try:
                config = {
                    'host': DB_HOST,
                    'user': DB_USER,
                    'password': DB_PASS,
                    'database': DB_NAME,
                    'port': DB_PORT,
                    'autocommit': False,
                    'use_pure': True,
                    'connection_timeout': 30
                }

                if ON_RENDER:
                    config['ssl_disabled'] = True

                g.db = mysql.connector.connect(**config)
                print("✅ Database connected successfully")
                break

            except Error as e:
                print(f"❌ DB Connection attempt {attempt + 1} failed: {e}")
                if attempt < max_retries - 1:
                    time.sleep(retry_delay)
                else:
                    print("❌ All connection attempts failed")
                    return None

            except Exception as e:
                print(f"❌ Unexpected error: {e}")
                return None

    return g.db

# ---------------- CLOSE DB ----------------
@app.teardown_appcontext
def close_db(exception):
    db = g.pop("db", None)
    if db is not None and db.is_connected():
        db.close()

# ---------------- TEST DATABASE ROUTE ----------------
@app.route("/test-db")
def test_db():
    try:
        db = get_db()
        if not db:
            return jsonify({
                "status": "error",
                "message": "Connection failed",
                "host": DB_HOST,
                "port": DB_PORT,
                "user": DB_USER,
                "db": DB_NAME,
                "on_render": ON_RENDER
            }), 500

        cursor = db.cursor(dictionary=True)
        cursor.execute("SELECT 1 as test")
        result = cursor.fetchone()
        cursor.close()

        return jsonify({
            "status": "success",
            "message": "Database connected!",
            "host": DB_HOST,
            "port": DB_PORT,
            "database": DB_NAME,
            "result": result
        })

    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e),
            "host": DB_HOST,
            "port": DB_PORT
        }), 500

# ---------------- Admin Login ----------------
@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        if request.form["username"] == "admin" and request.form["password"] == "admin123":
            session["admin_id"] = 1
            session["admin_username"] = "admin"
            flash("Welcome back, Admin!", "success")
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
            flash("Database connection error. Please try again.", "error")
            return redirect("/signup")
        cursor = db.cursor()
        try:
            if request.form["password"] != request.form["confirm_password"]:
                flash("Passwords do not match!", "error")
                return redirect("/signup")
            
            cursor.execute("SELECT id FROM users WHERE username = %s OR email = %s", 
                          (request.form["username"], request.form["email"]))
            if cursor.fetchone():
                flash("Username or email already exists. Please choose another.", "error")
                return redirect("/signup")
            
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
            flash("Signup successful! Please login.", "success")
            return redirect("/")
        except Exception as e:
            print("Signup Error:", e)
            db.rollback()
            flash("Signup failed. Username or email may already exist.", "error")
            return redirect("/signup")
        finally:
            cursor.close()
    return render_template("signup.html")

# ---------------- LOGIN ----------------
@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        db = get_db()
        if not db:
            flash("Database connection error", "error")
            return render_template("login.html", error="System error. Please try again.")
        
        cursor = db.cursor(dictionary=True)
        try:
            cursor.execute(
                "SELECT * FROM users WHERE username=%s AND password=%s",
                (request.form["username"], hash_password(request.form["password"]))
            )
            user = cursor.fetchone()
        except Exception as e:
            print("Login Error:", e)
            user = None
        finally:
            cursor.close()
            
        if user:
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["user_name"] = f"{user['first_name']} {user['last_name']}"
            flash(f"Welcome back, {user['first_name']}!", "success")
            return redirect("/home")
        return render_template("login.html", error="Invalid username or password")
    return render_template("login.html")

# ---------------- HOME ----------------
@app.route("/home")
@login_required
def home():
    db = get_db()
    if not db:
        flash("Database connection error", "error")
        return redirect("/")
        
    cursor = db.cursor(dictionary=True)

    try:
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
            LIMIT 10
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
            LIMIT 5
        """, (session["user_id"],))
        orders = cursor.fetchall()
    except Exception as e:
        print("Home Error:", e)
        packages = []
        package_reviews = []
        orders = []
    finally:
        cursor.close()

    return render_template(
        "home.html",
        packages=packages,
        package_reviews=package_reviews,
        orders=orders
    )

# ==================== PORTFOLIO / BEST WORK FEATURE ====================

# ---------------- API: GET PORTFOLIO DATA (for homepage & portfolio page) ----------------
@app.route("/api/portfolio")
def get_portfolio():
    """Return portfolio images grouped by photographer"""
    db = get_db()
    if not db:
        return jsonify([])  # Return empty list on error
    
    cursor = db.cursor(dictionary=True)
    try:
        # Check if table exists to avoid errors
        cursor.execute("SHOW TABLES LIKE 'portfolio_images'")
        if not cursor.fetchone():
            return jsonify([])
        
        cursor.execute("""
            SELECT 
                p.id as photographer_id,
                p.first_name,
                p.last_name,
                p.profile_image,
                p.rating,
                pi.id as image_id,
                pi.image_url,
                pi.location,
                pi.shoot_date,
                pi.description
            FROM photographers p
            JOIN portfolio_images pi ON p.id = pi.photographer_id
            WHERE p.status = 'active'
            ORDER BY p.id, pi.shoot_date DESC
        """)
        rows = cursor.fetchall()
        
        # Group images by photographer
        portfolio = {}
        for row in rows:
            pid = row['photographer_id']
            if pid not in portfolio:
                portfolio[pid] = {
                    'photographer_id': pid,
                    'name': f"{row['first_name']} {row['last_name']}",
                    'profile_image': row['profile_image'],
                    'rating': row['rating'],
                    'images': []
                }
            portfolio[pid]['images'].append({
                'id': row['image_id'],
                'url': row['image_url'],
                'location': row['location'],
                'shoot_date': row['shoot_date'].strftime('%Y-%m-%d') if row['shoot_date'] else None,
                'description': row['description']
            })
        
        return jsonify(list(portfolio.values()))
    except Exception as e:
        print("Portfolio API Error:", e)
        return jsonify([])
    finally:
        cursor.close()

# ---------------- DEDICATED PORTFOLIO PAGE ----------------
@app.route("/portfolio")
def portfolio_page():
    return render_template("portfolio.html")

# ---------------- ADMIN: PORTFOLIO MANAGEMENT (list photographers with image count) ----------------
@app.route("/admin/portfolio")
@admin_required
def admin_portfolio():
    db = get_db()
    cursor = db.cursor(dictionary=True)
    
    try:
        cursor.execute("""
            SELECT p.*, COUNT(pi.id) as image_count
            FROM photographers p
            LEFT JOIN portfolio_images pi ON p.id = pi.photographer_id
            GROUP BY p.id
            ORDER BY p.id DESC
        """)
        photographers = cursor.fetchall()
    except Exception as e:
        print("Admin Portfolio Error:", e)
        photographers = []
    finally:
        cursor.close()
    
    return render_template("admin_portfolio.html", photographers=photographers)

# ---------------- ADMIN: ADD PORTFOLIO IMAGE FOR A PHOTOGRAPHER ----------------
@app.route("/admin/portfolio/add/<int:photographer_id>", methods=["GET", "POST"])
@admin_required
def admin_add_portfolio_image(photographer_id):
    db = get_db()
    
    if request.method == "POST":
        image_url = request.form.get("image_url")
        location = request.form.get("location")
        shoot_date = request.form.get("shoot_date")
        description = request.form.get("description")
        
        cursor = db.cursor()
        try:
            cursor.execute("""
                INSERT INTO portfolio_images (photographer_id, image_url, location, shoot_date, description)
                VALUES (%s, %s, %s, %s, %s)
            """, (photographer_id, image_url, location, shoot_date, description))
            db.commit()
            flash("✅ Image added to portfolio!", "success")
        except Exception as e:
            print("Add Portfolio Error:", e)
            db.rollback()
            flash("❌ Error adding image", "error")
        finally:
            cursor.close()
        return redirect("/admin/portfolio")
    
    # GET - show form
    cursor = db.cursor(dictionary=True)
    try:
        cursor.execute("SELECT * FROM photographers WHERE id = %s", (photographer_id,))
        photographer = cursor.fetchone()
    except Exception as e:
        print("Fetch Photographer Error:", e)
        photographer = None
    finally:
        cursor.close()
    
    if not photographer:
        flash("Photographer not found!", "error")
        return redirect("/admin/portfolio")
    
    return render_template("admin_add_portfolio_image.html", photographer=photographer)

# ---------------- ADMIN: DELETE PORTFOLIO IMAGE ----------------
@app.route("/admin/portfolio/delete/<int:image_id>", methods=["POST"])
@admin_required
def admin_delete_portfolio_image(image_id):
    db = get_db()
    cursor = db.cursor()
    try:
        cursor.execute("DELETE FROM portfolio_images WHERE id = %s", (image_id,))
        db.commit()
        flash("🗑️ Image deleted successfully", "success")
    except Exception as e:
        print("Delete Portfolio Error:", e)
        db.rollback()
        flash("❌ Error deleting image", "error")
    finally:
        cursor.close()
    return redirect("/admin/portfolio")

# ---------------- UPDATE PHOTOGRAPHER EDIT FORM TO INCLUDE PROFILE_IMAGE ----------------
@app.route("/admin/edit_photographer/<int:id>", methods=["GET", "POST"])
@admin_required
def edit_photographer(id):
    db = get_db()
    if not db:
        flash("Database error", "error")
        return redirect("/admin/photographers")
        
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
            profile_image = request.form.get("profile_image")
            
            cursor.execute("""
                UPDATE photographers 
                SET first_name=%s, last_name=%s, email=%s, phone=%s, 
                    experience=%s, rating=%s, status=%s, profile_image=%s
                WHERE id=%s
            """, (first_name, last_name, email, phone, experience, rating, status, profile_image, id))
            db.commit()
            flash("✅ Photographer updated successfully!", "success")
            return redirect("/admin/photographers")
        except Exception as e:
            print("Update Error:", e)
            db.rollback()
            flash("❌ Error updating photographer", "error")
            return redirect(f"/admin/edit_photographer/{id}")
    
    try:
        cursor.execute("SELECT * FROM photographers WHERE id=%s", (id,))
        photographer = cursor.fetchone()
    except Exception as e:
        print("Fetch Photographer Error:", e)
        photographer = None
    finally:
        cursor.close()
    
    if not photographer:
        flash("❌ Photographer not found!", "error")
        return redirect("/admin/photographers")
    
    return render_template("admin_edit_photographer.html", photographer=photographer)

# ==================== END OF PORTFOLIO FEATURE ====================

# ---------------- CART ----------------
@app.route("/cart", methods=["GET", "POST"])
@login_required
def cart():
    user_id = session.get("user_id")
    db = get_db()
    if not db:
        flash("Database connection error", "error")
        return redirect("/home")
        
    cursor = db.cursor(dictionary=True)

    if request.method == "POST":
        try:
            for key, value in request.form.items():
                if key.startswith("photographer_"):
                    cart_item_id = int(key.split("_")[1])
                    photographer_id = int(value) if value else None
                    location = request.form.get(f"location_{cart_item_id}", "")
                    scheduled_date = request.form.get(f"date_{cart_item_id}", None)
                    cursor.execute("""
                        UPDATE user_packages
                        SET photographer_id=%s, location=%s, scheduled_date=%s
                        WHERE id=%s AND user_id=%s
                    """, (photographer_id, location, scheduled_date, cart_item_id, user_id))
            db.commit()
            flash("✅ Cart updated successfully!", "success")
        except Exception as e:
            print("Cart Update Error:", e)
            db.rollback()
            flash("❌ Error updating cart", "error")
        finally:
            cursor.close()
        return redirect("/cart")

    # Fetch cart items
    try:
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
            SELECT id, CONCAT(first_name, ' ', last_name) AS name, rating, status
            FROM photographers
            WHERE status = 'active'
            ORDER BY rating DESC
        """)
        photographers = cursor.fetchall()

        total = sum(item["package_price"] * item["quantity"] for item in cart_items)
    except Exception as e:
        print("Cart Fetch Error:", e)
        cart_items = []
        photographers = []
        total = 0
        flash("Error loading cart", "error")
    finally:
        cursor.close()
        
    return render_template("cart.html", cart_items=cart_items, total=total, photographers=photographers)

# ---------------- ADD TO CART ----------------
@app.route("/add_package/<int:package_id>", methods=["POST"])
@login_required
def add_package(package_id):
    db = get_db()
    if not db:
        return jsonify({"status": "error", "message": "Database error"})
        
    cursor = db.cursor(dictionary=True)
    try:
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
        return jsonify({"status": "success", "message": "Package added to cart"})
    except Exception as e:
        print("Add to Cart Error:", e)
        db.rollback()
        return jsonify({"status": "error", "message": str(e)})
    finally:
        cursor.close()

# ---------------- REMOVE ITEM ----------------
@app.route("/remove/<int:id>", methods=["POST"])
@login_required
def remove(id):
    db = get_db()
    if not db:
        flash("Database error", "error")
        return redirect("/cart")
        
    cursor = db.cursor(dictionary=True)
    try:
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
        flash("Item removed from cart", "success")
    except Exception as e:
        print("Remove Error:", e)
        db.rollback()
        flash("Error removing item", "error")
    finally:
        cursor.close()
    return redirect("/cart")

# ---------------- EMPTY CART ----------------
@app.route("/empty_cart", methods=["POST"])
@login_required
def empty_cart():
    db = get_db()
    if not db:
        flash("Database error", "error")
        return redirect("/cart")
        
    cursor = db.cursor()
    try:
        cursor.execute("DELETE FROM user_packages WHERE user_id=%s", (session["user_id"],))
        db.commit()
        flash("Cart emptied successfully!", "success")
    except Exception as e:
        print("Empty Cart Error:", e)
        db.rollback()
        flash("Error emptying cart", "error")
    finally:
        cursor.close()
    return redirect("/cart")

# ---------------- UPDATE INDIVIDUAL CART ITEM ----------------
@app.route("/update_item/<int:item_id>", methods=["POST"])
@login_required
def update_item(item_id):
    db = get_db()
    if not db:
        flash("Database error", "error")
        return redirect("/cart")
        
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
    finally:
        cursor.close()
    return redirect("/cart")

# ---------------- EDIT PROFILE ----------------
@app.route("/edit-profile", methods=["GET", "POST"])
@login_required
def edit_profile():
    db = get_db()
    if not db:
        flash("Database error", "error")
        return redirect("/home")
        
    cursor = db.cursor(dictionary=True)
    
    if request.method == "POST":
        try:
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
            flash("✅ Profile updated successfully!", "success")
            return redirect("/home")
        except Exception as e:
            print("Profile Update Error:", e)
            db.rollback()
            flash("❌ Error updating profile", "error")
        finally:
            cursor.close()
    else:
        try:
            cursor.execute("SELECT * FROM users WHERE id=%s", (session["user_id"],))
            user = cursor.fetchone()
        except Exception as e:
            print("Profile Fetch Error:", e)
            user = None
        finally:
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
@login_required
def orders():
    db = get_db()
    if not db:
        flash("Database error", "error")
        return redirect("/home")
        
    cursor = db.cursor(dictionary=True)

    try:
        cursor.execute("""
            SELECT order_id, total_price, status, created_at, location, scheduled_date
            FROM orders
            WHERE user_id = %s
            ORDER BY created_at DESC
        """, (session["user_id"],))
        orders = cursor.fetchall()
    except Exception as e:
        print("Orders Error:", e)
        orders = []
    finally:
        cursor.close()

    return render_template("orders.html", orders=orders)

#------------------ Order Details ----------------
@app.route("/order_details/<string:order_id>")
@login_required
def order_details(order_id):
    db = get_db()
    if not db:
        flash("Database error", "error")
        return redirect("/orders")
        
    cursor = db.cursor(dictionary=True)

    try:
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
            return render_template("order_details.html", order=None, items=[], subtotal=0, gst_amount=0, service_charge=0, grand_total=0)

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
        
        subtotal = 0.0
        for item in items:
            price = float(item["price"]) if item["price"] else 0
            quantity = int(item["quantity"]) if item["quantity"] else 0
            subtotal += price * quantity
        
        gst_amount = subtotal * 0.18
        service_charge = subtotal * 0.05
        grand_total = subtotal + gst_amount + service_charge
        
    except Exception as e:
        print("Order Details Error:", e)
        flash(f"Error loading order: {str(e)}", "error")
        order = None
        items = []
        subtotal = 0
        gst_amount = 0
        service_charge = 0
        grand_total = 0
    finally:
        cursor.close()

    return render_template(
        "order_details.html", 
        order=order, 
        items=items, 
        subtotal=subtotal,
        gst_amount=gst_amount,
        service_charge=service_charge,
        grand_total=grand_total
    )

# ---------------- PHOTOGRAPHER APPLY ----------------
@app.route("/photographer/apply", methods=["POST"])
def apply_photographer():
    db = get_db()
    if not db:
        flash("Database error", "error")
        return redirect("/get-hired")
        
    cursor = db.cursor()
    try:
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
        flash("🎉 Your application has been submitted successfully!", "success")
    except Exception as e:
        print("Application Error:", e)
        db.rollback()
        flash("❌ Error submitting application", "error")
    finally:
        cursor.close()
    return redirect("/photographer/submitted")

# ---------------- PHOTOGRAPHER SUBMITTED PAGE ----------------
@app.route("/photographer/submitted")
def photographer_submitted():
    return render_template("photographer_submitted.html")

# ---------------- ADMIN DASHBOARD ----------------
@app.route("/admin/dashboard")
@admin_required
def admin_dashboard():
    db = get_db()
    if not db:
        flash("Database error", "error")
        return redirect("/admin/login")
        
    cursor = db.cursor(dictionary=True)
    
    try:
        cursor.execute("SELECT COUNT(*) as count FROM orders")
        total_orders = cursor.fetchone()["count"]
        
        cursor.execute("SELECT COALESCE(SUM(total_price), 0) as total FROM orders WHERE status = 'Confirmed'")
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
    except Exception as e:
        print("Admin Dashboard Error:", e)
        total_orders = 0
        revenue = 0
        total_users = 0
        total_photographers = 0
        recent_orders = []
        applications = []
    finally:
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
@admin_required
def admin_order_details(order_id):
    db = get_db()
    if not db:
        flash("Database error", "error")
        return redirect("/admin/dashboard")
        
    cursor = db.cursor(dictionary=True)
    
    try:
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
    except Exception as e:
        print("Admin Order Details Error:", e)
        order = None
        items = []
    finally:
        cursor.close()
    
    return render_template("admin_order_details.html", order=order, items=items)

# ---------------- ADMIN PHOTOGRAPHERS ----------------
@app.route("/admin/photographers")
@admin_required
def admin_photographers():
    db = get_db()
    if not db:
        flash("Database error", "error")
        return redirect("/admin/dashboard")
        
    cursor = db.cursor(dictionary=True)
    try:
        cursor.execute("SELECT * FROM photographers ORDER BY id DESC")
        photographers = cursor.fetchall()
    except Exception as e:
        print("Admin Photographers Error:", e)
        photographers = []
    finally:
        cursor.close()
    return render_template("admin_photographers.html", photographers=photographers)

# ---------------- ADMIN APPROVE PHOTOGRAPHER ----------------
@app.route("/admin/approve/<int:id>", methods=["POST"])
@admin_required
def approve_photographer(id):
    db = get_db()
    if not db:
        flash("Database error", "error")
        return redirect("/admin/dashboard")
        
    cursor = db.cursor()
    try:
        cursor.execute("""
            INSERT INTO photographers (first_name, last_name, email, phone, address, status, rating)
            SELECT first_name, last_name, email, phone, address, 'active', 0
            FROM photographers_applications WHERE id=%s
        """, (id,))
        cursor.execute("DELETE FROM photographers_applications WHERE id=%s", (id,))
        db.commit()
        flash("✅ Photographer approved successfully!", "success")
    except Exception as e:
        print("Approve Error:", e)
        db.rollback()
        flash("❌ Error approving photographer", "error")
    finally:
        cursor.close()
    return redirect("/admin/dashboard")

# ---------------- ADMIN REJECT PHOTOGRAPHER ----------------
@app.route("/admin/reject/<int:id>", methods=["POST"])
@admin_required
def reject_photographer(id):
    db = get_db()
    if not db:
        flash("Database error", "error")
        return redirect("/admin/dashboard")
        
    cursor = db.cursor()
    try:
        cursor.execute("DELETE FROM photographers_applications WHERE id=%s", (id,))
        db.commit()
        flash("❌ Application rejected!", "error")
    except Exception as e:
        print("Reject Error:", e)
        db.rollback()
        flash("❌ Error rejecting application", "error")
    finally:
        cursor.close()
    return redirect("/admin/dashboard")

# ---------------- ADMIN ORDERS ----------------
@app.route("/admin/orders")
@admin_required
def admin_orders():
    db = get_db()
    if not db:
        flash("Database error", "error")
        return redirect("/admin/dashboard")
        
    cursor = db.cursor(dictionary=True)
    try:
        cursor.execute("""
            SELECT o.order_id, o.total_price, o.status, o.created_at,
                   u.first_name, u.last_name
            FROM orders o
            JOIN users u ON o.user_id = u.id
            ORDER BY o.created_at DESC
        """)
        orders = cursor.fetchall()
    except Exception as e:
        print("Admin Orders Error:", e)
        orders = []
    finally:
        cursor.close()
    return render_template("admin_orders.html", orders=orders)

# ---------------- ADMIN UPDATE ORDER STATUS ----------------
@app.route("/admin/update_order_status/<string:order_id>", methods=["POST"])
@admin_required
def update_order_status(order_id):
    new_status = request.form.get("status")
    db = get_db()
    if not db:
        flash("Database error", "error")
        return redirect("/admin/dashboard")
        
    cursor = db.cursor()
    try:
        cursor.execute("UPDATE orders SET status = %s WHERE order_id = %s", (new_status, order_id))
        db.commit()
        flash(f"✅ Order status updated to {new_status}!", "success")
    except Exception as e:
        print("Update Status Error:", e)
        db.rollback()
        flash("❌ Error updating order status", "error")
    finally:
        cursor.close()
    return redirect(f"/admin/order_details/{order_id}")

# ---------------- ADMIN PACKAGES ----------------
@app.route("/admin/packages", methods=["GET", "POST"])
@admin_required
def admin_packages():
    db = get_db()
    if not db:
        flash("Database error", "error")
        return redirect("/admin/dashboard")
        
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
            db.rollback()
            flash("❌ Error adding package", "error")
        return redirect("/admin/packages")
    
    try:
        cursor.execute("SELECT * FROM packages ORDER BY package_id DESC")
        packages = cursor.fetchall()
    except Exception as e:
        print("Fetch Packages Error:", e)
        packages = []
    finally:
        cursor.close()
    return render_template("admin_packages.html", packages=packages)

# ---------------- DELETE PACKAGE ----------------
@app.route("/admin/delete_package/<int:id>", methods=["POST"])
@admin_required
def delete_package(id):
    db = get_db()
    if not db:
        flash("Database error", "error")
        return redirect("/admin/packages")
        
    cursor = db.cursor()
    try:
        cursor.execute("DELETE FROM user_packages WHERE package_id=%s", (id,))
        cursor.execute("DELETE FROM packages WHERE package_id=%s", (id,))
        db.commit()
        flash("🗑️ Package deleted successfully!", "success")
    except Exception as e:
        print("Delete Error:", e)
        db.rollback()
        flash("❌ Cannot delete package", "error")
    finally:
        cursor.close()
    return redirect("/admin/packages")

# ---------------- EDIT PACKAGE ----------------
@app.route("/admin/edit_package/<int:id>", methods=["GET", "POST"])
@admin_required
def edit_package(id):
    db = get_db()
    if not db:
        flash("Database error", "error")
        return redirect("/admin/packages")
        
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
            db.rollback()
            flash("❌ Error updating package", "error")
    else:
        try:
            cursor.execute("SELECT * FROM packages WHERE package_id=%s", (id,))
            package = cursor.fetchone()
        except Exception as e:
            print("Fetch Package Error:", e)
            package = None
        finally:
            cursor.close()
        return render_template("edit_package.html", package=package)

# ---------------- ADMIN USERS ----------------
@app.route("/admin/users")
@admin_required
def admin_users():
    db = get_db()
    if not db:
        flash("Database error", "error")
        return redirect("/admin/dashboard")
        
    cursor = db.cursor(dictionary=True)
    try:
        cursor.execute("SELECT id, first_name, last_name, email, mobile, username, role, created_at FROM users ORDER BY id DESC")
        users = cursor.fetchall()
    except Exception as e:
        print("Admin Users Error:", e)
        users = []
    finally:
        cursor.close()
    return render_template("admin_users.html", users=users)

# ---------------- DELETE USER ----------------
@app.route("/admin/delete_user/<int:id>", methods=["POST"])
@admin_required
def delete_user(id):
    db = get_db()
    if not db:
        flash("Database error", "error")
        return redirect("/admin/users")
        
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
    finally:
        cursor.close()
    return redirect("/admin/users")

# ---------------- ADMIN DELETE PHOTOGRAPHER ----------------
@app.route("/admin/delete_photographer/<int:id>", methods=["POST"])
@admin_required
def delete_photographer(id):
    db = get_db()
    if not db:
        flash("Database error", "error")
        return redirect("/admin/photographers")
        
    cursor = db.cursor()
    
    try:
        cursor.execute("SELECT first_name, last_name FROM photographers WHERE id=%s", (id,))
        photographer = cursor.fetchone()
        
        if photographer:
            cursor.execute("DELETE FROM photographers WHERE id=%s", (id,))
            db.commit()
            flash(f"✅ Photographer deleted successfully!", "success")
        else:
            flash("❌ Photographer not found!", "error")
    except Exception as e:
        print("Delete Error:", e)
        db.rollback()
        flash("❌ Error deleting photographer", "error")
    finally:
        cursor.close()
    return redirect("/admin/photographers")

# ---------------- ADMIN VIEW USER ----------------
@app.route('/admin/view_user/<int:user_id>')
@admin_required
def view_user(user_id):
    db = get_db()
    if not db:
        flash("Database error", "error")
        return redirect('/admin/users')
        
    cursor = db.cursor(dictionary=True)

    try:
        cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        user = cursor.fetchone()

        if not user:
            flash("User not found", "error")
            return redirect('/admin/users')

        cursor.execute("""
            SELECT order_id, total_price, status, created_at 
            FROM orders 
            WHERE user_id = %s 
            ORDER BY created_at DESC
        """, (user_id,))
        orders = cursor.fetchall()
        user['orders'] = orders
    except Exception as e:
        print("View User Error:", e)
        user = None
    finally:
        cursor.close()

    return render_template('admin_view_user.html', user=user)

# ---------------- Order Success ----------------
@app.route("/order-success")
def order_success():
    order_id = request.args.get("order_id")
    total = request.args.get("total")
    return render_template("order_success.html", order_id=order_id, total=total)

#----------------- CheckOut Route----------------
@app.route("/checkout", methods=["GET", "POST"])
@login_required
def checkout():
    db = get_db()
    if not db:
        flash("Database error", "error")
        return redirect("/cart")
        
    cursor = db.cursor(dictionary=True)

    # ---------------- GET ----------------
    if request.method == "GET":
        try:
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

            for item in items:
                if not item["photographer_id"] or not item["location"] or not item["scheduled_date"]:
                    flash("⚠️ Please complete all package details before checkout!", "error")
                    return redirect("/cart")

            total = sum(item["package_price"] * item["quantity"] for item in items)

        except Exception as e:
            print("Checkout GET Error:", e)
            items = []
            total = 0
        finally:
            cursor.close()

        return render_template("checkout.html", items=items, total=total)

    # ---------------- POST ----------------
    if request.method == "POST":
        payment_method = request.form.get("payment")

        try:
            cursor.execute("""
                SELECT up.*, p.package_name, p.package_price, p.duration
                FROM user_packages up
                JOIN packages p ON up.package_id = p.package_id
                WHERE up.user_id = %s
            """, (session["user_id"],))

            cart_items = cursor.fetchall()

            if not cart_items:
                flash("Your cart is empty!", "error")
                return redirect("/cart")

            for item in cart_items:
                if not item["photographer_id"] or not item["location"] or not item["scheduled_date"]:
                    flash("⚠️ Please complete all package details before placing order!", "error")
                    return redirect("/cart")

            total = sum(item["package_price"] * item["quantity"] for item in cart_items)

            location = cart_items[0]["location"]
            scheduled_date = cart_items[0]["scheduled_date"]

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

            cursor.execute("DELETE FROM user_packages WHERE user_id=%s", (session["user_id"],))

            db.commit()
            cursor.close()

            flash("🎉 Order placed successfully!", "success")
            return redirect(f"/order-success?order_id={order_code}&total={total}")

        except Exception as e:
            print("Checkout POST Error:", e)
            db.rollback()
            flash("❌ Error processing checkout", "error")
            cursor.close()
            return redirect("/cart")

# ---------------- LOGOUT ----------------
@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out successfully.", "success")
    return redirect("/")

# ---------------- RUN APP ----------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=False)