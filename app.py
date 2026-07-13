from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, abort, send_from_directory
from functools import wraps
import os
from datetime import datetime
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from database import create_db_session, prepare_database

app = Flask(__name__)
app.secret_key = os.urandom(32)

prepare_database()

# Configure upload path and rules
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static', 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def send_email_notification(recipient_email, subject, body):
    """Mocks sending email notifications by writing them to email_logs.txt."""
    log_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'email_logs.txt')
    log_entry = f"=========================================\n"
    log_entry += f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
    log_entry += f"To: {recipient_email}\n"
    log_entry += f"Subject: {subject}\n"
    log_entry += f"-----------------------------------------\n"
    log_entry += f"{body}\n"
    log_entry += f"=========================================\n\n"
    try:
        with open(log_path, 'a', encoding='utf-8') as f:
            f.write(log_entry)
    except Exception as e:
        print("Failed to write mock email log:", e)
    print(f"[EMAIL MOCK] Sent to {recipient_email}: {subject}")

def add_dashboard_notification(user_id, message):
    """Creates a dashboard notification for the user."""
    conn = create_db_session()
    conn.execute("INSERT INTO notifications (user_id, message) VALUES (?, ?)", (user_id, message))
    conn.commit()
    conn.close()

def verify_user_logged_in(func):
    """Enforces that a valid user session exists."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            flash("Authentication required. Please log in first.", "error")
            return redirect(url_for('login'))
        return func(*args, **kwargs)
    return wrapper

def verify_user_access_role(permitted_roles):
    """Restricts access to specific user roles (e.g., Admin, Staff, Guide, Trekker)."""
    expanded_roles = list(permitted_roles)
    if 'Staff' in expanded_roles and 'Guide' not in expanded_roles:
        expanded_roles.append('Guide')
    
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if 'user_id' not in session:
                flash("Authentication required. Please log in first.", "error")
                return redirect(url_for('login'))
            if session.get('role') not in expanded_roles:
                flash("Unauthorized access. You do not have the required permissions.", "error")
                return redirect(url_for('dashboard'))
            return func(*args, **kwargs)
        return wrapper
    return decorator

@app.before_request
def enforce_security_checks():
    """Validates user account status in real-time on every authenticated request."""
    exempt_routes = ['static', 'login', 'logout', 'home', 'register_trekker', 'register_staff']
    if request.endpoint in exempt_routes or not request.endpoint:
        return

    if 'user_id' in session:
        conn = create_db_session()
        current_user = conn.execute(
            "SELECT status, role FROM users WHERE id = ?",
            (session['user_id'],)
        ).fetchone()
        conn.close()

        if not current_user:
            session.clear()
            flash("Your account has been deleted.", "error")
            return redirect(url_for('login'))

        session['status'] = current_user['status']

        if current_user['status'] == 'Blacklisted':
            session.clear()
            flash("Access denied: Your account has been blacklisted or deactivated.", "error")
            return redirect(url_for('login'))

        # If a Guide or Staff is NOT approved, they can ONLY visit the pending dashboard,
        # verification form, logout, or serve-document endpoints.
        if current_user['role'] in ['Staff', 'Guide'] and current_user['status'] != 'Approved':
            allowed_pending_endpoints = ['pending_dashboard', 'verification_form', 'logout', 'serve_document', 'static']
            if request.endpoint not in allowed_pending_endpoints:
                return redirect(url_for('pending_dashboard'))

@app.route('/')
def home():
    """Renders the public application homepage with dynamic database counts."""
    conn = create_db_session()
    num_trekkers = conn.execute("SELECT COUNT(*) FROM users WHERE role='Trekker'").fetchone()[0]
    num_staff = conn.execute("SELECT COUNT(*) FROM users WHERE role IN ('Staff', 'Guide') AND status='Approved'").fetchone()[0]
    num_treks = conn.execute("SELECT COUNT(*) FROM treks").fetchone()[0]
    conn.close()
    return render_template(
        'home.html',
        num_trekkers=num_trekkers,
        num_staff=num_staff,
        num_treks=num_treks
    )

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handles secure user authentication and session establishment."""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        uname = request.form.get('username', '').strip()
        pwd = request.form.get('password', '')

        if not uname or not pwd:
            flash("Please enter both username/email and password.", "error")
            return render_template('login.html')

        conn = create_db_session()
        # Support logging in by username OR email
        db_user = conn.execute("SELECT * FROM users WHERE username = ? OR email = ?", (uname, uname)).fetchone()
        conn.close()

        if db_user and check_password_hash(db_user['password_hash'], pwd):
            if db_user['status'] == 'Blacklisted':
                flash("Access denied: Your account has been deactivated or blacklisted.", "error")
                return render_template('login.html')

            session['user_id'] = db_user['id']
            session['username'] = db_user['username']
            session['role'] = db_user['role']
            session['status'] = db_user['status']

            if db_user['role'] in ['Staff', 'Guide']:
                conn = create_db_session()
                profile = conn.execute("SELECT approved_viewed FROM guide_profiles WHERE user_id = ?", (db_user['id'],)).fetchone()
                conn.close()
                if db_user['status'] == 'Approved' and profile and profile['approved_viewed'] == 0:
                    session['show_approval_success'] = True

            flash(f"Welcome back, {db_user['username']}!", "success")
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid credentials. Please try again.", "error")

    return render_template('login.html')

@app.route('/register/trekker', methods=['GET', 'POST'])
def register_trekker():
    """Registers new user/trekker accounts with instant approval status."""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        uname = request.form.get('username', '').strip()
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip()
        phone = request.form.get('phone', '').strip()
        location = request.form.get('location', '').strip()
        pwd = request.form.get('password', '')
        confirm_pwd = request.form.get('confirm_password', '')

        if not uname or not name or not email or not phone or not location or not pwd or not confirm_pwd:
            flash("All form fields are mandatory.", "error")
            return render_template('register_trekker.html')

        if pwd != confirm_pwd:
            flash("Passwords do not match.", "error")
            return render_template('register_trekker.html')

        conn = create_db_session()
        existing = conn.execute("SELECT id FROM users WHERE username = ?", (uname,)).fetchone()
        if existing:
            conn.close()
            flash("Username is already taken.", "error")
            return render_template('register_trekker.html')

        hashed_pwd = generate_password_hash(pwd)
        try:
            conn.execute(
                "INSERT INTO users (username, password_hash, role, status, name, email, phone, location) VALUES (?, ?, 'Trekker', 'Approved', ?, ?, ?, ?)",
                (uname, hashed_pwd, name, email, phone, location)
            )
            conn.commit()
            flash("Registration successful! You can now log in.", "success")
            return redirect(url_for('login'))
        except Exception:
            flash("Registration failed. Please contact support.", "error")
        finally:
            conn.close()

    return render_template('register_trekker.html')

@app.route('/register/staff', methods=['GET', 'POST'])
def register_staff():
    """Registers a new guide or staff applicant, defaulting to pending status."""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        uname = request.form.get('username', '').strip()
        real_name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip()
        phone = request.form.get('phone', '').strip()
        location = request.form.get('location', '').strip()
        pwd = request.form.get('password', '')
        confirm_pwd = request.form.get('confirm_password', '')
        role = request.form.get('role', 'Staff').strip()

        if role not in ['Staff', 'Guide']:
            role = 'Staff'

        if not uname or not real_name or not email or not phone or not location or not pwd or not confirm_pwd:
            flash("All registration fields are required.", "error")
            return render_template('register_staff.html')

        if pwd != confirm_pwd:
            flash("Passwords do not match.", "error")
            return render_template('register_staff.html')

        conn = create_db_session()
        existing = conn.execute("SELECT id FROM users WHERE username = ?", (uname,)).fetchone()
        if existing:
            conn.close()
            flash("Username is already taken.", "error")
            return render_template('register_staff.html')

        hashed_pwd = generate_password_hash(pwd)
        try:
            cursor = conn.cursor()
            # Register user with 'Pending' status and selected role (Staff or Guide)
            cursor.execute(
                "INSERT INTO users (username, password_hash, role, status, name, email, phone, location) VALUES (?, ?, ?, 'Pending', ?, ?, ?, ?)",
                (uname, hashed_pwd, role, real_name, email, phone, location)
            )
            new_staff_id = cursor.lastrowid
            
            # Seed staff_profiles for backward compatibility
            cursor.execute(
                "INSERT INTO staff_profiles (user_id, name, contact_details, age, gender, experience, emergency_contact) VALUES (?, ?, ?, NULL, NULL, NULL, NULL)",
                (new_staff_id, real_name, f"Email: {email}, Phone: {phone}, Location: {location}")
            )
            
            # Seed guide_profiles with default values and approved_viewed = 0
            cursor.execute(
                "INSERT INTO guide_profiles (user_id, role, phone, approved_viewed) VALUES (?, ?, ?, 0)",
                (new_staff_id, role, phone)
            )
            
            conn.commit()
            
            # Log mock email notification
            send_email_notification(
                email,
                "TrekManagement Account Registration Submitted",
                f"Dear {real_name},\n\nThank you for registering as a {role} at TrekManagement. "
                "Your account status is currently Pending. "
                "Please log in and submit the Verification Form to request administrator review."
            )
            
            flash("Account registered successfully! Please log in to complete your verification profile.", "success")
            return redirect(url_for('login'))
        except Exception as e:
            conn.rollback()
            flash("Failed to register account. Please try again.", "error")
        finally:
            conn.close()

    return render_template('register_staff.html')

@app.route('/logout')
def logout():
    """Clears the active session and signs out the user."""
    session.clear()
    flash("You have successfully signed out.", "success")
    return redirect(url_for('home'))

@app.route('/dashboard')
@verify_user_logged_in
def dashboard():
    """Redirects to the respective role-based dashboard."""
    user_role = session.get('role')
    if user_role == 'Admin':
        return redirect(url_for('admin_dashboard'))
    elif user_role in ['Staff', 'Guide']:
        conn = create_db_session()
        u = conn.execute("SELECT status FROM users WHERE id = ?", (session['user_id'],)).fetchone()
        conn.close()
        
        if u and u['status'] == 'Approved':
            if session.get('show_approval_success'):
                return redirect(url_for('approval_success'))
            return redirect(url_for('staff_dashboard'))
        else:
            return redirect(url_for('pending_dashboard'))
    elif user_role == 'Trekker':
        return redirect(url_for('trekker_dashboard'))
    else:
        session.clear()
        return redirect(url_for('login'))

@app.route('/admin/dashboard')
@verify_user_access_role(['Admin'])
def admin_dashboard():
    """Loads metrics, charts and pending staff requests on the admin panel."""
    conn = create_db_session()
    
    metrics = {
        'total_treks': conn.execute("SELECT COUNT(*) FROM treks").fetchone()[0],
        'total_bookings': conn.execute("SELECT COUNT(*) FROM bookings").fetchone()[0],
        'total_trekkers': conn.execute("SELECT COUNT(*) FROM users WHERE role='Trekker'").fetchone()[0],
        'total_staff': conn.execute("SELECT COUNT(*) FROM users WHERE role IN ('Staff', 'Guide')").fetchone()[0]
    }

    pending_list = conn.execute(
        """SELECT u.id as user_id, u.username, sp.name, sp.contact_details
           FROM users u
           JOIN staff_profiles sp ON u.id = sp.user_id
           WHERE u.role IN ('Staff', 'Guide') AND u.status='Pending'"""
    ).fetchall()

    conn.close()
    return render_template('admin_dashboard.html', stats=metrics, pending_staff=pending_list)

@app.route('/admin/approve-staff/<int:user_id>', methods=['POST'])
@verify_user_access_role(['Admin'])
def admin_approve_staff(user_id):
    """Approves a staff guide registration request."""
    conn = create_db_session()
    conn.execute("UPDATE users SET status = 'Approved' WHERE id = ? AND role IN ('Staff', 'Guide')", (user_id,))
    
    # Initialize/Sync default profiles if needed
    user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if user:
        profile = conn.execute("SELECT * FROM guide_profiles WHERE user_id = ?", (user_id,)).fetchone()
        if not profile:
            conn.execute(
                """INSERT OR IGNORE INTO guide_profiles (user_id, role, phone, approved_viewed)
                   VALUES (?, ?, ?, 0)""",
                (user_id, user['role'], user['phone'])
            )
            
        conn.execute(
            """INSERT OR REPLACE INTO staff_profiles (user_id, name, contact_details, age, gender, experience, emergency_contact)
               VALUES (?, ?, ?, NULL, NULL, NULL, NULL)""",
            (user_id, user['name'], f"Email: {user['email']}, Phone: {user['phone']}, Location: {user['location']}")
        )
        
        conn.execute(
            "INSERT INTO approval_requests (user_id, status, admin_comment, reviewed_by, reviewed_at) VALUES (?, 'Approved', 'Approved via quick admin action.', ?, CURRENT_TIMESTAMP)",
            (user_id, session.get('user_id'))
        )
        
        conn.execute(
            "INSERT INTO notifications (user_id, message) VALUES (?, 'Your account has been approved by the administrator.')",
            (user_id,)
        )
        
    conn.commit()
    conn.close()
    flash("Staff account registration approved.", "success")
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/reject-staff/<int:user_id>', methods=['POST'])
@verify_user_access_role(['Admin'])
def admin_reject_staff(user_id):
    """Rejects and removes a pending staff profile."""
    conn = create_db_session()
    conn.execute("DELETE FROM users WHERE id = ? AND role IN ('Staff', 'Guide')", (user_id,))
    conn.commit()
    conn.close()
    flash("Staff guide request rejected and profile deleted.", "success")
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/treks', methods=['GET', 'POST'])
@verify_user_access_role(['Admin'])
def admin_treks():
    """Allows adding, listing, and filtering of treks."""
    conn = create_db_session()

    edit_id = request.args.get('edit', type=int)
    edit_trek = None
    if edit_id:
        edit_trek = conn.execute("SELECT * FROM treks WHERE id = ?", (edit_id,)).fetchone()

    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        location = request.form.get('location', '').strip()
        difficulty = request.form.get('difficulty')
        duration = request.form.get('duration', type=int)
        total_slots = request.form.get('total_slots', type=int)
        start_date = request.form.get('start_date')
        end_date = request.form.get('end_date')
        description = request.form.get('description', '').strip()

        if not (name and location and difficulty and duration and total_slots and start_date and end_date):
            flash("All parameters are required to create a trek.", "error")
        else:
            conn.execute(
                """INSERT INTO treks (name, location, difficulty, duration, total_slots, available_slots, status, start_date, end_date, description)
                   VALUES (?, ?, ?, ?, ?, ?, 'Approved', ?, ?, ?)""",
                (name, location, difficulty, duration, total_slots, total_slots, start_date, end_date, description)
            )
            conn.commit()
            flash("New trek trail created successfully.", "success")
            return redirect(url_for('admin_treks'))

    search_query = request.args.get('search', '').strip()
    if search_query:
        if search_query.isdigit():
            treks_list = conn.execute("SELECT * FROM treks WHERE id = ?", (int(search_query),)).fetchall()
        else:
            treks_list = conn.execute(
                "SELECT * FROM treks WHERE name LIKE ? OR location LIKE ?",
                (f"%{search_query}%", f"%{search_query}%")
            ).fetchall()
    else:
        treks_list = conn.execute("SELECT * FROM treks ORDER BY id DESC").fetchall()

    conn.close()
    return render_template('admin_treks.html', treks=treks_list, edit_trek=edit_trek, search_query=search_query)

@app.route('/admin/edit-trek/<int:trek_id>', methods=['POST'])
@verify_user_access_role(['Admin'])
def admin_edit_trek(trek_id):
    """Updates trek trail parameters and automatically marks bookings completed if status completed."""
    conn = create_db_session()
    trek = conn.execute("SELECT * FROM treks WHERE id = ?", (trek_id,)).fetchone()
    if not trek:
        conn.close()
        flash("Trek not found.", "error")
        return redirect(url_for('admin_treks'))

    name = request.form.get('name', '').strip()
    location = request.form.get('location', '').strip()
    difficulty = request.form.get('difficulty')
    duration = request.form.get('duration', type=int)
    total_slots = request.form.get('total_slots', type=int)
    start_date = request.form.get('start_date')
    end_date = request.form.get('end_date')
    description = request.form.get('description', '').strip()
    status = request.form.get('status')

    occupied_slots = conn.execute(
        """SELECT COUNT(*) FROM booking_participants bp
           JOIN bookings b ON bp.booking_id = b.id
           WHERE b.trek_id = ? AND b.status = 'Booked'""",
        (trek_id,)
    ).fetchone()[0]

    new_avail = total_slots - occupied_slots
    if new_avail < 0:
        flash(f"Cannot reduce capacity to {total_slots}. {occupied_slots} slots are already booked.", "error")
        conn.close()
        return redirect(url_for('admin_treks', edit=trek_id))

    if status == 'Open' and new_avail == 0:
        status = 'Closed'
        flash("Trek has no available slots. Status automatically adjusted to Closed.", "info")

    conn.execute(
        """UPDATE treks
           SET name=?, location=?, difficulty=?, duration=?, total_slots=?, available_slots=?, start_date=?, end_date=?, description=?, status=?
           WHERE id=?""",
        (name, location, difficulty, duration, total_slots, new_avail, start_date, end_date, description, status, trek_id)
    )

    if status == 'Completed':
        conn.execute("UPDATE bookings SET status = 'Completed' WHERE trek_id = ? AND status = 'Booked'", (trek_id,))

    conn.commit()
    conn.close()
    flash("Trek details updated successfully.", "success")
    return redirect(url_for('admin_treks'))

@app.route('/admin/delete-trek/<int:trek_id>', methods=['POST'])
@verify_user_access_role(['Admin'])
def admin_delete_trek(trek_id):
    """Deletes a trek and cascades to remove its bookings."""
    conn = create_db_session()
    conn.execute("DELETE FROM treks WHERE id = ?", (trek_id,))
    conn.commit()
    conn.close()
    flash("Trek and all associated bookings removed.", "success")
    return redirect(url_for('admin_treks'))

@app.route('/admin/staff', methods=['GET', 'POST'])
@verify_user_access_role(['Admin'])
def admin_staff():
    """Manages staff directories and assignments."""
    conn = create_db_session()
    search_query = request.args.get('search', '').strip()

    if search_query:
        if search_query.isdigit():
            staff_list = conn.execute(
                """SELECT u.id as user_id, u.username, u.status, sp.name, sp.contact_details, sp.age, sp.gender, sp.experience, sp.emergency_contact
                   FROM users u
                   JOIN staff_profiles sp ON u.id = sp.user_id
                   WHERE u.role IN ('Staff', 'Guide') AND u.status != 'Blacklisted' AND u.id = ?""", (int(search_query),)
            ).fetchall()
        else:
            staff_list = conn.execute(
                """SELECT u.id as user_id, u.username, u.status, sp.name, sp.contact_details, sp.age, sp.gender, sp.experience, sp.emergency_contact
                   FROM users u
                   JOIN staff_profiles sp ON u.id = sp.user_id
                   WHERE u.role IN ('Staff', 'Guide') AND u.status != 'Blacklisted' AND (sp.name LIKE ? OR u.username LIKE ?)""",
                (f"%{search_query}%", f"%{search_query}%")
            ).fetchall()
    else:
        staff_list = conn.execute(
            """SELECT u.id as user_id, u.username, u.status, sp.name, sp.contact_details, sp.age, sp.gender, sp.experience, sp.emergency_contact
               FROM users u
               JOIN staff_profiles sp ON u.id = sp.user_id
               WHERE u.role IN ('Staff', 'Guide') AND u.status != 'Blacklisted'"""
        ).fetchall()

    active_guides = conn.execute(
        """SELECT u.id as user_id, sp.name, u.username
           FROM users u
           JOIN staff_profiles sp ON u.id = sp.user_id
           WHERE u.role IN ('Staff', 'Guide') AND u.status='Approved'"""
    ).fetchall()

    treks = conn.execute(
        """SELECT t.*, sp.name as guide_name
           FROM treks t
           LEFT JOIN staff_profiles sp ON t.assigned_staff_id = sp.user_id
           ORDER BY t.id DESC"""
    ).fetchall()

    conn.close()
    return render_template('admin_staff.html', staff_list=staff_list, active_guides=active_guides, treks=treks, search_query=search_query)

@app.route('/admin/assign-staff', methods=['POST'])
@verify_user_access_role(['Admin'])
def admin_assign_staff():
    """Assigns staff guide to a trek trail."""
    trek_id = request.form.get('trek_id', type=int)
    staff_id = request.form.get('staff_id', type=int)

    if not trek_id or not staff_id:
        flash("Select both a trek and a staff guide.", "error")
        return redirect(url_for('admin_staff'))

    conn = create_db_session()
    guide = conn.execute("SELECT id FROM users WHERE id = ? AND role IN ('Staff', 'Guide') AND status = 'Approved'", (staff_id,)).fetchone()
    if not guide:
        conn.close()
        flash("Selected guide is invalid or inactive.", "error")
        return redirect(url_for('admin_staff'))

    conn.execute("UPDATE treks SET assigned_staff_id = ? WHERE id = ?", (staff_id, trek_id))
    conn.commit()
    conn.close()
    flash("Staff guide assigned to trek successfully.", "success")
    return redirect(url_for('admin_staff'))

@app.route('/admin/toggle-blacklist-staff/<int:user_id>', methods=['POST'])
@verify_user_access_role(['Admin'])
def admin_toggle_blacklist_staff(user_id):
    """Toggles blacklist/activation status of staff guides."""
    conn = create_db_session()
    user = conn.execute("SELECT status FROM users WHERE id = ? AND role IN ('Staff', 'Guide')", (user_id,)).fetchone()
    if user:
        new_status = 'Blacklisted' if user['status'] == 'Approved' else 'Approved'
        conn.execute("UPDATE users SET status = ? WHERE id = ?", (new_status, user_id))
        conn.commit()
        flash(f"Staff account status updated to {new_status}.", "success")
    conn.close()
    
    referrer = request.referrer or ''
    if 'admin/blacklist' in referrer:
        return redirect(url_for('admin_blacklist'))
    return redirect(url_for('admin_staff'))

@app.route('/admin/delete-staff/<int:user_id>', methods=['POST'])
@verify_user_access_role(['Admin'])
def admin_delete_staff(user_id):
    """Deletes a staff user permanently."""
    conn = create_db_session()
    conn.execute("DELETE FROM users WHERE id = ? AND role IN ('Staff', 'Guide')", (user_id,))
    conn.commit()
    conn.close()
    flash("Staff guide deleted permanently.", "success")
    return redirect(url_for('admin_staff'))

@app.route('/admin/blacklist')
@verify_user_access_role(['Admin'])
def admin_blacklist():
    """Displays separate lists of blacklisted trekkers and blacklisted staff guides, allowing unblacklisting."""
    conn = create_db_session()
    
    blacklisted_trekkers = conn.execute(
        "SELECT * FROM users WHERE role = 'Trekker' AND status = 'Blacklisted' ORDER BY id DESC"
    ).fetchall()
    
    blacklisted_staff = conn.execute(
        """SELECT u.id as user_id, u.username, u.status, sp.name, sp.contact_details, sp.age, sp.gender, sp.experience, sp.emergency_contact
           FROM users u
           JOIN staff_profiles sp ON u.id = sp.user_id
           WHERE u.role IN ('Staff', 'Guide') AND u.status = 'Blacklisted' ORDER BY u.id DESC"""
    ).fetchall()
    
    conn.close()
    return render_template(
        'admin_blacklist.html',
        trekkers=blacklisted_trekkers,
        staff=blacklisted_staff
    )

@app.route('/admin/users')
@verify_user_access_role(['Admin'])
def admin_users():
    """Allows administrators to search, view, and blacklist trekkers."""
    conn = create_db_session()
    search_query = request.args.get('search', '').strip()

    if search_query:
        if search_query.isdigit():
            users_list = conn.execute("SELECT * FROM users WHERE role='Trekker' AND status != 'Blacklisted' AND id = ?", (int(search_query),)).fetchall()
        else:
            users_list = conn.execute("SELECT * FROM users WHERE role='Trekker' AND status != 'Blacklisted' AND username LIKE ?", (f"%{search_query}%",)).fetchall()
    else:
        users_list = conn.execute("SELECT * FROM users WHERE role='Trekker' AND status != 'Blacklisted' ORDER BY id DESC").fetchall()

    conn.close()
    return render_template('admin_users.html', users=users_list, search_query=search_query)

@app.route('/admin/toggle-blacklist-user/<int:user_id>', methods=['POST'])
@verify_user_access_role(['Admin'])
def admin_toggle_blacklist_user(user_id):
    """Toggles blacklist/activation status of trekker users."""
    conn = create_db_session()
    user = conn.execute("SELECT status FROM users WHERE id = ? AND role = 'Trekker'", (user_id,)).fetchone()
    if user:
        new_status = 'Blacklisted' if user['status'] == 'Approved' else 'Approved'
        conn.execute("UPDATE users SET status = ? WHERE id = ?", (new_status, user_id))
        conn.commit()
        flash(f"Trekker status updated to {new_status}.", "success")
    conn.close()
    
    referrer = request.referrer or ''
    if 'admin/blacklist' in referrer:
        return redirect(url_for('admin_blacklist'))
    return redirect(url_for('admin_users'))

@app.route('/admin/delete-user/<int:user_id>', methods=['POST'])
@verify_user_access_role(['Admin'])
def admin_delete_user(user_id):
    """Removes a trekker user permanently."""
    conn = create_db_session()
    conn.execute("DELETE FROM users WHERE id = ? AND role = 'Trekker'", (user_id,))
    conn.commit()
    conn.close()
    flash("Trekker account deleted permanently.", "success")
    return redirect(url_for('admin_users'))

@app.route('/admin/bookings')
@verify_user_access_role(['Admin'])
def admin_bookings():
    """Displays and filters comprehensive booking logs across the system."""
    conn = create_db_session()
    search_query = request.args.get('search', '').strip()

    query = """
        SELECT b.id, b.booking_date, b.status, u.username, t.name as trek_name, t.location, t.start_date, t.status as trek_status,
        (SELECT COUNT(*) FROM booking_participants WHERE booking_id = b.id) as participant_count
        FROM bookings b
        JOIN users u ON b.user_id = u.id
        JOIN treks t ON b.trek_id = t.id
    """

    if search_query:
        if search_query.isdigit():
            bookings_list = conn.execute(query + " WHERE b.id = ?", (int(search_query),)).fetchall()
        else:
            bookings_list = conn.execute(
                query + " WHERE u.username LIKE ? OR t.name LIKE ? OR t.location LIKE ?",
                (f"%{search_query}%", f"%{search_query}%", f"%{search_query}%")
            ).fetchall()
    else:
        bookings_list = conn.execute(query + " ORDER BY b.id DESC").fetchall()

    conn.close()
    return render_template('admin_bookings.html', bookings=bookings_list, search_query=search_query)

@app.route('/staff/dashboard')
@verify_user_access_role(['Staff'])
def staff_dashboard():
    """Loads a dashboard of assigned treks and registered traveler metrics."""
    conn = create_db_session()
    staff_id = session.get('user_id')

    profile = conn.execute("SELECT * FROM staff_profiles WHERE user_id = ?", (staff_id,)).fetchone()

    assigned_treks = conn.execute(
        """SELECT t.*, 
           (SELECT COUNT(*) FROM booking_participants bp 
             JOIN bookings b ON bp.booking_id = b.id 
             WHERE b.trek_id = t.id AND b.status IN ('Booked', 'Completed')) as participant_count
            FROM treks t
            WHERE t.assigned_staff_id = ?
            ORDER BY t.id DESC""",
        (staff_id,)
    ).fetchall()

    conn.close()
    return render_template('staff_dashboard.html', profile=profile, treks=assigned_treks)

@app.route('/staff/trek/<int:trek_id>')
@verify_user_access_role(['Staff'])
def staff_trek_detail(trek_id):
    """Shows participant rosters and enables trek parameter editing for the assigned guide."""
    conn = create_db_session()
    staff_id = session.get('user_id')

    trek = conn.execute("SELECT * FROM treks WHERE id = ? AND assigned_staff_id = ?", (trek_id, staff_id)).fetchone()
    if not trek:
        conn.close()
        abort(403)

    participants = conn.execute(
        """SELECT bp.name, bp.details, bp.address, bp.phone_no, bp.age, bp.country, b.booking_date, b.status as booking_status, u.username as booked_by
           FROM booking_participants bp
           JOIN bookings b ON bp.booking_id = b.id
           JOIN users u ON b.user_id = u.id
           WHERE b.trek_id = ? AND b.status IN ('Booked', 'Completed')""",
        (trek_id,)
    ).fetchall()

    conn.close()
    return render_template('staff_trek_detail.html', trek=trek, participants=participants)

@app.route('/staff/update-trek/<int:trek_id>', methods=['POST'])
@verify_user_access_role(['Staff'])
def staff_update_trek(trek_id):
    """Updates slots and status (Open, Closed, Completed, Approved, Started) from the staff panel."""
    conn = create_db_session()
    staff_id = session.get('user_id')

    trek = conn.execute("SELECT * FROM treks WHERE id = ? AND assigned_staff_id = ?", (trek_id, staff_id)).fetchone()
    if not trek:
        conn.close()
        abort(403)

    avail_slots = request.form.get('available_slots', type=int)
    status = request.form.get('status')

    if avail_slots is None or not status:
        flash("All settings are required.", "error")
        conn.close()
        return redirect(url_for('staff_trek_detail', trek_id=trek_id))

    occupied_slots = conn.execute(
        """SELECT COUNT(*) FROM booking_participants bp
           JOIN bookings b ON bp.booking_id = b.id
           WHERE b.trek_id = ? AND b.status = 'Booked'""",
        (trek_id,)
    ).fetchone()[0]

    max_possible_avail = trek['total_slots'] - occupied_slots

    if avail_slots > max_possible_avail:
        flash(f"Available slots cannot exceed remaining capacity ({max_possible_avail} available out of {trek['total_slots']}).", "error")
        conn.close()
        return redirect(url_for('staff_trek_detail', trek_id=trek_id))

    if avail_slots < 0:
        flash("Available slots cannot be negative.", "error")
        conn.close()
        return redirect(url_for('staff_trek_detail', trek_id=trek_id))

    if status == 'Open' and avail_slots == 0:
        status = 'Closed'
        flash("Available slots are 0. Trek set to Closed status.", "info")

    conn.execute(
        "UPDATE treks SET available_slots = ?, status = ? WHERE id = ?",
        (avail_slots, status, trek_id)
    )

    if status == 'Completed':
        conn.execute("UPDATE bookings SET status = 'Completed' WHERE trek_id = ? AND status = 'Booked'", (trek_id,))

    conn.commit()
    conn.close()

    flash("Trek details successfully updated.", "success")
    return redirect(url_for('staff_trek_detail', trek_id=trek_id))

@app.route('/trekker/dashboard')
@verify_user_access_role(['Trekker'])
def trekker_dashboard():
    """Allows trekkers to search, filter, and view open treks."""
    conn = create_db_session()
    user_id = session.get('user_id')

    search_query = request.args.get('search', '').strip()
    diff_filter = request.args.get('difficulty', '').strip()

    query = """
        SELECT t.*,
          (SELECT COUNT(*) FROM bookings b WHERE b.trek_id = t.id AND b.user_id = ? AND b.status = 'Booked') as user_has_booked,
          (SELECT sp.name FROM staff_profiles sp WHERE sp.user_id = t.assigned_staff_id) as guide_name
        FROM treks t
        WHERE t.status IN ('Open', 'Closed')
    """
    params = [user_id]

    if search_query:
        query += " AND (t.name LIKE ? OR t.location LIKE ?)"
        params.extend([f"%{search_query}%", f"%{search_query}%"])

    if diff_filter:
        query += " AND t.difficulty = ?"
        params.append(diff_filter)

    query += " ORDER BY t.id DESC"
    treks_list = conn.execute(query, params).fetchall()
    conn.close()

    return render_template(
        'trekker_dashboard.html',
        treks=treks_list,
        search_query=search_query,
        difficulty_filter=diff_filter
    )

@app.route('/trekker/book/<int:trek_id>', methods=['GET', 'POST'])
@verify_user_access_role(['Trekker'])
def trekker_book(trek_id):
    """Step 1 of Multi-person booking: Choosing the number of slots and booking type."""
    user_id = session.get('user_id')
    conn = create_db_session()

    trek = conn.execute("SELECT * FROM treks WHERE id = ?", (trek_id,)).fetchone()
    if not trek or trek['status'] != 'Open' or trek['available_slots'] <= 0:
        conn.close()
        flash("Booking Closed", "error")
        return redirect(url_for('trekker_dashboard'))

    existing_booking = conn.execute(
        "SELECT id FROM bookings WHERE user_id = ? AND trek_id = ? AND status = 'Booked'",
        (user_id, trek_id)
    ).fetchone()

    if existing_booking:
        conn.close()
        flash("You already have an active booking for this trek.", "error")
        return redirect(url_for('trekker_bookings'))

    if request.method == 'POST':
        booking_type = request.form.get('booking_type', 'self')
        slots_count = request.form.get('slots_count', type=int)

        if not slots_count or slots_count < 1 or slots_count > trek['available_slots']:
            flash(f"Please select a slot count between 1 and {trek['available_slots']}.", "error")
            conn.close()
            return render_template('book_slots.html', trek=trek)

        conn.close()
        return redirect(url_for('trekker_book_details', trek_id=trek_id, slots=slots_count, booking_type=booking_type))

    conn.close()
    return render_template('book_slots.html', trek=trek)

@app.route('/trekker/book/<int:trek_id>/details', methods=['GET', 'POST'])
@verify_user_access_role(['Trekker'])
def trekker_book_details(trek_id):
    """Step 2 of Multi-person booking: Filling in information for each slot."""
    user_id = session.get('user_id')
    slots = request.args.get('slots', type=int)
    booking_type = request.args.get('booking_type', 'self')

    if not slots or slots < 1:
        flash("Invalid booking request.", "error")
        return redirect(url_for('trekker_dashboard'))

    conn = create_db_session()
    trek = conn.execute("SELECT * FROM treks WHERE id = ?", (trek_id,)).fetchone()

    if not trek or trek['status'] != 'Open' or trek['available_slots'] <= 0:
        conn.close()
        flash("Booking Closed", "error")
        return redirect(url_for('trekker_dashboard'))

    if trek['available_slots'] < slots:
        conn.close()
        flash("The requested slots are not available.", "error")
        return redirect(url_for('trekker_dashboard'))

    existing = conn.execute(
        "SELECT id FROM bookings WHERE user_id = ? AND trek_id = ? AND status = 'Booked'",
        (user_id, trek_id)
    ).fetchone()
    if existing:
        conn.close()
        flash("You already have an active booking for this trek.", "error")
        return redirect(url_for('trekker_bookings'))

    if request.method == 'POST':
        participants_data = []
        for i in range(slots):
            name = request.form.get(f'name_{i}', '').strip()
            phone = request.form.get(f'phone_{i}', '').strip()
            age = request.form.get(f'age_{i}', type=int)
            country = request.form.get(f'country_{i}', '').strip()
            addr = request.form.get(f'address_{i}', '').strip()
            desc = request.form.get(f'details_{i}', '').strip()

            if not name or not phone or not age or not country or not addr:
                flash(f"Please fill in Name, Phone, Age, Country, and Address for Participant #{i+1}.", "error")
                user_profile = None
                if booking_type == 'self':
                    user_profile = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
                conn.close()
                return render_template('book_details.html', trek=trek, slots=slots, booking_type=booking_type, user_profile=user_profile)

            participants_data.append((name, desc, addr, phone, age, country))

        try:
            cursor = conn.cursor()
            
            cursor.execute(
                "UPDATE treks SET available_slots = available_slots - ? WHERE id = ? AND available_slots >= ? AND status = 'Open'",
                (slots, trek_id, slots)
            )

            if cursor.rowcount == 0:
                conn.rollback()
                flash("Booking failed. The slots were taken or status changed. Please try again.", "error")
                conn.close()
                return redirect(url_for('trekker_dashboard'))

            prev_booking = cursor.execute(
                "SELECT id, status FROM bookings WHERE user_id = ? AND trek_id = ?",
                (user_id, trek_id)
            ).fetchone()

            if prev_booking:
                booking_id = prev_booking['id']
                cursor.execute(
                    "UPDATE bookings SET status = 'Booked', booking_date = CURRENT_TIMESTAMP WHERE id = ?",
                    (booking_id,)
                )
                cursor.execute("DELETE FROM booking_participants WHERE booking_id = ?", (booking_id,))
            else:
                cursor.execute(
                    "INSERT INTO bookings (user_id, trek_id, status) VALUES (?, ?, 'Booked')",
                    (user_id, trek_id)
                )
                booking_id = cursor.lastrowid

            for p_name, p_desc, p_addr, p_phone, p_age, p_country in participants_data:
                cursor.execute(
                    "INSERT INTO booking_participants (booking_id, name, details, address, phone_no, age, country) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (booking_id, p_name, p_desc, p_addr, p_phone, p_age, p_country)
                )

            updated_trek = cursor.execute("SELECT available_slots FROM treks WHERE id = ?", (trek_id,)).fetchone()
            if updated_trek['available_slots'] == 0:
                cursor.execute("UPDATE treks SET status = 'Closed' WHERE id = ?", (trek_id,))

            conn.commit()
            flash(f"Successfully booked {slots} slots! Prepare for your adventure.", "success")
            return redirect(url_for('trekker_bookings'))

        except Exception:
            conn.rollback()
            flash("An error occurred during booking. Please try again.", "error")
        finally:
            conn.close()

    user_profile = None
    if booking_type == 'self':
        user_profile = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    return render_template('book_details.html', trek=trek, slots=slots, booking_type=booking_type, user_profile=user_profile)

@app.route('/trekker/cancel-booking/<int:booking_id>', methods=['POST'])
@verify_user_access_role(['Trekker'])
def trekker_cancel_booking(booking_id):
    """Cancels a booking, increments slots, and re-opens the trek if it was closed."""
    user_id = session.get('user_id')
    conn = create_db_session()

    booking = conn.execute(
        "SELECT * FROM bookings WHERE id = ? AND user_id = ? AND status = 'Booked'",
        (booking_id, user_id)
    ).fetchone()

    if not booking:
        conn.close()
        flash("Active booking reservation not found.", "error")
        return redirect(url_for('trekker_bookings'))

    canceled_slots = conn.execute(
        "SELECT COUNT(*) FROM booking_participants WHERE booking_id = ?",
        (booking_id,)
    ).fetchone()[0]

    try:
        cursor = conn.cursor()
        cursor.execute("UPDATE bookings SET status = 'Cancelled' WHERE id = ?", (booking_id,))

        cursor.execute(
            "UPDATE treks SET available_slots = available_slots + ? WHERE id = ?",
            (canceled_slots, booking['trek_id'])
        )

        cursor.execute(
            "UPDATE treks SET status = 'Open' WHERE id = ? AND status = 'Closed' AND available_slots > 0",
            (booking['trek_id'],)
        )

        conn.commit()
        flash("Your booking reservation has been cancelled.", "success")
    except Exception:
        conn.rollback()
        flash("Failed to cancel booking. Please try again.", "error")
    finally:
        conn.close()

    return redirect(url_for('trekker_bookings'))

@app.route('/trekker/bookings')
@verify_user_access_role(['Trekker'])
def trekker_bookings():
    """Lists current and completed adventures for the logged-in trekker."""
    conn = create_db_session()
    user_id = session.get('user_id')

    bookings_list = conn.execute(
        """SELECT b.id, b.status, b.booking_date, t.name as trek_name, t.location, t.start_date, t.end_date, t.status as trek_status,
           (SELECT COUNT(*) FROM booking_participants WHERE booking_id = b.id) as participant_count
           FROM bookings b
           JOIN treks t ON b.trek_id = t.id
           WHERE b.user_id = ?
           ORDER BY b.id DESC""",
        (user_id,)
    ).fetchall()

    conn.close()

    active_list = []
    history_list = []

    for b in bookings_list:
        if b['status'] == 'Booked' and b['trek_status'] != 'Completed':
            active_list.append(b)
        else:
            history_list.append(b)

    return render_template('trekker_bookings.html', active_bookings=active_list, history_bookings=history_list)

@app.route('/trekker/profile', methods=['GET', 'POST'])
@verify_user_access_role(['Trekker'])
def trekker_profile():
    """Allows profile modifications for trekkers."""
    user_id = session.get('user_id')
    conn = create_db_session()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip()
        phone = request.form.get('phone', '').strip()
        location = request.form.get('location', '').strip()
        
        age_val = request.form.get('age', '').strip()
        age = int(age_val) if age_val and age_val.isdigit() else None
        gender = request.form.get('gender', '').strip()
        emergency_contact = request.form.get('emergency_contact', '').strip()
        medical_issues = request.form.get('medical_issues', '').strip()

        if not username or not name or not email or not phone or not location:
            flash("All profile fields are required.", "error")
            conn.close()
            return render_template('trekker_profile.html', user=user)

        if username != user['username']:
            existing = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
            if existing:
                flash("Username is already taken.", "error")
                conn.close()
                return render_template('trekker_profile.html', user=user)

        try:
            conn.execute(
                "UPDATE users SET username = ?, name = ?, email = ?, phone = ?, location = ?, age = ?, gender = ?, emergency_contact = ?, medical_issues = ? WHERE id = ?",
                (username, name, email, phone, location, age, gender, emergency_contact, medical_issues, user_id)
            )
            conn.commit()
            session['username'] = username
            flash("Profile updated successfully.", "success")
            return redirect(url_for('trekker_profile'))
        except Exception:
            flash("Failed to update profile.", "error")
        finally:
            conn.close()
    else:
        conn.close()
    return render_template('trekker_profile.html', user=user)

@app.route('/trekker/change-password', methods=['POST'])
@verify_user_access_role(['Trekker'])
def trekker_change_password():
    """Allows trekkers to change their password separately."""
    user_id = session.get('user_id')
    current_pw = request.form.get('current_password', '')
    new_pw = request.form.get('new_password', '')
    confirm_new_pw = request.form.get('confirm_new_password', '')

    if not current_pw or not new_pw or not confirm_new_pw:
        flash("All password fields are required to change password.", "error")
        return redirect(url_for('trekker_profile'))

    conn = create_db_session()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()

    if not check_password_hash(user['password_hash'], current_pw):
        flash("Incorrect current password.", "error")
        conn.close()
        return redirect(url_for('trekker_profile'))

    if new_pw != confirm_new_pw:
        flash("New passwords do not match.", "error")
        conn.close()
        return redirect(url_for('trekker_profile'))

    try:
        hashed_pw = generate_password_hash(new_pw)
        conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", (hashed_pw, user_id))
        conn.commit()
        flash("Password updated successfully.", "success")
    except Exception:
        flash("Failed to update password. Please try again.", "error")
    finally:
        conn.close()

    return redirect(url_for('trekker_profile'))

@app.route('/staff/profile', methods=['GET', 'POST'])
@verify_user_access_role(['Staff'])
def staff_profile():
    """Allows profile modifications for staff members."""
    user_id = session.get('user_id')
    conn = create_db_session()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    profile = conn.execute("SELECT * FROM staff_profiles WHERE user_id = ?", (user_id,)).fetchone()

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip()
        phone = request.form.get('phone', '').strip()
        location = request.form.get('location', '').strip()
        
        age_val = request.form.get('age', '').strip()
        age = int(age_val) if age_val and age_val.isdigit() else None
        gender = request.form.get('gender', '').strip()
        experience = request.form.get('experience', '').strip()
        emergency_contact = request.form.get('emergency_contact', '').strip()

        if not username or not name or not email or not phone or not location:
            flash("All profile fields are required.", "error")
            conn.close()
            return render_template('staff_profile.html', user=user, profile=profile)

        if username != user['username']:
            existing = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
            if existing:
                flash("Username is already taken.", "error")
                conn.close()
                return render_template('staff_profile.html', user=user, profile=profile)

        try:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE users SET username = ?, name = ?, email = ?, phone = ?, location = ? WHERE id = ?",
                (username, name, email, phone, location, user_id)
            )
            cursor.execute(
                "UPDATE staff_profiles SET name = ?, contact_details = ?, age = ?, gender = ?, experience = ?, emergency_contact = ? WHERE user_id = ?",
                (name, f"Email: {email}, Phone: {phone}, Location: {location}", age, gender, experience, emergency_contact, user_id)
            )
            conn.commit()
            session['username'] = username
            flash("Profile updated successfully.", "success")
            return redirect(url_for('staff_profile'))
        except Exception:
            conn.rollback()
            flash("Failed to update profile.", "error")
        finally:
            conn.close()
    else:
        conn.close()
    return render_template('staff_profile.html', user=user, profile=profile)

@app.route('/staff/change-password', methods=['POST'])
@verify_user_access_role(['Staff'])
def staff_change_password():
    """Allows staff members to change their password separately."""
    user_id = session.get('user_id')
    current_pw = request.form.get('current_password', '')
    new_pw = request.form.get('new_password', '')
    confirm_new_pw = request.form.get('confirm_new_password', '')

    if not current_pw or not new_pw or not confirm_new_pw:
        flash("All password fields are required to change password.", "error")
        return redirect(url_for('staff_profile'))

    conn = create_db_session()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()

    if not check_password_hash(user['password_hash'], current_pw):
        flash("Incorrect current password.", "error")
        conn.close()
        return redirect(url_for('staff_profile'))

    if new_pw != confirm_new_pw:
        flash("New passwords do not match.", "error")
        conn.close()
        return redirect(url_for('staff_profile'))

    try:
        hashed_pw = generate_password_hash(new_pw)
        conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", (hashed_pw, user_id))
        conn.commit()
        flash("Password updated successfully.", "success")
    except Exception:
        flash("Failed to update password. Please try again.", "error")
    finally:
        conn.close()

    return redirect(url_for('staff_profile'))

def api_admin_required(func):
    """Secures administrative API resources."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        if 'user_id' not in session or session.get('role') != 'Admin':
            return jsonify({"error": "Access denied: Administrative privileges required."}), 401
        return func(*args, **kwargs)
    return wrapper

@app.route('/api/treks', methods=['GET', 'POST'])
@api_admin_required
def api_treks():
    """API endpoint to list or create treks (Admin only)."""
    conn = create_db_session()
    if request.method == 'GET':
        treks = conn.execute("SELECT * FROM treks").fetchall()
        conn.close()
        return jsonify([dict(t) for t in treks])

    elif request.method == 'POST':
        data = request.json or {}
        required = ['name', 'location', 'difficulty', 'duration', 'total_slots', 'start_date', 'end_date']
        if not all(k in data for k in required):
            conn.close()
            return jsonify({"error": "Missing parameters"}), 400

        try:
            cursor = conn.cursor()
            cursor.execute(
                """INSERT INTO treks (name, location, difficulty, duration, total_slots, available_slots, status, start_date, end_date, description)
                   VALUES (?, ?, ?, ?, ?, ?, 'Approved', ?, ?, ?)""",
                (data['name'], data['location'], data['difficulty'], data['duration'], data['total_slots'], data['total_slots'], data['start_date'], data['end_date'], data.get('description', ''))
            )
            conn.commit()
            new_id = cursor.lastrowid
            conn.close()
            return jsonify({"status": "Trek created", "id": new_id}), 201
        except Exception:
            conn.close()
            return jsonify({"error": "Failed to create trek"}), 500

@app.route('/api/treks/<int:trek_id>', methods=['GET', 'PUT', 'DELETE'])
@api_admin_required
def api_single_trek(trek_id):
    """API endpoint to view, edit or delete a trek (Admin only)."""
    conn = create_db_session()
    trek = conn.execute("SELECT * FROM treks WHERE id = ?", (trek_id,)).fetchone()
    if not trek:
        conn.close()
        return jsonify({"error": "Trek not found"}), 404

    if request.method == 'GET':
        conn.close()
        return jsonify(dict(trek))

    elif request.method == 'PUT':
        data = request.json or {}
        name = data.get('name', trek['name'])
        location = data.get('location', trek['location'])
        difficulty = data.get('difficulty', trek['difficulty'])
        duration = data.get('duration', trek['duration'])
        total_slots = data.get('total_slots', trek['total_slots'])
        start_date = data.get('start_date', trek['start_date'])
        end_date = data.get('end_date', trek['end_date'])
        description = data.get('description', trek['description'])
        status = data.get('status', trek['status'])

        occupied_slots = conn.execute(
            """SELECT COUNT(*) FROM booking_participants bp
               JOIN bookings b ON bp.booking_id = b.id
               WHERE b.trek_id = ? AND b.status = 'Booked'""",
            (trek_id,)
        ).fetchone()[0]

        new_avail = total_slots - occupied_slots
        if new_avail < 0:
            conn.close()
            return jsonify({"error": "Cannot reduce total slots below currently booked slots"}), 400

        conn.execute(
            """UPDATE treks SET name=?, location=?, difficulty=?, duration=?, total_slots=?, available_slots=?, start_date=?, end_date=?, description=?, status=?
               WHERE id=?""",
            (name, location, difficulty, duration, total_slots, new_avail, start_date, end_date, description, status, trek_id)
        )
        conn.commit()
        conn.close()
        return jsonify({"status": "Trek updated"})

    elif request.method == 'DELETE':
        conn.execute("DELETE FROM treks WHERE id = ?", (trek_id,))
        conn.commit()
        conn.close()
        return jsonify({"status": "Trek deleted"})

@app.route('/api/users', methods=['GET'])
@api_admin_required
def api_users():
    """API endpoint to view user directories (Admin only)."""
    conn = create_db_session()
    users = conn.execute("SELECT id, username, role, status, created_at FROM users").fetchall()
    conn.close()
    return jsonify([dict(u) for u in users])

@app.route('/api/bookings', methods=['GET'])
@api_admin_required
def api_bookings():
    """API endpoint to view system bookings (Admin only)."""
    conn = create_db_session()
    bookings = conn.execute("SELECT * FROM bookings").fetchall()
    conn.close()
    return jsonify([dict(b) for b in bookings])

# ==============================================================================
# GUIDE & STAFF APPROVAL WORKFLOW ROUTES
# ==============================================================================

@app.route('/pending-dashboard')
@verify_user_logged_in
def pending_dashboard():
    """Renders the wait screen or dashboard with progress tracking for unapproved staff/guides."""
    user_id = session.get('user_id')
    user_role = session.get('role')
    if user_role not in ['Staff', 'Guide']:
        return redirect(url_for('dashboard'))

    conn = create_db_session()
    user = conn.execute("SELECT status, name, role, email FROM users WHERE id = ?", (user_id,)).fetchone()
    
    # If already approved, direct them to standard dashboard
    if user['status'] == 'Approved':
        conn.close()
        return redirect(url_for('dashboard'))

    # Fetch admin notes / feedback if status is Changes Requested
    latest_request = conn.execute(
        "SELECT admin_comment FROM approval_requests WHERE user_id = ? ORDER BY id DESC LIMIT 1",
        (user_id,)
    ).fetchone()
    
    admin_comment = latest_request['admin_comment'] if latest_request else None
    
    # Fetch notifications
    notifs = conn.execute("SELECT * FROM notifications WHERE user_id = ? ORDER BY id DESC LIMIT 5", (user_id,)).fetchall()
    
    # Mark notifications as read
    conn.execute("UPDATE notifications SET is_read = 1 WHERE user_id = ?", (user_id,))
    conn.commit()
    conn.close()

    return render_template(
        'pending_dashboard.html',
        user=user,
        admin_comment=admin_comment,
        notifications=notifs
    )


@app.route('/verification-form', methods=['GET', 'POST'])
@verify_user_logged_in
def verification_form():
    """Handles the multi-section professional verification profile form submission."""
    user_id = session.get('user_id')
    user_role = session.get('role')
    if user_role not in ['Staff', 'Guide']:
        return redirect(url_for('dashboard'))

    conn = create_db_session()
    user_data = conn.execute("SELECT status, name, email, role FROM users WHERE id = ?", (user_id,)).fetchone()

    # Block access if already approved or currently under review
    if user_data['status'] in ['Approved', 'Under Review']:
        conn.close()
        flash("Your profile is already submitted or approved.", "info")
        return redirect(url_for('pending_dashboard'))

    # prefill form fields if Guide/Staff has previously submitted
    profile = conn.execute("SELECT * FROM guide_profiles WHERE user_id = ?", (user_id,)).fetchone()
    
    # Fetch uploaded documents
    docs = conn.execute("SELECT * FROM documents WHERE user_id = ?", (user_id,)).fetchall()
    existing_docs = {doc['document_type']: doc for doc in docs}

    if request.method == 'POST':
        MAX_FILE_SIZE = 5 * 1024 * 1024 # 5MB

        phone = request.form.get('phone', '').strip()
        dob = request.form.get('dob', '').strip()
        gender = request.form.get('gender', '').strip()
        
        address = request.form.get('address', '').strip()
        city = request.form.get('city', '').strip()
        state = request.form.get('state', '').strip()
        pin_code = request.form.get('pin_code', '').strip()
        country = request.form.get('country', '').strip()

        emergency_name = request.form.get('emergency_contact_name', '').strip()
        emergency_relation = request.form.get('emergency_contact_relation', '').strip()
        emergency_phone = request.form.get('emergency_contact_phone', '').strip()

        experience = request.form.get('experience', type=int) or 0
        organization = request.form.get('organization', '').strip()
        specialization = request.form.get('specialization', '').strip()

        skills_list = request.form.getlist('skills')
        skills_str = ",".join(skills_list)

        languages_list = request.form.getlist('languages')
        languages_str = ",".join(languages_list)

        availability_list = request.form.getlist('availability')
        availability_str = ",".join(availability_list)

        about_me = request.form.get('about_me', '').strip()
        declaration = request.form.get('declaration')
        
        # Validation checks
        if not phone or not dob or not gender or not address or not city or not state or not pin_code or not country or not emergency_name or not emergency_phone or not declaration:
            conn.close()
            flash("Please fill in all mandatory text fields and check the Declaration box.", "error")
            return redirect(url_for('verification_form'))

        # Document upload mappings
        file_fields = [
            ('profile_photo', 'profile_photo', not existing_docs.get('profile_photo')),
            ('id_proof', 'id_proof', not existing_docs.get('id_proof')),
            ('cert_first_aid', 'cert_first_aid', False),
            ('cert_mountaineering', 'cert_mountaineering', False),
            ('cert_adventure', 'cert_adventure', False),
            ('cert_rescue', 'cert_rescue', False),
            ('cert_other', 'cert_other', False),
            ('resume', 'resume', not existing_docs.get('resume')),
            ('medical_fitness', 'medical_fitness', not existing_docs.get('medical_fitness')),
            ('police_verification', 'police_verification', False),
            ('experience_cert', 'experience_cert', False)
        ]

        uploaded_files_data = []

        # Validate file uploads before saving
        for field_name, doc_type, required in file_fields:
            file = request.files.get(field_name)
            if file and file.filename:
                # Check size limit
                file.seek(0, os.SEEK_END)
                size = file.tell()
                file.seek(0)
                if size > MAX_FILE_SIZE:
                    conn.close()
                    flash(f"File size error: '{field_name}' exceeds the 5MB file size limit.", "error")
                    return redirect(url_for('verification_form'))
                
                # Check extension
                ext = os.path.splitext(file.filename)[1].lower()
                if ext not in ['.jpg', '.jpeg', '.png', '.pdf', '.docx', '.doc']:
                    conn.close()
                    flash(f"Invalid file type for {field_name}. Upload JPG, PNG, PDF or DOCX only.", "error")
                    return redirect(url_for('verification_form'))
                
                uploaded_files_data.append((file, doc_type))
            elif required:
                conn.close()
                flash(f"Required document '{field_name}' is missing.", "error")
                return redirect(url_for('verification_form'))

        try:
            cursor = conn.cursor()
            
            # 1. Update users table with basic info
            cursor.execute(
                "UPDATE users SET phone = ?, gender = ?, age = ?, emergency_contact = ? WHERE id = ?",
                (phone, gender, datetime.now().year - int(dob.split('-')[0]) if dob else None, emergency_phone, user_id)
            )

            # 2. Insert or replace guide_profile data
            cursor.execute(
                """INSERT OR REPLACE INTO guide_profiles 
                   (user_id, phone, dob, gender, address, city, state, pin_code, country,
                    emergency_contact_name, emergency_contact_relation, emergency_contact_phone,
                    role, experience, organization, specialization, skills, languages, availability, about_me, approved_viewed)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)""",
                (user_id, phone, dob, gender, address, city, state, pin_code, country,
                 emergency_name, emergency_relation, emergency_phone,
                 user_data['role'], experience, organization, specialization, skills_str, languages_str, availability_str, about_me)
            )

            # 3. Save files and insert to documents table
            for file, doc_type in uploaded_files_data:
                ext = os.path.splitext(file.filename)[1].lower()
                filename = f"user_{user_id}_{doc_type}{ext}"
                safe_name = secure_filename(filename)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], safe_name)
                file.save(filepath)

                # Insert or update documents
                existing_doc = cursor.execute("SELECT id FROM documents WHERE user_id = ? AND document_type = ?", (user_id, doc_type)).fetchone()
                if existing_doc:
                    cursor.execute(
                        "UPDATE documents SET file_url = ?, verification_status = 'Pending' WHERE id = ?",
                        (safe_name, existing_doc['id'])
                    )
                else:
                    cursor.execute(
                        "INSERT INTO documents (user_id, document_type, file_url, verification_status) VALUES (?, ?, ?, 'Pending')",
                        (user_id, doc_type, safe_name)
                    )

            # 4. Update status in users to 'Under Review'
            cursor.execute("UPDATE users SET status = 'Under Review' WHERE id = ?", (user_id,))
            
            # 5. Insert approval history request record
            cursor.execute(
                "INSERT INTO approval_requests (user_id, status, admin_comment) VALUES (?, 'Under Review', 'Verification profile submitted by user')",
                (user_id,)
            )

            # 6. Notify Administrators
            admin = cursor.execute("SELECT id FROM users WHERE role = 'Admin' LIMIT 1").fetchone()
            if admin:
                cursor.execute(
                    "INSERT INTO notifications (user_id, message) VALUES (?, ?)",
                    (admin['id'], f"New Verification profile submitted by {user_data['name']} (@{session.get('username')})")
                )

            conn.commit()

            # Mock Email
            send_email_notification(
                user_data['email'],
                "TrekManagement Profile Under Review",
                f"Hello {user_data['name']},\n\nYour guide/staff verification profile has been submitted successfully and is now Under Review. "
                "The administrator will review your credentials shortly.\n\nEstimated review time: 24-48 hours."
            )

            flash("Verification Submitted Successfully! Your profile is now under review.", "success")
            conn.close()
            return redirect(url_for('pending_dashboard'))

        except Exception as e:
            conn.rollback()
            conn.close()
            flash("Database update failed. Please verify your entries.", "error")
            return redirect(url_for('verification_form'))

    conn.close()
    return render_template(
        'verification_form.html',
        user=user_data,
        profile=profile,
        existing_docs=existing_docs
    )


@app.route('/serve-document/<int:document_id>')
@verify_user_logged_in
def serve_document(document_id):
    """Safely serves uploaded files to authenticated users and administrators."""
    conn = create_db_session()
    doc = conn.execute("SELECT * FROM documents WHERE id = ?", (document_id,)).fetchone()
    conn.close()

    if not doc:
        abort(404)

    # Security check: Admin can access any document. Otherwise, users can only access their own.
    if session.get('role') != 'Admin' and doc['user_id'] != session.get('user_id'):
        abort(403)

    return send_from_directory(app.config['UPLOAD_FOLDER'], doc['file_url'])


@app.route('/approval-success')
@verify_user_logged_in
def approval_success():
    """Renders the congratulations screen upon first login of an approved user."""
    user_id = session.get('user_id')
    user_role = session.get('role')
    if user_role not in ['Staff', 'Guide']:
        return redirect(url_for('dashboard'))

    conn = create_db_session()
    user = conn.execute("SELECT status FROM users WHERE id = ?", (user_id,)).fetchone()
    
    if not user or user['status'] != 'Approved':
        conn.close()
        return redirect(url_for('pending_dashboard'))

    # Mark as viewed in guide_profiles
    cursor = conn.cursor()
    cursor.execute("UPDATE guide_profiles SET approved_viewed = 1 WHERE user_id = ?", (user_id,))
    conn.commit()
    conn.close()

    # Clear session flag
    session.pop('show_approval_success', None)

    return render_template('approval_success.html')


# ==============================================================================
# ADMINISTRATOR VERIFICATION MANAGEMENT ROUTES
# ==============================================================================

@app.route('/admin/verifications')
@verify_user_access_role(['Admin'])
def admin_verifications():
    """Renders the Dedicated Guide & Staff Verification directory dashboard."""
    conn = create_db_session()
    
    # Get filters
    search_query = request.args.get('search', '').strip()
    status_filter = request.args.get('status', '').strip()
    role_filter = request.args.get('role', '').strip()

    # Fetch users requiring verification (role Staff or Guide)
    query = """
        SELECT u.id as user_id, u.name, u.username, u.role, u.status, u.created_at,
               gp.experience,
               (SELECT file_url FROM documents WHERE user_id = u.id AND document_type = 'profile_photo') as photo_url,
               (SELECT id FROM documents WHERE user_id = u.id AND document_type = 'profile_photo') as photo_id,
               (SELECT MAX(reviewed_at) FROM approval_requests WHERE user_id = u.id) as submitted_date
        FROM users u
        LEFT JOIN guide_profiles gp ON u.id = gp.user_id
        WHERE u.role IN ('Staff', 'Guide')
    """
    params = []

    if search_query:
        query += " AND (u.name LIKE ? OR u.username LIKE ?)"
        params.extend([f"%{search_query}%", f"%{search_query}%"])
    
    if status_filter:
        query += " AND u.status = ?"
        params.append(status_filter)
    else:
        # Default: show unapproved first, or all except Approved
        query += " AND u.status != 'Approved'"

    if role_filter:
        query += " AND u.role = ?"
        params.append(role_filter)

    query += " ORDER BY u.id DESC"
    requests_list = conn.execute(query, params).fetchall()

    # Fetch history of approval actions
    history_query = """
        SELECT ar.*, u.name, u.username, u.role,
               admin.username as admin_name
        FROM approval_requests ar
        JOIN users u ON ar.user_id = u.id
        LEFT JOIN users admin ON ar.reviewed_by = admin.id
        ORDER BY ar.id DESC LIMIT 30
    """
    history_list = conn.execute(history_query).fetchall()
    
    conn.close()

    return render_template(
        'admin_verifications.html',
        requests=requests_list,
        history=history_list,
        search_query=search_query,
        status_filter=status_filter,
        role_filter=role_filter
    )


@app.route('/admin/verifications/review/<int:user_id>')
@verify_user_access_role(['Admin'])
def admin_review_profile(user_id):
    """Loads a full, 12-section profile review panel for the administrator."""
    conn = create_db_session()
    
    # Fetch base user details
    user = conn.execute("SELECT * FROM users WHERE id = ? AND role IN ('Staff', 'Guide')", (user_id,)).fetchone()
    if not user:
        conn.close()
        abort(404)

    # Fetch guide profiles detailed fields
    profile = conn.execute("SELECT * FROM guide_profiles WHERE user_id = ?", (user_id,)).fetchone()
    
    # Fetch documents with their id and types
    docs = conn.execute("SELECT * FROM documents WHERE user_id = ?", (user_id,)).fetchall()
    
    # Fetch audit log requests
    logs = conn.execute(
        """SELECT ar.*, admin.username as admin_name 
           FROM approval_requests ar 
           LEFT JOIN users admin ON ar.reviewed_by = admin.id
           WHERE ar.user_id = ? ORDER BY ar.id DESC""", (user_id,)
    ).fetchall()

    conn.close()

    # Turn documents list into a dictionary
    documents_dict = {d['document_type']: d for d in docs}

    return render_template(
        'admin_review.html',
        candidate=user,
        profile=profile,
        documents=documents_dict,
        history_logs=logs
    )


@app.route('/admin/verifications/action/<int:user_id>', methods=['POST'])
@verify_user_access_role(['Admin'])
def admin_verification_action(user_id):
    """Executes the administrator's review action: Approve, Reject, or Request Changes."""
    action = request.form.get('action')
    feedback = request.form.get('feedback', '').strip()
    admin_id = session.get('user_id')

    if action not in ['approve', 'reject', 'request_changes']:
        flash("Invalid verification action specified.", "error")
        return redirect(url_for('admin_verifications'))

    conn = create_db_session()
    user = conn.execute("SELECT * FROM users WHERE id = ? AND role IN ('Staff', 'Guide')", (user_id,)).fetchone()
    if not user:
        conn.close()
        abort(404)

    try:
        cursor = conn.cursor()
        if action == 'approve':
            cursor.execute("UPDATE users SET status = 'Approved' WHERE id = ?", (user_id,))
            cursor.execute(
                "INSERT INTO approval_requests (user_id, status, admin_comment, reviewed_by, reviewed_at) VALUES (?, 'Approved', ?, ?, CURRENT_TIMESTAMP)",
                (user_id, feedback or "Account approved by administrator.", admin_id)
            )

            # Synchronize guide_profiles to staff_profiles
            profile = cursor.execute("SELECT * FROM guide_profiles WHERE user_id = ?", (user_id,)).fetchone()
            if profile:
                age = None
                if profile['dob']:
                    try:
                        age = datetime.now().year - int(profile['dob'].split('-')[0])
                    except Exception:
                        pass
                
                exp_text = f"Experience: {profile['experience']} years. Specialization: {profile['specialization']}. Skills: {profile['skills']}. Bio: {profile['about_me']}"
                contact_details = f"Email: {user['email']}, Phone: {profile['phone']}, Location: {profile['city']}, {profile['state']}"
                
                cursor.execute(
                    """INSERT OR REPLACE INTO staff_profiles 
                       (user_id, name, contact_details, age, gender, experience, emergency_contact)
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (user_id, user['name'], contact_details, age, profile['gender'], exp_text, profile['emergency_contact_phone'])
                )
            
            cursor.execute(
                "INSERT INTO notifications (user_id, message) VALUES (?, 'Congratulations! Your verification profile has been approved. You now have access to TrekManagement.')",
                (user_id,)
            )

            conn.commit()

            # Mock Email
            send_email_notification(
                user['email'],
                "TrekManagement - Account Approved!",
                f"Dear {user['name']},\n\nCongratulations! Your application has been approved by the administrator. "
                "You now have full access to the Trek Management Dashboard.\n\nLog in now."
            )

            flash(f"Candidate {user['name']} has been approved.", "success")

        elif action == 'request_changes':
            if not feedback:
                conn.close()
                flash("Feedback details are required when requesting changes.", "error")
                return redirect(url_for('admin_review_profile', user_id=user_id))

            cursor.execute("UPDATE users SET status = 'Changes Requested' WHERE id = ?", (user_id,))
            cursor.execute(
                "INSERT INTO approval_requests (user_id, status, admin_comment, reviewed_by, reviewed_at) VALUES (?, 'Changes Requested', ?, ?, CURRENT_TIMESTAMP)",
                (user_id, feedback, admin_id)
            )
            cursor.execute(
                "INSERT INTO notifications (user_id, message) VALUES (?, ?)",
                (user_id, f"Admin requested changes to your profile. Feedback: '{feedback}'")
            )

            conn.commit()

            # Mock Email
            send_email_notification(
                user['email'],
                "TrekManagement - Action Required: Changes Requested",
                f"Hello {user['name']},\n\nDuring the verification review, the administrator requested changes to your profile. "
                f"Please log in to address the following feedback:\n\n\"{feedback}\"\n\nResubmit the form at your earliest convenience."
            )

            flash(f"Feedback submitted. Account status set to Changes Requested.", "info")

        elif action == 'reject':
            cursor.execute("UPDATE users SET status = 'Rejected' WHERE id = ?", (user_id,))
            cursor.execute(
                "INSERT INTO approval_requests (user_id, status, admin_comment, reviewed_by, reviewed_at) VALUES (?, 'Rejected', ?, ?, CURRENT_TIMESTAMP)",
                (user_id, feedback or "Account rejected during screening.", admin_id)
            )
            cursor.execute(
                "INSERT INTO notifications (user_id, message) VALUES (?, ?)",
                (user_id, f"Your verification has been rejected. Details: '{feedback or 'No comment'}'")
            )

            conn.commit()

            # Mock Email
            send_email_notification(
                user['email'],
                "TrekManagement - Application Status Update",
                f"Hello {user['name']},\n\nWe regret to inform you that your guide/staff verification profile has been rejected. "
                f"Details: {feedback or 'No comment provided.'}"
            )

            flash(f"Application for {user['name']} has been rejected.", "error")

    except Exception as e:
        conn.rollback()
        flash("An error occurred while updating status.", "error")
    finally:
        conn.close()

    return redirect(url_for('admin_verifications'))

@app.errorhandler(403)
def forbidden(e):
    return render_template('base.html'), 403

@app.errorhandler(404)
def not_found(e):
    return render_template('base.html'), 404

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=True)