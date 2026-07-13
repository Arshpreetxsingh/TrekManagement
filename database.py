import sqlite3
import os
from werkzeug.security import generate_password_hash

DB_FILE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'trekking.db')

def create_db_session():
    """Establishes and returns a connection to the SQLite database with row factory active."""
    connection = sqlite3.connect(DB_FILE_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON;")
    return connection

def prepare_database():
    """Initializes database tables and seeds initial administrative and demo data."""
    connection = create_db_session()
    db_cursor = connection.cursor()

    # Core Users Table
    db_cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'Approved',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            name TEXT,
            email TEXT,
            phone TEXT,
            location TEXT,
            age INTEGER,
            gender TEXT,
            emergency_contact TEXT,
            medical_issues TEXT
        );
    ''')

    # Migration check: Ensure new columns exist in users for existing databases
    db_cursor.execute("PRAGMA table_info(users)")
    existing_user_columns = [row['name'] for row in db_cursor.fetchall()]
    for col_name, col_type in [('age', 'INTEGER'), ('gender', 'TEXT'), ('emergency_contact', 'TEXT'), ('medical_issues', 'TEXT')]:
        if col_name not in existing_user_columns:
            db_cursor.execute(f"ALTER TABLE users ADD COLUMN {col_name} {col_type};")
            print(f"[DB] Added column {col_name} to users.")

    # Detailed Staff Profiles
    db_cursor.execute('''
        CREATE TABLE IF NOT EXISTS staff_profiles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER UNIQUE NOT NULL,
            name TEXT NOT NULL,
            contact_details TEXT,
            age INTEGER,
            gender TEXT,
            experience TEXT,
            emergency_contact TEXT,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        );
    ''')

    # Detailed Guide & Staff Profiles (Approval Workflow)
    db_cursor.execute('''
        CREATE TABLE IF NOT EXISTS guide_profiles (
            user_id INTEGER PRIMARY KEY,
            phone TEXT,
            dob TEXT,
            gender TEXT,
            address TEXT,
            city TEXT,
            state TEXT,
            pin_code TEXT,
            country TEXT,
            emergency_contact_name TEXT,
            emergency_contact_relation TEXT,
            emergency_contact_phone TEXT,
            role TEXT,
            experience INTEGER,
            organization TEXT,
            specialization TEXT,
            skills TEXT,
            languages TEXT,
            availability TEXT,
            about_me TEXT,
            approved_viewed INTEGER DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        );
    ''')

    # Documents Uploaded Table
    db_cursor.execute('''
        CREATE TABLE IF NOT EXISTS documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            document_type TEXT NOT NULL,
            file_url TEXT NOT NULL,
            verification_status TEXT NOT NULL DEFAULT 'Pending',
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        );
    ''')

    # Approval Requests History Table
    db_cursor.execute('''
        CREATE TABLE IF NOT EXISTS approval_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            status TEXT NOT NULL,
            admin_comment TEXT,
            reviewed_by INTEGER,
            reviewed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
            FOREIGN KEY (reviewed_by) REFERENCES users (id)
        );
    ''')

    # Notifications Table
    db_cursor.execute('''
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            message TEXT NOT NULL,
            is_read INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        );
    ''')

    # Migration check: Ensure new columns exist in staff_profiles for existing databases
    db_cursor.execute("PRAGMA table_info(staff_profiles)")
    existing_columns = [row['name'] for row in db_cursor.fetchall()]
    for col_name, col_type in [('age', 'INTEGER'), ('gender', 'TEXT'), ('experience', 'TEXT'), ('emergency_contact', 'TEXT')]:
        if col_name not in existing_columns:
            db_cursor.execute(f"ALTER TABLE staff_profiles ADD COLUMN {col_name} {col_type};")
            print(f"[DB] Added column {col_name} to staff_profiles.")

    # Trek Trails Table
    db_cursor.execute('''
        CREATE TABLE IF NOT EXISTS treks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            location TEXT NOT NULL,
            difficulty TEXT NOT NULL,
            duration INTEGER NOT NULL,
            total_slots INTEGER NOT NULL,
            available_slots INTEGER NOT NULL,
            assigned_staff_id INTEGER,
            status TEXT NOT NULL DEFAULT 'Pending',
            start_date DATE NOT NULL,
            end_date DATE NOT NULL,
            description TEXT,
            FOREIGN KEY (assigned_staff_id) REFERENCES users (id) ON DELETE SET NULL
        );
    ''')

    # Bookings Table
    db_cursor.execute('''
        CREATE TABLE IF NOT EXISTS bookings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            trek_id INTEGER NOT NULL,
            booking_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            status TEXT NOT NULL DEFAULT 'Booked',
            UNIQUE(user_id, trek_id),
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
            FOREIGN KEY (trek_id) REFERENCES treks (id) ON DELETE CASCADE
        );
    ''')

    # Booking Participants (Companion / detailed names)
    db_cursor.execute('''
        CREATE TABLE IF NOT EXISTS booking_participants (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            booking_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            details TEXT,
            address TEXT,
            phone_no TEXT,
            age INTEGER,
            country TEXT,
            FOREIGN KEY (booking_id) REFERENCES bookings (id) ON DELETE CASCADE
        );
    ''')

    connection.commit()

    # Seed Admin User if not exists
    db_cursor.execute("SELECT id FROM users WHERE username = 'admin'")
    if not db_cursor.fetchone():
        hashed_admin_pwd = generate_password_hash('admin123')
        db_cursor.execute(
            "INSERT INTO users (username, password_hash, role, status, name, email, phone, location) VALUES (?, ?, 'Admin', 'Approved', 'Platform Admin', 'admin@trekking.com', '+91-98765-43210', 'Office 1, Chandigarh')",
            ('admin', hashed_admin_pwd)
        )
        connection.commit()
        print("[DB] Admin seed user created.")

    # Seed Demo Data if treks are empty
    db_cursor.execute("SELECT COUNT(*) FROM treks")
    if db_cursor.fetchone()[0] == 0:
        # 1. Seed 5 Staff Guides (guide1 to guide5)
        staff_ids = []
        base_camps = [
            "Manali, Himachal Pradesh",
            "Dharamshala, Himachal Pradesh",
            "Rishikesh, Uttarakhand",
            "Joshimath, Uttarakhand",
            "Munnar, Kerala"
        ]
        guide_ages = [28, 35, 41, 33, 29]
        guide_genders = ["Male", "Female", "Male", "Female", "Non-Binary"]
        guide_exps = [
            "Licensed mountaineer with 6+ years of wilderness guiding experience in Kullu valley.",
            "Certified Wilderness First Responder with 10+ years of high-altitude rescue experience.",
            "Professional local naturalist guide specializing in Himalayan flora and bird watching.",
            "High-altitude guide with 8+ years leading climbs in Garhwal Himalayas.",
            "Certified rescue expert with 5+ years of trekking guidance in Western Ghats."
        ]
        for i in range(1, 6):
            uname = f"guide{i}"
            hashed_pwd = generate_password_hash(uname)
            name = f"Guide Officer {i}"
            email = f"guide{i}@gmail.com"
            phone = f"+91 98765 4320{i}"
            loc = base_camps[i-1]
            
            # Insert into users
            db_cursor.execute(
                "INSERT INTO users (username, password_hash, role, status, name, email, phone, location) VALUES (?, ?, 'Staff', 'Approved', ?, ?, ?, ?)",
                (uname, hashed_pwd, name, email, phone, loc)
            )
            staff_user_id = db_cursor.lastrowid
            staff_ids.append(staff_user_id)
            
            # Insert into staff_profiles for backward compatibility
            age = guide_ages[i-1]
            gender = guide_genders[i-1]
            exp = guide_exps[i-1]
            emergency = f"+91 91111 2222{i}"
            db_cursor.execute(
                "INSERT INTO staff_profiles (user_id, name, contact_details, age, gender, experience, emergency_contact) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (staff_user_id, name, f"Email: {email}, Phone: {phone}, Location: {loc}", age, gender, exp, emergency)
            )
            db_cursor.execute(
                """INSERT OR IGNORE INTO guide_profiles (user_id, phone, dob, gender, address, city, state, pin_code, country,
                                              emergency_contact_name, emergency_contact_relation, emergency_contact_phone,
                                              role, experience, organization, specialization, skills, languages, availability, about_me)
                   VALUES (?, ?, '1990-01-01', ?, ?, ?, ?, '123456', 'India',
                           'Emergency Contact', 'Family', ?,
                           'Staff', ?, 'TrekManagement Org', 'Mountain Guiding',
                           'Camping,Trekking,First Aid', 'English,Hindi', 'Weekdays,Weekends', ?)""",
                (staff_user_id, phone, gender, loc, loc, loc, emergency, age, exp)
            )

        # 2. Seed 40 Trekkers (trekker1 to trekker40)
        trekker_ids = []
        indian_cities = [
            "Delhi, NCR", "Mumbai, Maharashtra", "Bangalore, Karnataka", "Pune, Maharashtra", 
            "Kolkata, West Bengal", "Chennai, Tamil Nadu", "Hyderabad, Telangana", 
            "Jaipur, Rajasthan", "Chandigarh, Punjab", "Ahmedabad, Gujarat"
        ]
        medical_issues_list = [
            "None", "Asthma (uses inhaler)", "Mild dust allergy", "None", 
            "Knee sensitivity on descents", "None", "Hypertension", "None", 
            "Penicillin allergy", "None"
        ]
        trekker_genders = ["Male", "Female", "Non-Binary"]
        for i in range(1, 41):
            uname = f"trekker{i}"
            hashed_pwd = generate_password_hash(uname)
            name = f"Adventurer Traveler {i}"
            email = f"trekker{i}@gmail.com"
            phone = f"+91 98761 123{i:02d}"
            loc = indian_cities[i % len(indian_cities)]
            age = 18 + (i * 7) % 35
            gender = trekker_genders[i % len(trekker_genders)]
            emergency = f"+91 99999 888{i:02d}"
            med_issues = medical_issues_list[i % len(medical_issues_list)]
            
            db_cursor.execute(
                "INSERT INTO users (username, password_hash, role, status, name, email, phone, location, age, gender, emergency_contact, medical_issues) VALUES (?, ?, 'Trekker', 'Approved', ?, ?, ?, ?, ?, ?, ?, ?)",
                (uname, hashed_pwd, name, email, phone, loc, age, gender, emergency, med_issues)
            )
            trekker_ids.append(db_cursor.lastrowid)

        # 3. Seed 10 Trek Trails with various locations, guides, and status profiles
        treks_data = [
            ("Hampta Pass Trek", "Manali, Himachal Pradesh", "Moderate", 5, 15, staff_ids[0]),
            ("Valley of Flowers", "Chamoli, Uttarakhand", "Easy", 6, 12, staff_ids[1]),
            ("Kedarkantha Summit", "Uttarkashi, Uttarakhand", "Moderate", 6, 15, staff_ids[2]),
            ("Roopkund Lake Trail", "Chamoli, Uttarakhand", "Hard", 8, 10, staff_ids[3]),
            ("Triund Hill Trail", "Dharamshala, Himachal Pradesh", "Easy", 2, 25, staff_ids[4]),
            ("Goechala Trek", "Yuksom, Sikkim", "Hard", 10, 8, staff_ids[0]),
            ("Sandakphu Ridge Trek", "Darjeeling, West Bengal", "Moderate", 6, 12, staff_ids[1]),
            ("Markha Valley Trek", "Leh, Ladakh", "Hard", 9, 10, staff_ids[2]),
            ("Kumara Parvatha Trek", "Coorg, Karnataka", "Moderate", 2, 20, staff_ids[3]),
            ("Chembra Peak Trail", "Wayanad, Kerala", "Easy", 1, 30, staff_ids[4])
        ]

        # Insert treks and bookings to create realistic available slot counts
        for idx, (t_name, t_loc, t_diff, t_dur, t_slots, t_guide) in enumerate(treks_data, 1):
            avail = t_slots
            status = 'Open'
            
            if idx in [3, 6]:
                avail = 0
                status = 'Closed'
            elif idx == 8:
                avail = 1
                status = 'Open'
            elif idx == 4:
                avail = 2
                status = 'Open'
            
            db_cursor.execute(
                """INSERT INTO treks (name, location, difficulty, duration, total_slots, available_slots, assigned_staff_id, status, start_date, end_date, description)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (t_name, t_loc, t_diff, t_dur, t_slots, avail, t_guide, status, f"2026-09-{10+idx:02d}", f"2026-09-{10+idx+t_dur:02d}", f"A premium trekking adventure on the historical {t_name}.")
            )
            trek_id = db_cursor.lastrowid
            
            booked_slots = t_slots - avail
            if booked_slots > 0:
                tk_user_id = trekker_ids[idx % len(trekker_ids)]
                db_cursor.execute(
                    "INSERT INTO bookings (user_id, trek_id, status) VALUES (?, ?, 'Booked')",
                    (tk_user_id, trek_id)
                )
                booking_id = db_cursor.lastrowid
                
                for p_idx in range(1, booked_slots + 1):
                    db_cursor.execute(
                        "INSERT INTO booking_participants (booking_id, name, details, address, phone_no, age, country) VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (booking_id, f"Companion {p_idx} of User {tk_user_id}", f"Details {p_idx}", indian_cities[tk_user_id % len(indian_cities)], f"+91 99999 123{p_idx}", 20 + p_idx, "India")
                    )


        connection.commit()
        print("[DB] 10 treks, 5 staffs, 40 trekkers and default bookings seeded successfully.")

    connection.close()

if __name__ == '__main__':
    prepare_database()
    print("Database initialization script run completed.")