from flask import Flask, render_template, redirect, url_for, request, session, jsonify,flash,make_response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
from datetime import datetime, timedelta,timezone, UTC
from urllib.parse import quote
from apscheduler.schedulers.background import BackgroundScheduler
from itsdangerous import URLSafeTimedSerializer
from sqlalchemy.sql import func, and_
from functools import wraps
from werkzeug.utils import secure_filename
import random
import os
import requests
import pandas as pd
import csv
import qrcode
from io import BytesIO
from base64 import b64encode
from pytz import timezone 
import atexit
from cryptography.fernet import Fernet
import time
app = Flask(__name__)
UPLOAD_FOLDER = 'static/uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

ALLOWED_EXTENSIONS = {'csv'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

app.secret_key = "Shannu"
serializer = URLSafeTimedSerializer(app.secret_key)
# app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)  # Session lasts 1 hour
# Make session permanent
password = "@Ppk200404k"
escaped_password = quote(password)
# Mail Configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv("EMAIL")  # Update with your email
app.config['MAIL_PASSWORD'] = os.getenv("EMAIL_APP_PASSWORD") # Update with your app password

mail = Mail(app)

# Database Configuration
# app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql://postgres:@Ppk200404k@localhost:5432/users"
# app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
# app.config["SQLALCHEMY_BINDS"] = {
#     "new_db": "postgresql://postgres:@Ppk200404k@localhost:5432/faculty_db",  # PostgreSQL for faculty
#     "perm_db": "postgresql://postgres:@Ppk200404k@localhost:5432/permissions_db"  
# }

app.config["SQLALCHEMY_DATABASE_URI"] = f"postgresql://postgres:{escaped_password}@192.168.0.104:5000/users"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_BINDS"] = {
    "new_db": f"postgresql://postgres:{escaped_password}@192.168.0.104:5000/faculty_db",  # PostgreSQL for faculty
    "perm_db": f"postgresql://postgres:{escaped_password}@192.168.0.104:5000/permissions_db"   # PostgreSQL for permissions
}

db = SQLAlchemy(app)

app.config['ADMIN_USERNAME'] = os.getenv('ADMIN_USERNAME')
app.config['ADMIN_PASSWORD'] = os.getenv('ADMIN_PASSWORD')

app.config['ENCRYPTION_KEY'] = Fernet.generate_key()
cipher_suite = Fernet(app.config['ENCRYPTION_KEY'])

# User table model
class User(db.Model):
    regd = db.Column(db.String(80), primary_key=True, nullable=False)  # Username & Password
    first_name = db.Column(db.String(80), nullable=False)
    last_name = db.Column(db.String(80), nullable=True)
    gender = db.Column(db.String(10), nullable=True, default='not prefer to say')
    email = db.Column(db.String(120), unique=True, nullable=False)
    dept = db.Column(db.String(10), nullable=False)
    student_phone = db.Column(db.String(10), nullable=False)
    parent_phone = db.Column(db.String(10), nullable=False)  # New field
    address = db.Column(db.String(150), nullable=False)
    password = db.Column(db.String(256), nullable=False)  # Hashed password
    photo = db.Column(db.String(150), nullable=True)  # Photo path
    category = db.Column(db.String(20), nullable=False)
    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)


class Faculty(db.Model):
    __bind_key__ = "new_db"
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(100), unique=True,primary_key=True, nullable=False)
    dept = db.Column(db.String(50), nullable=False)
    faculty_phone = db.Column(db.String(10), unique=True, nullable=False)
    room_no=db.Column(db.String(10), nullable=False)
    category = db.Column(db.String(50), nullable=False)  #HOD, incharge, admin
    password_hash = db.Column(db.String(255), nullable=False)
    photo = db.Column(db.String(255), nullable=True)

class PermissionRequest(db.Model):
    __bind_key__ = "perm_db"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    student_regd = db.Column(db.String(80), nullable=False)
    student_name = db.Column(db.String(100), nullable=False)
    student_email = db.Column(db.String(120), nullable=False)
    dept = db.Column(db.String(10), nullable=False)
    permission_type = db.Column(db.String(10), nullable=False)  # Outing or Leave
    start_time = db.Column(db.String(10), nullable=True)  # For outing
    end_time = db.Column(db.String(10), nullable=True)  # For outing
    start_date = db.Column(db.String(10), nullable=True)  # For leave
    end_date = db.Column(db.String(10), nullable=True)  # For leave
    reason = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(10), default='Pending')  # Pending, Approved, Rejected
    hod_status = db.Column(db.String(10), default='Pending')  # Approval from HOD
    incharge_status = db.Column(db.String(10), default='Pending')  # Approval from Incharge
    hod_message = db.Column(db.Text, default='NIL')  # HOD's rejection message
    incharge_message = db.Column(db.Text, default='NIL')  # Incharge's rejection message
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    check_in_time = db.Column(db.DateTime, nullable=True)  # New field for check-in time
    check_out_time = db.Column(db.DateTime, nullable=True)  # New field for check-out time



# def no_cache(f):
#     @wraps(f)
#     def decorated_function(*args, **kwargs):
#         # Call the original route function
#         response = f(*args, **kwargs)
        
#         # Ensure the response is a Flask Response object
#         if not isinstance(response, (tuple, dict)) and not hasattr(response, "headers"):
#             response = make_response(response)
        
#         # Add no-cache headers
#         response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
#         response.headers["Pragma"] = "no-cache"
#         response.headers["Expires"] = "0"
        
#         return response
#     return decorated_function

@app.after_request
def add_no_cache_headers(response):
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


@app.route('/')
def home():
    return render_template('index.html')

def login_required(role=None):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'username' not in session:
                return redirect(url_for('home'))  # Redirect to home if not logged in
            
            if role and session.get('category') != role:
                return redirect(url_for('home'))  # Redirect if role doesn't match
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def no_cache(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        response = f(*args, **kwargs)

        # Convert response to Flask response if needed
        if not isinstance(response, (tuple, dict)) and not hasattr(response, "headers"):
            response = make_response(response)

        # Prevent caching
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"

        return response
    return decorated_function

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    print(f"Attempting login with username: {username}")  # Debug statement

    user = User.query.filter_by(regd=username).first()
    faculty = Faculty.query.filter_by(email=username).first()

    if user:
        print(f"User found: {user.regd}")  # Debug statement
        if not check_password_hash(user.password, password):
            print("Incorrect password")  # Debug statement
            return jsonify({"message": "Incorrect password"}), 400
        
        session['username'] = username
        session['category'] = 'student'
        session.permanent = True 
        return jsonify({"message": "Login successful", "redirect": "/dashboard"}), 200

    elif faculty:
        print(f"Faculty found: {faculty.email}")  # Debug statement
        if not check_password_hash(faculty.password_hash, password):
            print("Incorrect password")  # Debug statement
            return jsonify({"message": "Incorrect password"}), 400

        session['username'] = username
        session['category'] = faculty.category.lower()  # Store faculty category
        session.permanent = True 
        if faculty.category.lower() == "admin":
            return jsonify({"message": "Login successful", "redirect": "/admin_dashboard"}), 200
        if faculty.category.lower() in ['hod','incharge']:
            return jsonify({"message": "Login successful", "redirect": "/faculty_dashboard"}), 200
        if faculty.category.lower() == "security":
            return jsonify({"message": "Login successful", "redirect": "/scan_qr"}), 200
    print("Username does not exist")  # Debug statement
    return jsonify({"message": "Username does not exist"}), 400



@app.route('/dashboard')
# @no_cache
def dashboard():
    if 'username' not in session or session.get('category') != 'student':
        return redirect(url_for('home'))

    user = User.query.filter_by(regd=session['username']).first()
    if not user:
        return redirect(url_for('home'))

    # Fetch all requests made by the student, sorted by timestamp in descending order (latest first)
    all_requests = PermissionRequest.query.filter_by(student_regd=user.regd).order_by(PermissionRequest.timestamp.desc()).all()

    return render_template('student.html', user=user, all_requests=all_requests)


@app.route('/faculty_dashboard')

def faculty_dashboard():
    if 'username' not in session or session.get('category') not in ['hod', 'incharge']:
        return redirect(url_for('home'))

    faculty = Faculty.query.filter_by(email=session['username']).first()
    if not faculty:
        return redirect(url_for('home'))

    # Fetch pending requests based on faculty role
    pending_requests = []
    if faculty.category.lower() == "hod":
        pending_requests = PermissionRequest.query.filter(
            PermissionRequest.dept == faculty.dept,
            PermissionRequest.permission_type == "Leave",
            PermissionRequest.hod_status == "Pending"
        ).all()
    elif faculty.category.lower() == "incharge":
        pending_requests = PermissionRequest.query.filter(
            ((PermissionRequest.permission_type == "Outing") | (PermissionRequest.permission_type == "Leave")) &
            (PermissionRequest.incharge_status == "Pending")
        ).all()
    return render_template('faculty.html', faculty=faculty, leave_requests=pending_requests)

@app.route('/student_dashboard/<regd_no>')
def student_dashboard(regd_no):
    if 'username' not in session or session.get('category') not in ['hod', 'incharge']:
        return redirect(url_for('home'))
    student = User.query.filter_by(regd=regd_no).first()
    if not student:
        return "Student not found", 404
    all_requests = PermissionRequest.query.filter_by(student_regd=student.regd).order_by(PermissionRequest.timestamp.desc()).all()

    return render_template('student.html', user=student, all_requests=all_requests)


# @app.route('/admin_login', methods=['GET', 'POST'])
# def admin_login():
#     if request.method == 'POST':
#         username = request.form.get('username')
#         password = request.form.get('password')

#         if username == app.config['ADMIN_USERNAME'] and password == app.config['ADMIN_PASSWORD']:
#             session['admin_logged_in'] = True
#             return redirect(url_for('admin_dashboard'))
#         else:
#             flash('Invalid credentials', 'error')
#             return redirect(url_for('admin_login'))
#     return render_template('admin_login.html')

# @app.route('/admin_dashboard')
# def admin_dashboard():
#     if not session.get('admin_logged_in'):
#         return redirect(url_for('admin_login'))
#     return render_template('admin_dashboard.html')

@app.route('/admin_dashboard')

@login_required(role='admin')
def admin():
    if 'username' not in session or session.get('category') not in ['admin']:
        return redirect(url_for('home'))

    faculty = Faculty.query.filter_by(email=session['username']).first()
    if not faculty:
        return redirect(url_for('home'))
    return render_template("admin.html")


@app.route('/new_password')
def new_password():
    if 'username' not in session:
        return redirect(url_for('home'))  # Redirect if not logged in
    return render_template('newpassword.html')



@app.route('/send_otp', methods=['POST'])
def send_otp():
    data = request.get_json()
    email = data.get("email")

    # Check if the user exists
    user = User.query.filter_by(email=email).first()
    faculty = Faculty.query.filter_by(email=email).first()

    if not user and not faculty:
        return jsonify({"message": "Email not registered!"}), 400

    # Generate a 6-digit OTP
    otp = str(random.randint(100000, 999999))
    session["otp"] = otp  # Store OTP in session
    session["reset_email"] = email  # Store email
    session["otp_expiry"] = (datetime.utcnow() + timedelta(minutes=2)).strftime("%Y-%m-%d %H:%M:%S")

    # Send OTP via email
    msg = Message("Password Reset OTP", sender="pragadapre143@gmail.com", recipients=[email])
    msg.body = f"Your OTP for password reset is: {otp}. This OTP is valid for 2 minutes."
    mail.send(msg)

    return jsonify({"message": "OTP sent successfully!"}), 200




@app.route('/verify_otp', methods=['POST'])
def verify_otp():
    data = request.get_json()
    entered_otp = data.get("otp")
    new_password = data.get("new_password")

    # Check if OTP exists and is not expired
    otp_expiry = session.get("otp_expiry")
    if not otp_expiry or datetime.utcnow() > datetime.strptime(otp_expiry, "%Y-%m-%d %H:%M:%S"):
        return jsonify({"message": "OTP expired! Request a new one."}), 400

    # Check OTP
    if session.get("otp") != entered_otp:
        return jsonify({"message": "Invalid OTP!"}), 400

    email = session.get("reset_email")

    # Update password
    user = User.query.filter_by(email=email).first()
    faculty = Faculty.query.filter_by(email=email).first()

    if user:
        user.password = generate_password_hash(new_password)
    elif faculty:
        faculty.password_hash = generate_password_hash(new_password)

    db.session.commit()

    # Clear session OTP
    session.pop("otp", None)
    session.pop("reset_email", None)
    session.pop("otp_expiry", None)

    return jsonify({"message": "Password updated successfully!"}), 200

# @app.route('/submit_permission', methods=['POST'])
# def submit_permission():
#     if 'username' not in session or session.get('category') != 'student':
#         return jsonify({"message": "Unauthorized"}), 403

#     data = request.get_json()
#     user = User.query.filter_by(regd=session['username']).first()

#     if not user:
#         return jsonify({"message": "User not found"}), 404

#     try:
#         new_request = PermissionRequest(
#             student_regd=user.regd,
#             student_name=f"{user.first_name} {user.last_name}",
#             student_email=user.email,
#             dept=user.dept,
#             permission_type=data.get('permission_type'),
#             start_time=data.get('start_time'),
#             end_time=data.get('end_time'),
#             start_date=data.get('start_date'),
#             end_date=data.get('end_date'),
#             reason=data.get('reason'),
#             status="Pending",
#             hod_status="NIL" if data.get('permission_type') == "Outing" else "Pending"
#         )
#         today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
#         request_count = PermissionRequest.query.filter(
#         PermissionRequest.student_regd == user.regd,
#         PermissionRequest.timestamp >= today_start
#     ).count()

#         if request_count >= 5:
#              return jsonify({"message": "You have exceeded the maximum of 5 permission requests per day."}), 400

#         db.session.add(new_request)
#         db.session.commit()

#         # Send emails
#         permission_type = data.get('permission_type')

#         if permission_type == "Leave":
#             hod = Faculty.query.filter_by(dept=user.dept, category="HOD").first()
#             incharge = Faculty.query.filter_by(category="Incharge").first()

#             if hod:
#                 token_approve_hod = serializer.dumps({"request_id": new_request.id, "action": "approve", "approver": hod.email}, salt="permission_approval")
#                 token_reject_hod = serializer.dumps({"request_id": new_request.id, "action": "reject", "approver": hod.email}, salt="permission_approval")
#                 approve_link_hod = f"{request.host_url}process_request/{token_approve_hod}"
#                 reject_link_hod = f"{request.host_url}process_request/{token_reject_hod}"

#                 msg = Message("New Leave Request - HOD", sender="pragadaprem143@gmail.com", recipients=[hod.email])
#                 msg.body = f"""
#                 Dear {hod.first_name},

#                 A new leave request has been submitted by {user.first_name} {user.last_name}.

#                 🏫 Department: {user.dept}
#                 📌 Student: {user.first_name} {user.last_name} ({user.regd})
#                 📩 Email: {user.email}
#                 📞 Phone: {user.student_phone}

#                 Start Date: {data.get('start_date') or 'N/A'}
#                 End Date: {data.get('end_date') or 'N/A'}
#                 Reason: {data.get('reason')}

#                 ✅ Approve: {approve_link_hod}
#                 ❌ Reject: {reject_link_hod}
#                 """
#                 mail.send(msg)

#             if incharge:
#                 token_approve_incharge = serializer.dumps({"request_id": new_request.id, "action": "approve", "approver": incharge.email}, salt="permission_approval")
#                 token_reject_incharge = serializer.dumps({"request_id": new_request.id, "action": "reject", "approver": incharge.email}, salt="permission_approval")
#                 approve_link_incharge = f"{request.host_url}process_request/{token_approve_incharge}"
#                 reject_link_incharge = f"{request.host_url}process_request/{token_reject_incharge}"

#                 msg = Message("New Leave Request - Incharge", sender="pragadaprem143@gmail.com", recipients=[incharge.email])
#                 msg.body = f"""
#                 Dear {incharge.first_name},

#                 A new leave request has been submitted by {user.first_name} {user.last_name}.

#                 🏫 Department: {user.dept}
#                 📌 Student: {user.first_name} {user.last_name} ({user.regd})
#                 📩 Email: {user.email}
#                 📞 Phone: {user.student_phone}
#                 Start Date: {data.get('start_date') or 'N/A'}
#                 End Date: {data.get('end_date') or 'N/A'}
#                 Start Time: {data.get('start_time') or 'N/A'}
#                 End Time: {data.get('end_time') or 'N/A'}
#                 Reason: {data.get('reason')}

#                 ✅ Approve: {approve_link_incharge}
#                 ❌ Reject: {reject_link_incharge}
#                 """
#                 mail.send(msg)

#         # **FIX: Add Outing Email Sending Logic**
#         elif permission_type == "Outing":
#             incharge = Faculty.query.filter_by(category="Incharge").first()

#             if incharge:
#                 token_approve = serializer.dumps({"request_id": new_request.id, "action": "approve", "approver": incharge.email}, salt="permission_approval")
#                 token_reject = serializer.dumps({"request_id": new_request.id, "action": "reject", "approver": incharge.email}, salt="permission_approval")
#                 approve_link = f"{request.host_url}process_request/{token_approve}"
#                 reject_link = f"{request.host_url}process_request/{token_reject}"

#                 msg = Message("New Outing Request - Incharge", sender="pragadaprem143@gmail.com", recipients=[incharge.email])
#                 msg.body = f"""
#                 Dear {incharge.first_name},

#                 A new Outing request has been submitted by {user.first_name} {user.last_name}.

#                 📌 Student: {user.first_name} {user.last_name} ({user.regd})
#                 📩 Email: {user.email}
#                 📞 Phone: {user.student_phone}
#                 🏫 Department: {user.dept}
#                 ⏳ Start Time: {data.get('start_time') or 'N/A'}
#                 ⏳ End Time: {data.get('end_time') or 'N/A'}
#                 📜 Reason: {data.get('reason')}

#                 ✅ Approve: {approve_link}
#                 ❌ Reject: {reject_link}
#                 """
#                 mail.send(msg)

#     except Exception as e:
#         db.session.rollback()
#         return jsonify({"message": f"Database error: {str(e)}"}), 500

#     return jsonify({"message": "Permission request submitted successfully!"}), 200

@app.route('/submit_permission', methods=['POST'])
def submit_permission():
    if 'username' not in session or session.get('category') != 'student':
        return jsonify({"message": "Unauthorized"}), 403

    data = request.get_json()
    user = User.query.filter_by(regd=session['username']).first()

    if not user:
        return jsonify({"message": "User not found"}), 404
    permission_type = data.get('permission_type')
    current_month_start = datetime.utcnow().replace(day=1, hour=0, minute=0, second=0, microsecond=0)

    # # Check monthly limits
    # if permission_type == "Leave":
    #     # Check if student has already used their monthly leave allowance
    #     leave_count = PermissionRequest.query.filter(
    #         PermissionRequest.student_regd == user.regd,
    #         PermissionRequest.permission_type == "Leave",
    #         PermissionRequest.status == "Approved",
    #         PermissionRequest.timestamp >= current_month_start
    #     ).count()
    #     if leave_count >= 1:
    #         return jsonify({"message": "You have already used your monthly leave allowance (1 per month)."}), 400

    # elif permission_type == "Outing":
    #     # Check if student has already used their monthly outing allowance
    #     outing_count = PermissionRequest.query.filter(
    #         PermissionRequest.student_regd == user.regd,
    #         PermissionRequest.permission_type == "Outing",
    #         PermissionRequest.status == "Approved",
    #         PermissionRequest.timestamp >= current_month_start
    #     ).count()
    #     if outing_count >= 2:
    #         return jsonify({"message": "You have already used your monthly outing allowance (2 per month)."}), 400


    try:
        # When creating a new PermissionRequest
        new_request = PermissionRequest(
            student_regd=user.regd,
            student_name=f"{user.first_name} {user.last_name}",
            student_email=user.email,
            dept=user.dept,
            permission_type=data.get('permission_type'),
            start_time=data.get('start_time'),
            end_time=data.get('end_time', "23:59:59"),  # Default end_time
            start_date=data.get('start_date'),
            end_date=data.get('end_date', datetime.now().strftime("%Y-%m-%d")),  # Default end_date
            reason=data.get('reason'),
            status="Pending",
            hod_status="NIL" if data.get('permission_type') == "Outing" else "Pending"
        )

    #     today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    #     request_count = PermissionRequest.query.filter(
    #     PermissionRequest.student_regd == user.regd,
    #     PermissionRequest.timestamp >= today_start
    # ).count()

    #     if request_count >= 5:
    #          return jsonify({"message": "You have exceeded the maximum of 5 permission requests per day."}), 400

       
        db.session.add(new_request)
        db.session.commit()

        # Send emails without approve/reject links
        permission_type = data.get('permission_type')

        if permission_type == "Leave":
            hod = Faculty.query.filter_by(dept=user.dept, category="HOD").first()
            incharge = Faculty.query.filter_by(category="Incharge").first()

            if hod:
                msg = Message("New Leave Request - HOD", sender="pragadaprem143@gmail.com", recipients=[hod.email])
                msg.body = f"""
                Dear {hod.first_name},

                A new leave request has been submitted by {user.first_name} {user.last_name}.

                🏫 Department: {user.dept}
                📌 Student: {user.first_name} {user.last_name} ({user.regd})
                📩 Email: {user.email}
                📞 Phone: {user.student_phone}

                Start Date: {data.get('start_date') or 'N/A'}
                End Date: {data.get('end_date') or 'N/A'}
                Reason: {data.get('reason')}

                Please log in to the faculty dashboard to review and take action on this request.

                Best Regards,
                Admin
                """
                mail.send(msg)

            if incharge:
                msg = Message("New Leave Request - Incharge", sender="pragadaprem143@gmail.com", recipients=[incharge.email])
                msg.body = f"""
                Dear {incharge.first_name},

                A new leave request has been submitted by {user.first_name} {user.last_name}.

                🏫 Department: {user.dept}
                📌 Student: {user.first_name} {user.last_name} ({user.regd})
                📩 Email: {user.email}
                📞 Phone: {user.student_phone}
                Start Date: {data.get('start_date') or 'N/A'}
                End Date: {data.get('end_date') or 'N/A'}
                Start Time: {data.get('start_time') or 'N/A'}
                End Time: {data.get('end_time') or 'N/A'}
                Reason: {data.get('reason')}

                Please log in to the faculty dashboard to review and take action on this request.

                Best Regards,
                Admin
                """
                mail.send(msg)

        elif permission_type == "Outing":
            incharge = Faculty.query.filter_by(category="Incharge").first()

            if incharge:
                msg = Message("New Outing Request - Incharge", sender="pragadaprem143@gmail.com", recipients=[incharge.email])
                msg.body = f"""
                Dear {incharge.first_name},

                A new Outing request has been submitted by {user.first_name} {user.last_name}.

                📌 Student: {user.first_name} {user.last_name} ({user.regd})
                📩 Email: {user.email}
                📞 Phone: {user.student_phone}
                🏫 Department: {user.dept}
                ⏳ Start Time: {data.get('start_time') or 'N/A'}
                ⏳ End Time: {data.get('end_time') or 'N/A'}
                📜 Reason: {data.get('reason')}

                Please log in to the faculty dashboard to review and take action on this request.

                Best Regards,
                Admin
                """
                mail.send(msg)

    except Exception as e:
        db.session.rollback()
        return jsonify({"message": f"Database error: {str(e)}"}), 500

    return jsonify({"message": "Permission request submitted successfully!"}), 200


# @app.route('/process_request/<token>', methods=['GET'])
# def process_request(token):
#     try:
#         data = serializer.loads(token, salt="permission_approval", max_age=86400)
#         if "request_id" not in data or "action" not in data or "approver" not in data:
#             return "Invalid token data.", 400

#         request_id = data["request_id"]
#         action = data["action"]
#         approver_email = data["approver"]

#         permission_request = PermissionRequest.query.get(request_id)
#         if not permission_request:
#             return "Request not found.", 404

#         faculty = Faculty.query.filter_by(email=approver_email).first()
#         if not faculty:
#             return "Unauthorized access.", 403

#         if faculty.category.lower() == "incharge":
#             permission_request.incharge_status = "Approved" if action == "approve" else "Rejected"
#         elif faculty.category.lower() == "hod":
#             if permission_request.permission_type != "Outing":
#                 permission_request.hod_status = "Approved" if action == "approve" else "Rejected"

#         if permission_request.permission_type == "Leave":
#             if permission_request.hod_status == "Approved" and permission_request.incharge_status == "Approved":
#                 permission_request.status = "Approved"
#             elif permission_request.hod_status == "Rejected" or permission_request.incharge_status == "Rejected":
#                 permission_request.status = "Rejected"
    
#         elif permission_request.permission_type == "Outing":
#             permission_request.status = "Approved" if permission_request.incharge_status == "Approved" else "Rejected"

#         db.session.commit()

#         # Send email to student
#         email_subject = f"Your {permission_request.permission_type} request has been {permission_request.status}"
#         email_body = f"Dear Student,\n\nYour {permission_request.permission_type} request has been {permission_request.status} by {faculty.category}.\n\nBest Regards,\nAdmin"
#         msg = Message(email_subject, sender="pragadaprem143@gmail.com", recipients=[permission_request.student_email])
#         msg.body = email_body
#         mail.send(msg)

#         # Send SMS to Parent
#         student = User.query.filter_by(regd=permission_request.student_regd).first()
#         if student and student.parent_phone:
#             sms_body = f"Dear Parent, your ward's {permission_request.permission_type} request has been {permission_request.status}."
#             send_sms_fast2sms(student.parent_phone, sms_body)

#         return f"Request {permission_request.status} successfully!", 200

#     except Exception as e:
#         return f"Error processing request: {str(e)}", 500



# @app.route('/process_request', methods=['POST'])
# def process_request_post():
#     try:
#         if 'username' not in session:
#             return jsonify({"success": False, "message": "Unauthorized access"}), 403

#         data = request.get_json()
#         request_id = data.get("request_id")
#         action = data.get("action")
#         role = data.get("role")  # "hod" or "incharge"
#         approver_email = session['username']  # Get logged-in faculty email

#         # Retrieve faculty details
#         faculty = Faculty.query.filter_by(email=approver_email).first()
#         if not faculty:
#             return jsonify({"success": False, "message": "Unauthorized access"}), 403
        
#         # Retrieve permission request
#         permission_request = PermissionRequest.query.get(request_id)
#         if not permission_request:
#             return jsonify({"success": False, "message": "Request not found"}), 404

#         # Check if the faculty has permission to approve this request
#         if role == "incharge" and faculty.category.lower() == "incharge":
#             permission_request.incharge_status = "Approved" if action == "approve" else "Rejected"
#         elif role == "hod" and faculty.category.lower() == "hod":
#             if permission_request.permission_type == "Leave":
#                 permission_request.hod_status = "Approved" if action == "approve" else "Rejected"
#         else:
#             return jsonify({"success": False, "message": "Unauthorized access"}), 403

#         # Final status check for Leave & Outing requests
#         if permission_request.permission_type == "Leave":
#             if permission_request.hod_status == "Approved" and permission_request.incharge_status == "Approved":
#                 permission_request.status = "Approved"
#             elif permission_request.hod_status == "Rejected" or permission_request.incharge_status == "Rejected":
#                 permission_request.status = "Rejected"
#         elif permission_request.permission_type == "Outing":
#             permission_request.status = "Approved" if permission_request.incharge_status == "Approved" else "Rejected"

#         # Commit the changes
#         db.session.commit()

#         # Send email to student
#         email_subject = f"Your {permission_request.permission_type} request has been {permission_request.status}"
#         email_body = f"Dear Student,\n\nYour {permission_request.permission_type} request has been {permission_request.status} by {faculty.category}.\n\nBest Regards,\nAdmin"

#         msg = Message(email_subject, sender="pragadaprem143@gmail.com", recipients=[permission_request.student_email])
#         msg.body = email_body
#         mail.send(msg)

#         return jsonify({"success": True, "new_status": permission_request.status}), 200

#     except Exception as e:
#         return jsonify({"success": False, "message": f"Error processing request: {str(e)}"}), 500

def send_sms_fast2sms(phone_number, message):
    url = "https://www.fast2sms.com/dev/bulkV2"
    headers = {
        "authorization": os.getenv("FAST2SMS_API_KEY"),  # Store API Key in environment variable
        "Content-Type": "application/x-www-form-urlencoded"
    }
    data = {
        "route": "q",
        "message": message,
        "language": "english",
        "flash": 0,
        "numbers": phone_number
    }
    response = requests.post(url, headers=headers, data=data)
    return response.json()

@app.route('/process_request', methods=['POST'])
def process_request_post():
    try:
        if 'username' not in session:
            return jsonify({"success": False, "message": "Unauthorized access"}), 403

        data = request.get_json()
        request_id = data.get("request_id")
        action = data.get("action")
        role = data.get("role")  # "hod" or "incharge"
        message = data.get("message", "")  # Get the rejection message
        approver_email = session['username']  # Get logged-in faculty email

        # Retrieve faculty details
        faculty = Faculty.query.filter_by(email=approver_email).first()
        if not faculty:
            return jsonify({"success": False, "message": "Unauthorized access"}), 403

        # Retrieve permission request
        permission_request = PermissionRequest.query.get(request_id)
        if not permission_request:
            return jsonify({"success": False, "message": "Request not found"}), 404

        # Check if the faculty has permission to approve this request
        if role == "incharge" and faculty.category.lower() == "incharge":
            permission_request.incharge_status = "Approved" if action == "approve" else "Rejected"
            if action == "reject":
                permission_request.incharge_message = message  # Store Incharge's rejection message
        elif role == "hod" and faculty.category.lower() == "hod":
            if permission_request.permission_type == "Leave":
                permission_request.hod_status = "Approved" if action == "approve" else "Rejected"
                if action == "reject":
                    permission_request.hod_message = message  # Store HOD's rejection message
            elif permission_request.permission_type == "Outing":
                # Set HOD message to NIL for Outing requests
                permission_request.hod_message = "NIL"
        else:
            return jsonify({"success": False, "message": "Unauthorized access"}), 403

        # Final status check for Leave & Outing requests
        if permission_request.permission_type == "Leave":
            if permission_request.hod_status == "Approved" and permission_request.incharge_status == "Approved":
                permission_request.status = "Approved"
            elif permission_request.hod_status == "Rejected" or permission_request.incharge_status == "Rejected":
                permission_request.status = "Rejected"
        elif permission_request.permission_type == "Outing":
            permission_request.status = "Approved" if permission_request.incharge_status == "Approved" else "Rejected"

        # Commit the changes
        db.session.commit()

        # Generate QR code if the request is approved
        if permission_request.status == "Approved":
            # Create QR code data
            expiration_time = int(time.time()) + 3600  # 1 hour from now
            qr_data = f"Student Name: {permission_request.student_name}, Regd: {permission_request.student_regd}, Dept: {permission_request.dept}, Permission Type: {permission_request.permission_type}, Status: {permission_request.status}, Start Time: {permission_request.start_time or 'N/A'}, End Time: {permission_request.end_time or 'N/A'}, Start Date: {permission_request.start_date or 'N/A'}, End Date: {permission_request.end_date or 'N/A'}, Permission ID: {permission_request.id}, Exp: {expiration_time}"

            # Use the cipher_suite from the app configuration
            cipher_suite = Fernet(app.config['ENCRYPTION_KEY'])

            # Encrypt the data
            encrypted_data = cipher_suite.encrypt(qr_data.encode())

            # Generate QR code with encrypted data
            qr = qrcode.QRCode(version=1, box_size=10, border=5)
            qr.add_data(encrypted_data)
            qr.make(fit=True)
            img = qr.make_image(fill='black', back_color='white')

            # Save the QR code image to a file
            qr_filename = f"qr_{permission_request.student_regd}.png"
            qr_path = os.path.join(app.config['UPLOAD_FOLDER'], qr_filename)
            img.save(qr_path)

            # Generate a URL for the QR code image
            qr_url = url_for('static', filename=f'uploads/{qr_filename}', _external=True)

            # Send the QR code URL in the email
            email_subject = f"{permission_request.permission_type} request"
            email_body = f"""
            Dear Student,

            Your {permission_request.permission_type} request has been {permission_request.status}.

            Please find the QR code for verification at the following link:
            {qr_url}

            Best Regards,
            Admin
            """

            msg = Message(email_subject, sender="pragadaprem143@gmail.com",
                          recipients=[permission_request.student_email])
            msg.body = email_body
            mail.send(msg)

            # Store the encryption key securely in the database
            permission_request.encryption_key = app.config['ENCRYPTION_KEY'].decode()
            db.session.commit()

        return jsonify({"success": True, "new_status": permission_request.status}), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "message": f"Error processing request: {str(e)}"}), 500
    




# def process_request_post():
#     try:
#         if 'username' not in session:
#             return jsonify({"success": False, "message": "Unauthorized access"}), 403

#         data = request.get_json()
#         request_id = data.get("request_id")
#         action = data.get("action")
#         role = data.get("role")  # "hod" or "incharge"
#         message = data.get("message", "")  # Get the rejection message
#         approver_email = session['username']  # Get logged-in faculty email

#         # Retrieve faculty details
#         faculty = Faculty.query.filter_by(email=approver_email).first()
#         if not faculty:
#             return jsonify({"success": False, "message": "Unauthorized access"}), 403

#         # Retrieve permission request
#         permission_request = PermissionRequest.query.get(request_id)
#         if not permission_request:
#             return jsonify({"success": False, "message": "Request not found"}), 404

#         # Check if the faculty has permission to approve this request
#         if role == "incharge" and faculty.category.lower() == "incharge":
#             permission_request.incharge_status = "Approved" if action == "approve" else "Rejected"
#             if action == "reject":
#                 permission_request.incharge_message = message  # Store Incharge's rejection message
#         elif role == "hod" and faculty.category.lower() == "hod":
#             if permission_request.permission_type == "Leave":
#                 permission_request.hod_status = "Approved" if action == "approve" else "Rejected"
#                 if action == "reject":
#                     permission_request.hod_message = message  # Store HOD's rejection message
#             elif permission_request.permission_type == "Outing":
#                 # Set HOD message to NIL for Outing requests
#                 permission_request.hod_message = "NIL"
#         else:
#             return jsonify({"success": False, "message": "Unauthorized access"}), 403

#         # Final status check for Leave & Outing requests
#         if permission_request.permission_type == "Leave":
#             if permission_request.hod_status == "Approved" and permission_request.incharge_status == "Approved":
#                 permission_request.status = "Approved"
#             elif permission_request.hod_status == "Rejected" or permission_request.incharge_status == "Rejected":
#                 permission_request.status = "Rejected"
#         elif permission_request.permission_type == "Outing":
#             permission_request.status = "Approved" if permission_request.incharge_status == "Approved" else "Rejected"

#         # Commit the changes
#         db.session.commit()

#         # Generate QR code if the request is approved
#         if permission_request.status == "Approved":
#             # Create QR code data
#             qr_data = f"""
#             Student Name: {permission_request.student_name}
#             Registration Number: {permission_request.student_regd}
#             Dept: {permission_request.dept}
#             Permission Type: {permission_request.permission_type}
#             Status: Approved
#             Start Time: {permission_request.start_time}
#             End Time: {permission_request.end_time}
#             Start Date: {permission_request.start_date}
#             End Date: {permission_request.end_date}
#             """

#             qr = qrcode.QRCode(version=1, box_size=10, border=5)
#             qr.add_data(qr_data)
#             qr.make(fit=True)
#             img = qr.make_image(fill='black', back_color='white')

#             # Save the QR code image to a file
#             qr_filename = f"qr_{permission_request.student_regd}.png"
#             qr_path = os.path.join(app.config['UPLOAD_FOLDER'], qr_filename)
#             img.save(qr_path)

#             # Generate a URL for the QR code image
#             qr_url = url_for('static', filename=f'uploads/{qr_filename}', _external=True)

#             # Send the QR code URL in the email
#             email_subject = f"{permission_request.permission_type} request"
#             email_body = f"""
#             Dear Student,

#             Your {permission_request.permission_type} request has been {permission_request.status}.

#             Please find the QR code for verification at the following link:
#             {qr_url}

#             Best Regards,
#             Admin
#             """

#             msg = Message(email_subject, sender="pragadaprem143@gmail.com", recipients=[permission_request.student_email])
#             msg.body = email_body
#             mail.send(msg)

#         return jsonify({"success": True, "new_status": permission_request.status}), 200

#     except Exception as e:
#         return jsonify({"success": False, "message": f"Error processing request: {str(e)}"}), 500



# @app.route('/verify_qr', methods=['POST'])
# def verify_qr():
#     try:
#         data = request.get_json()
#         qr_data = data.get("qr_data")

#         # Parse QR code data
#         qr_lines = qr_data.split("\n")
#         qr_dict = {line.split(": ")[0]: line.split(": ")[1] for line in qr_lines if ": " in line}

#         student_regd = qr_dict.get("Registration Number")
#         Dept = qr_dict.get("Dept")
#         permission_type = qr_dict.get("Permission Type")
#         end_time = qr_dict.get("End Time")
#         end_date = qr_dict.get("End Date")

#         # Check if the permission is still valid
#         current_time = datetime.utcnow()
#         end_datetime = datetime.strptime(f"{end_date} {end_time}", "%Y-%m-%d %H:%M:%S")

#         if current_time > end_datetime:
#             return jsonify({"success": False, "message": "Permission has expired"}), 400

#         # Fetch the student's permission request
#         permission_request = PermissionRequest.query.filter_by(student_regd=student_regd, permission_type=permission_type).first()
#         if not permission_request:
#             return jsonify({"success": False, "message": "Permission not found"}), 404

#         return jsonify({"success": True, "message": "Permission is valid"}), 200

#     except Exception as e:
#         return jsonify({"success": False, "message": f"Error verifying QR code: {str(e)}"}), 500



def delete_expired_qr_codes():
    print("Running delete_expired_qr_codes job...")
    with app.app_context():
        # Get the current time in IST (Indian Standard Time)
        ist = timezone('Asia/Kolkata')
        current_time = datetime.now(ist)

        # Fetch all approved requests
        expired_requests = PermissionRequest.query.filter(
            PermissionRequest.status == "Approved"
        ).all()

        for request in expired_requests:
            # Handle Outing Requests (only end_time is provided)
            if request.permission_type == "Outing":
                if request.end_time is None:
                    print(f"Skipping outing request ID {request.id} because end_time is None.")
                    continue

                # For outings, use today's date and the provided end_time
                end_date = current_time.strftime("%Y-%m-%d")  # Today's date
                end_time = request.end_time

            # Handle Leave Requests (only end_date is provided)
            elif request.permission_type == "Leave":
                if request.end_date is None:
                    print(f"Skipping leave request ID {request.id} because end_date is None.")
                    continue

                # For leaves, use the provided end_date and a default end_time (end of day)
                end_date = request.end_date
                end_time = "23:59:59"  # Default end_time for leave requests

            else:
                print(f"Skipping request ID {request.id} because permission_type is invalid.")
                continue

            # Handle cases where end_time does not include seconds
            if len(end_time.split(':')) == 2:  # Only hours and minutes are provided
                end_time += ":00"  # Add seconds

            # Combine end_date and end_time into a datetime object
            end_datetime_str = f"{end_date} {end_time}"
            try:
                end_datetime = datetime.strptime(end_datetime_str, "%Y-%m-%d %H:%M:%S")
            except ValueError as e:
                print(f"Error parsing datetime for request ID {request.id}: {e}")
                continue  # Skip this request if datetime parsing fails

            # Make the end_datetime time zone-aware (IST)
            end_datetime = ist.localize(end_datetime)

            # Check if the request has expired
            if current_time > end_datetime:
                # Generate the QR code filename
                qr_filename = f"qr_{request.student_regd}.png"
                qr_path = os.path.join(app.config['UPLOAD_FOLDER'], qr_filename)

                # Check if the QR code file exists and delete it
                print(f"Checking QR code at path: {qr_path}")
                if os.path.exists(qr_path):
                    os.remove(qr_path)
                    print(f"Deleted QR code for request ID: {request.id}")
                else:
                    print(f"QR code not found at path: {qr_path}")

# def check_expired_permissions_and_notify():
#     with app.app_context():
#         # Get the current time in IST (Indian Standard Time)
#         ist = timezone('Asia/Kolkata')
#         current_time = datetime.now(ist)

#         # Fetch all approved requests
#         expired_requests = PermissionRequest.query.filter(
#             PermissionRequest.status == "Approved"
#         ).all()

#         for request in expired_requests:
#             # Handle Outing Requests (only end_time is provided)
#             if request.permission_type == "Outing":
#                 if request.end_time is None:
#                     continue

#                 # For outings, use today's date and the provided end_time
#                 end_date = current_time.strftime("%Y-%m-%d")  # Today's date
#                 end_time = request.end_time

#             # Handle Leave Requests (only end_date is provided)
#             elif request.permission_type == "Leave":
#                 if request.end_date is None:
#                     continue

#                 # For leaves, use the provided end_date and a default end_time (end of day)
#                 end_date = request.end_date
#                 end_time = "23:59:59"  # Default end_time for leave requests

#             else:
#                 continue

#             # Handle cases where end_time does not include seconds
#             if len(end_time.split(':')) == 2:  # Only hours and minutes are provided
#                 end_time += ":00"  # Add seconds

#             # Combine end_date and end_time into a datetime object
#             end_datetime_str = f"{end_date} {end_time}"
#             try:
#                 end_datetime = datetime.strptime(end_datetime_str, "%Y-%m-%d %H:%M:%S")
#             except ValueError as e:
#                 continue  # Skip this request if datetime parsing fails

#             # Make the end_datetime time zone-aware (IST)
#             end_datetime = ist.localize(end_datetime)

#             # Check if the request has expired
#             if current_time > end_datetime:
#                 # Send email to student
#                 student_email_subject = f"Your {request.permission_type} request has expired"
#                 student_email_body = f"""
#                 Dear {request.student_name},

#                 Your {request.permission_type} request has expired. Please return to the campus immediately.

#                 Best Regards,
#                 Admin
#                 """
#                 msg = Message(student_email_subject, sender="pragadaprem143@gmail.com", recipients=[request.student_email])
#                 msg.body = student_email_body
#                 mail.send(msg)

#                 # Send email to HOD
#                 hod = Faculty.query.filter_by(dept=request.dept, category="HOD").first()
#                 if hod:
#                     hod_email_subject = f"Student {request.student_name} has not returned"
#                     hod_email_body = f"""
#                     Dear {hod.first_name},

#                     Student {request.student_name} ({request.student_regd}) has not returned after their {request.permission_type} request expired.

#                     Best Regards,
#                     Admin
#                     """
#                     msg = Message(hod_email_subject, sender="pragadaprem143@gmail.com", recipients=[hod.email])
#                     msg.body = hod_email_body
#                     mail.send(msg)

#                 # Send email to Incharge
#                 incharge = Faculty.query.filter_by(category="Incharge").first()
#                 if incharge:
#                     incharge_email_subject = f"Student {request.student_name} has not returned"
#                     incharge_email_body = f"""
#                     Dear {incharge.first_name},

#                     Student {request.student_name} ({request.student_regd}) has not returned after their {request.permission_type} request expired.

#                     Best Regards,
#                     Admin
#                     """
#                     msg = Message(incharge_email_subject, sender="pragadaprem143@gmail.com", recipients=[incharge.email])
#                     msg.body = incharge_email_body
#                     mail.send(msg)

#                 # Optionally, you can update the status of the request to "Expired"
#                 request.status = "Expired"
#                 db.session.commit()

import traceback

def send_email(subject, body, recipient):
    try:
        msg = Message(subject, sender="pragadaprem143@gmail.com", recipients=[recipient])
        msg.body = body
        mail.send(msg)
        print(f"Email sent successfully to {recipient}")
    except Exception as e:
        print(f"Failed to send email to {recipient}: {str(e)}")
        traceback.print_exc()  # Print the full traceback

def check_expired_permissions_and_notify():
    with app.app_context():
        try:
            ist = timezone('Asia/Kolkata')
            current_time = datetime.now(ist)
            print(f"Current time: {current_time}")  # Debug statement

            # Fetch all approved requests
            expired_requests = PermissionRequest.query.filter(
                PermissionRequest.status == "Approved"
            ).all()

            print(f"Total approved requests: {len(expired_requests)}")  # Debug statement

            for request in expired_requests:
                print(f"Processing request ID: {request.id}")  # Debug statement

                # Handle Outing Requests
                if request.permission_type == "Outing":
                    if request.end_time is None:
                        print(f"Skipping outing request ID {request.id} because end_time is None.")  # Debug statement
                        continue

                    # For outings, use today's date and the provided end_time
                    end_date = current_time.strftime("%Y-%m-%d")
                    end_time = request.end_time

                # Handle Leave Requests
                elif request.permission_type == "Leave":
                    if request.end_date is None:
                        print(f"Skipping leave request ID {request.id} because end_date is None.")  # Debug statement
                        continue

                    # For leaves, use the provided end_date and a default end_time (end of day)
                    end_date = request.end_date
                    end_time = "23:59:59"

                else:
                    print(f"Skipping request ID {request.id} because permission_type is invalid.")  # Debug statement
                    continue

                # Handle cases where end_time does not include seconds
                if len(end_time.split(':')) == 2:  # Only hours and minutes are provided
                    end_time += ":00"  # Add seconds

                # Combine end_date and end_time into a datetime object
                end_datetime_str = f"{end_date} {end_time}"
                try:
                    end_datetime = datetime.strptime(end_datetime_str, "%Y-%m-%d %H:%M:%S")
                    end_datetime = ist.localize(end_datetime)  # Make the end_datetime time zone-aware (IST)
                except ValueError as e:
                    print(f"Error parsing datetime for request ID {request.id}: {e}")  # Debug statement
                    continue

                print(f"End datetime for request ID {request.id}: {end_datetime}")  # Debug statement

                # Check if the request has expired
                if current_time > end_datetime:
                    print(f"Request ID {request.id} has expired.")  # Debug statement

                    # Check if the student has checked out
                    if not request.check_out_time:
                        print(f"Student has not checked out for request ID {request.id}.")  # Debug statement

                        # Send email to student
                        student_email_subject = f"Your {request.permission_type} request has expired"
                        student_email_body = f"""
                        Dear {request.student_name},

                        Your {request.permission_type} request has expired. Please return to the campus immediately.

                        Best Regards,
                        Admin
                        """
                        send_email(student_email_subject, student_email_body, request.student_email)

                        # Send email to HOD
                        hod = Faculty.query.filter_by(dept=request.dept, category="HOD").first()
                        if hod:
                            hod_email_subject = f"Student {request.student_name} has not returned"
                            hod_email_body = f"""
                            Dear {hod.first_name},

                            Student {request.student_name} ({request.student_regd}) has not returned after their {request.permission_type} request expired.

                            Best Regards,
                            Admin
                            """
                            send_email(hod_email_subject, hod_email_body, hod.email)

                        # Send email to Incharge
                        incharge = Faculty.query.filter_by(category="Incharge").first()
                        if incharge:
                            incharge_email_subject = f"Student {request.student_name} has not returned"
                            incharge_email_body = f"""
                            Dear {incharge.first_name},

                            Student {request.student_name} ({request.student_regd}) has not returned after their {request.permission_type} request expired.

                            Best Regards,
                            Admin
                            """
                            send_email(incharge_email_subject, incharge_email_body, incharge.email)

                        # Optionally, update the status of the request to "Expired"
                        request.status = "Expired"
                        db.session.commit()
                        print(f"Request ID {request.id} marked as expired.")  # Debug statement

        except Exception as e:
            print(f"Error in check_expired_permissions_and_notify: {str(e)}")  # Debug statement
            traceback.print_exc()  # Print the full traceback

@app.route('/verify_qr', methods=['POST'])
def verify_qr():
    try:
        data = request.get_json()
        encrypted_data = data.get("qr_data")

        if not encrypted_data:
            return jsonify({"success": False, "message": "No QR data provided"}), 400

        # Decrypt the data using the stored encryption key
        cipher_suite = Fernet(app.config['ENCRYPTION_KEY'])
        decrypted_data = cipher_suite.decrypt(encrypted_data.encode()).decode()

        # Parse the decrypted data
        qr_lines = decrypted_data.split(", ")
        qr_dict = {line.split(": ")[0]: line.split(": ")[1] for line in qr_lines if ": " in line}

        # Check if the QR code is still valid
        expiration_time = int(qr_dict.get("Exp"))
        if time.time() > expiration_time:
            return jsonify({"success": False, "message": "QR code has expired"}), 400

        # Proceed with verification
        student_regd = qr_dict.get("Regd")
        student = User.query.filter_by(regd=student_regd).first()
        if not student:
            return jsonify({"success": False, "message": "Student not found"}), 404

        return jsonify({"success": True, "message": "QR code is valid", "student": student.first_name}), 200

    except Exception as e:
        print(f"Error verifying QR code: {str(e)}")  # Log the error for debugging
        return jsonify({"success": False, "message": f"Error verifying QR code: {str(e)}"}), 500
@app.route('/check_in', methods=['POST'])
def check_in():
    try:
        data = request.get_json()
        print("Received data for check-in:", data)  # Debug statement

        student_regd = data.get("student_regd")
        permission_id = data.get("permission_id")

        if not student_regd or not permission_id:
            return jsonify({"success": False, "message": "Student registration number and permission ID are required."}), 400

        # Fetch the permission request
        permission_request = PermissionRequest.query.filter_by(
            student_regd=student_regd,
            id=permission_id,
            status="Approved"
        ).first()

        if not permission_request:
            return jsonify({"success": False, "message": "Permission request not found or not approved."}), 404

        # Check if the permission is still valid
        ist = timezone('Asia/Kolkata')
        current_time = datetime.now(ist)
        print(f"Current time: {current_time}")  # Debug statement

        if permission_request.permission_type == "Outing":
            # For outing, use today's date and the provided end_time
            end_date = current_time.strftime("%Y-%m-%d")  # Today's date
            end_time = permission_request.end_time

            # Handle cases where end_time does not include seconds
            if len(end_time.split(':')) == 2:  # Only hours and minutes are provided
                end_time += ":00"  # Add seconds

            # Combine end_date and end_time into a datetime object
            end_datetime_str = f"{end_date} {end_time}"
            end_datetime = datetime.strptime(end_datetime_str, "%Y-%m-%d %H:%M:%S")
            end_datetime = ist.localize(end_datetime)

        elif permission_request.permission_type == "Leave":
            # For leave, use the provided end_date and a default end_time (end of day)
            end_date = permission_request.end_date
            end_time = "23:59:59"  # Default end_time for leave requests

            # Combine end_date and end_time into a datetime object
            end_datetime_str = f"{end_date} {end_time}"
            end_datetime = datetime.strptime(end_datetime_str, "%Y-%m-%d %H:%M:%S")
            end_datetime = ist.localize(end_datetime)

        else:
            return jsonify({"success": False, "message": "Invalid permission type."}), 400

        print(f"End datetime: {end_datetime}")  # Debug statement

        # Check if the permission has expired
        if current_time > end_datetime:
            return jsonify({"success": False, "message": "Permission has expired."}), 400

        # Update the check-in time
        permission_request.check_in_time = current_time
        db.session.commit()

        print(f"Check-in successful for permission ID: {permission_id}")  # Debug statement
        return jsonify({"success": True, "message": "Check-in successful."}), 200

    except Exception as e:
        db.session.rollback()
        print(f"Error during check-in: {str(e)}")  # Debug statement
        return jsonify({"success": False, "message": f"Error during check-in: {str(e)}"}), 500

@app.route('/check_out', methods=['POST'])
def check_out():
    try:
        data = request.get_json()
        print("Received data for check-out:", data)  # Debug statement

        student_regd = data.get("student_regd")
        permission_id = data.get("permission_id")

        if not student_regd or not permission_id:
            return jsonify({"success": False, "message": "Student registration number and permission ID are required."}), 400

        # Fetch the permission request
        permission_request = PermissionRequest.query.filter_by(
            student_regd=student_regd,
            id=permission_id,
            status="Approved"
        ).first()

        if not permission_request:
            return jsonify({"success": False, "message": "Permission request not found or not approved."}), 404

        # Update the check-out time
        permission_request.check_out_time = datetime.now(timezone('Asia/Kolkata'))
        db.session.commit()

        print(f"Check-out successful for permission ID: {permission_id}")  # Debug statement
        return jsonify({"success": True, "message": "Check-out successful."}), 200

    except Exception as e:
        db.session.rollback()
        print(f"Error during check-out: {str(e)}")  # Debug statement
        return jsonify({"success": False, "message": f"Error during check-out: {str(e)}"}), 500

# @app.route('/scan_login', methods=['GET', 'POST'])
# def scan_login():
#     if request.method == 'POST':
#         username = request.form.get('username')
#         password = request.form.get('password')
        
#         # Check if the user is authorized (e.g., security personnel)
#         authorized_user = Faculty.query.filter_by(email=username, category='security').first()
        
#         if authorized_user and check_password_hash(authorized_user.password_hash, password):
#             session['scan_authorized'] = True
#             return redirect(url_for('scan_qr'))
#         else:
#             flash('Invalid credentials', 'error')
    
#     return render_template('scan_login.html')

@app.route('/scan_qr')
def scan_qr():
    if 'username' not in session or session.get('category') != 'security':
        return redirect(url_for('login'))  # Redirect to login if not authenticated or not a security personnel
    
    return render_template('scan_qr.html')



# delete_expired_qr_codes()
# @app.route('/logout')
# def logout():
#     session.clear()  # Clear the session
#     return redirect(url_for('home'))
@app.route('/logout')
def logout():
    session.clear()  # Clear session
    response = redirect(url_for('home'))

    # Prevent caching to block back navigation
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"

    return response

# @app.after_request
# def add_no_cache_headers(response):
#     response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
#     response.headers["Pragma"] = "no-cache"
#     response.headers["Expires"] = "0"
#     return response



@app.route('/form')
def form():
    return render_template('frm.html')

@app.errorhandler(403)
def forbidden(e):
    return render_template('403.html'), 403  # Create a 403.html template for unauthorized access

@app.route('/get_student_details', methods=['POST'])
def get_student_details():
    data = request.get_json()
    student_regd = data.get("student_regd")

    if not student_regd:
        return jsonify({"success": False, "message": "Invalid Register Number"}), 400

    student = User.query.filter_by(regd=student_regd).first()
    if student:
        leave_count = PermissionRequest.query.filter_by(
            student_regd=student_regd,
            permission_type="Leave",
            status="Approved"
        ).count()

        outing_count = PermissionRequest.query.filter_by(
            student_regd=student_regd,
            permission_type="Outing",
            status="Approved"
        ).count()

        student_data = {
            "name": f"{student.first_name} {student.last_name}",
            "register_number": student.regd,
            "department": student.dept,
            "phone": student.student_phone,
            "email": student.email,
            "leave_requests": leave_count,
            "outing_requests": outing_count,
            "photo": student.photo
        }
        return jsonify({"success": True, "student": student_data})
    else:
        return jsonify({"success": False, "message": "Student not found"}), 404

def reset_permissions_db():
    with app.app_context():
        # Calculate the timestamp for 6 months ago
        six_months_ago = datetime.now(timezone.utc) - timedelta(days = 180)
        # Query and delete old permission requests
        old_requests = PermissionRequest.query.filter(
            PermissionRequest.timestamp < six_months_ago
        ).all()

        for request in old_requests:
            db.session.delete(request)

        db.session.commit()
        print("✅ Old permission requests (older than 6 months) deleted successfully.")


@app.route('/addStudent')
@login_required(role='admin')  # Only admin can access
def addStudent():
    return render_template('add_student.html')

@app.route('/removeStudent')
@login_required(role='admin')  # Only admin can access
def removeStudent():
    return render_template('remove_student.html')

@app.route('/modifyStudent')
@login_required(role='admin')  # Only admin can access
def modifyStudent():
    return render_template('modify_student.html')

@app.route('/viewStudent')
@login_required(role='admin')  # Only admin can access
def viewStudent():
    return render_template('view_student_details.html')

@app.route('/addFaculty')
@login_required(role='admin')  # Only admin can access
def addFaculty():
    return render_template('add_faculty.html')

@app.route('/removeFaculty')
@login_required(role='admin')  # Only admin can access
def removeFaculty():
    return render_template('remove_faculty.html')

@app.route('/modifyFaculty')
@login_required(role='admin')  # Only admin can access
def modifyFaculty():
    return render_template('modify_faculty.html')

@app.route('/viewFaculty')
@login_required(role='admin')  # Only admin can access
def viewFaculty():
    return render_template('view_faculty_details.html')


@app.route('/upload1', methods=['POST'])
def upload1():
    if 'file' not in request.files:
        flash('No file selected', 'error')
        return redirect(request.url)
    
    file = request.files['file']
    if file.filename == '':
        flash('No selected file', 'error')
        return redirect(request.url)
    
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        try:
            with open(filepath, 'r') as csvfile:
                reader = csv.DictReader(csvfile)
                for row in reader:
                    # Skip empty rows
                    if not any(row.values()):
                        continue

                    # Strip whitespace from keys and values
                    row = {k.strip(): v.strip() if isinstance(v, str) else v for k, v in row.items()}

                    # Validate required fields
                    required_fields = ['regd', 'first_name', 'email']
                    if not all(row.get(field) for field in required_fields):
                        flash(f"Missing required fields in row: {row}", 'error')
                        continue
                    
                    # Check for duplicates
                    existing_user = User.query.filter_by(regd=row['regd']).first()
                    if existing_user:
                        flash(f"Student with regd {row['regd']} already exists", 'warning')
                        continue
                    
                    # Hash the password
                    hashed_password = generate_password_hash(row['password'])
                    
                    # Create new User object
                    new_user = User(
                        regd=row['regd'],
                        first_name=row['first_name'],
                        last_name=row['last_name'],
                        gender=row.get('gender', 'not prefer to say'),  # Default value if gender is missing
                        email=row['email'],
                        dept=row['dept'],
                        student_phone=row['student_phone'],
                        parent_phone=row['parent_phone'],
                        address=row['address'],
                        password=hashed_password,
                        photo=row['photo'],
                        category=row['category']
                    )
                    
                    db.session.add(new_user)
                db.session.commit()
            
            flash('CSV file processed successfully', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Error processing CSV: {str(e)}', 'error')
        finally:
            os.remove(filepath)  # Delete the file after processing
    else:
        flash('Invalid file type. Only CSV files are allowed.', 'error')
    
    return redirect(url_for('addStudent'))

@app.route('/add_single_student', methods=['POST'])
def add_single_student():
    try:
        # Extract form data
        regd = request.form['regd']
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        gender = request.form['gender']
        email = request.form['email']
        dept = request.form['dept']
        student_phone = request.form['student_phone']
        parent_phone = request.form['parent_phone']
        address = request.form['address']
        password = request.form['password']
        category = request.form['category']

        # Check for existing registration number
        existing_user = User.query.filter_by(regd=regd).first()
        if existing_user:
            flash('Error: Registration number already exists', 'error')
            return redirect(url_for('addStudent'))

        # Process file upload
        if 'photo' not in request.files:
            flash('No file uploaded', 'error')
            return redirect(url_for('addStudent'))
        
        file = request.files['photo']
        if file.filename == '':
            flash('No selected file', 'error')
            return redirect(url_for('addStudent'))
            
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            photo_path = filename
        else:
            flash('Invalid file type', 'error')
            return redirect(url_for('addStudent'))

        # Create new User object
        new_user = User(
            regd=regd,
            first_name=first_name,
            last_name=last_name,
            email=email,
            dept=dept,
            student_phone=student_phone,
            parent_phone=parent_phone,
            address=address,
            password=generate_password_hash(password),
            photo=photo_path,
            category=category
        )

        db.session.add(new_user)
        db.session.commit()

        flash('Student added successfully!', 'success')
        return redirect(url_for('addStudent'))

    except Exception as e:
        db.session.rollback()
        flash(f'Error: {str(e)}', 'error')
        return redirect(url_for('addStudent'))
    


# Single student deletion route
@app.route('/delete_student', methods=['POST'])
def delete_student():
    if 'username' not in session or session.get('category') != 'admin':
        flash('Unauthorized access', 'error')
        return redirect(url_for('home'))

    regd = request.form.get('regd')
    if not regd:
        flash('Please enter a registration number', 'error')
        return redirect(url_for('removeStudent'))

    student = User.query.filter_by(regd=regd).first()
    if student:
        try:
            # Delete associated permissions
            PermissionRequest.query.filter_by(student_regd=regd).delete()
            db.session.delete(student)
            db.session.commit()
            flash(f'Success! Student {regd} deleted permanently', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Error deleting student: {str(e)}', 'error')
    else:
        flash(f'Student {regd} not found in database', 'error')
    
    return redirect(url_for('removeStudent'))


# CSV deletion route
@app.route('/delete_csv', methods=['POST'])
def delete_csv():
    if 'username' not in session or session.get('category') != 'admin':
        flash('Unauthorized access', 'error')
        return redirect(url_for('home'))

    if 'file' not in request.files:
        flash('No file selected', 'error')
        return redirect(url_for('removeStudent'))

    file = request.files['file']
    if file.filename == '':
        flash('No selected file', 'error')
        return redirect(url_for('removeStudent'))

    if file and file.filename.endswith('.csv'):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        try:
            deleted_count = 0
            with open(filepath, 'r') as csvfile:
                reader = csv.reader(csvfile)
                header = next(reader, None)
                
                if not header or 'regd' not in header:
                    flash('Invalid CSV format: Missing regd column header', 'error')
                    return redirect(url_for('removeStudent'))
                
                regd_index = header.index('regd')
                
                for row in reader:
                    if len(row) <= regd_index:
                        continue
                    regd = row[regd_index].strip()
                    if regd:
                        student = User.query.filter_by(regd=regd).first()
                        if student:
                            PermissionRequest.query.filter_by(student_regd=regd).delete()
                            db.session.delete(student)
                            deleted_count += 1
                            
                db.session.commit()
                
                if deleted_count > 0:
                    flash(f'Success! Deleted {deleted_count} students from CSV', 'success')
                else:
                    flash('No valid students found in CSV file', 'warning')
                    
            os.remove(filepath)
            
        except Exception as e:
            db.session.rollback()
            flash(f'CSV processing failed: {str(e)}', 'error')
            if os.path.exists(filepath):
                os.remove(filepath)
                
    else:
        flash('Only CSV files allowed', 'error')
    
    return redirect(url_for('removeStudent'))

@app.route('/get_student')
def get_student():
    if 'username' not in session or session.get('category') != 'admin':
        return jsonify({"error": "Unauthorized"}), 403

    regd = request.args.get('regd')
    if not regd:
        return jsonify({"error": "Registration number required"}), 400

    student = User.query.filter_by(regd=regd).first()
    if not student:
        return jsonify({"error": "Student not found"}), 404

    return jsonify({
        "regd": student.regd,
        "first_name": student.first_name,
        "last_name": student.last_name,
        "email": student.email,
        "dept": student.dept,
        "student_phone": student.student_phone,
        "parent_phone": student.parent_phone,
        "address": student.address
    })

@app.route('/modify_student', methods=['POST'])
def modify_student():
    if 'username' not in session or session.get('category') != 'admin':
        flash('Unauthorized access', 'error')
        return redirect(url_for('home'))

    original_regd = request.form.get('original_regd')
    new_regd = request.form.get('regd')
    
    try:
        student = User.query.filter_by(regd=original_regd).first()
        if not student:
            flash('Student not found', 'error')
            return redirect(url_for('modifyStudent'))

        # Check if new regd already exists
        if new_regd != original_regd and User.query.filter_by(regd=new_regd).first():
            flash('New registration number already exists', 'error')
            return redirect(url_for('modifyStudent'))

        # Update fields
        student.regd = new_regd
        student.first_name = request.form.get('first_name')
        student.last_name = request.form.get('last_name')
        student.email = request.form.get('email')
        student.dept = request.form.get('dept').capitalize
        student.student_phone = request.form.get('student_phone')
        student.parent_phone = request.form.get('parent_phone')
        student.address = request.form.get('address')

        db.session.commit()
        flash('Student details updated successfully', 'success')
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error updating student: {str(e)}', 'error')

    return redirect(url_for('modifyStudent'))

#view_student



@app.route('/get_students_by_dept')
def get_students_by_dept():
    if 'username' not in session or session.get('category') != 'admin':
        return jsonify({"error": "Unauthorized"}), 403

    dept = request.args.get('dept', '')
    
    query = User.query
    if dept:
        query = query.filter_by(dept=dept)
    
    students = query.all()
    
    student_list = [{
        "regd": s.regd,
        "first_name": s.first_name,
        "last_name": s.last_name,
        "email": s.email,
        "student_phone": s.student_phone,
        "parent_phone":s.parent_phone,
        "dept": s.dept
    } for s in students]

    return jsonify({"students": student_list})

@app.route('/add_faculty', methods=['POST'])
def add_faculty():
    try:
        # Get form data
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        email = request.form.get('email')
        dept = request.form.get('dept')
        faculty_phone = request.form.get('faculty_phone')
        room_no = request.form.get('room_no')
        category = request.form.get('category').upper()
        password = request.form.get('password')
        photo = request.files.get('photo')

        # Hash the password
        hashed_password = generate_password_hash(password)

        # Save the photo (if provided)
        photo_path = None
        if photo:
            photo_filename = secure_filename(photo.filename)
            photo_path = os.path.join(app.config['UPLOAD_FOLDER'], photo_filename)
            photo.save(photo_path)
            photo_path = f"static/uploads/{photo_filename}"

        # Create a new Faculty object
        new_faculty = Faculty(
            first_name=first_name,
            last_name=last_name,
            email=email,
            dept=dept,
            faculty_phone=faculty_phone,
            room_no=room_no,
            category=category,
            password_hash=hashed_password,
            photo=photo_path
        )

        # Add to the database
        db.session.add(new_faculty)
        db.session.commit()

        return jsonify({"success": True, "message": "Faculty member added successfully!"})

    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "message": str(e)}), 500

@app.route('/remove_faculty', methods=['POST'])
def remove_faculty():
    try:
        data = request.get_json()
        email = data.get('email')

        if not email:
            return jsonify({"success": False, "message": "Email is required."}), 400

        # Find the faculty member by email
        faculty = Faculty.query.filter_by(email=email).first()

        if not faculty:
            return jsonify({"success": False, "message": "Faculty member not found."}), 404

        # Delete the faculty member from the database
        db.session.delete(faculty)
        db.session.commit()

        return jsonify({"success": True, "message": "Faculty member removed successfully!"})

    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "message": str(e)}), 500

@app.route('/get_faculty_by_department', methods=['GET'])
def get_faculty_by_department():
    try:
        department = request.args.get('department')

        if not department:
            return jsonify({"success": False, "message": "Department is required."}), 400

        # Find all faculty members in the department
        faculty_members = Faculty.query.filter_by(dept=department).all()

        if not faculty_members:
            return jsonify({"success": False, "message": "No faculty members found in this department."}), 404

        # Return faculty details
        faculty_data = [
            {
                "first_name": faculty.first_name,
                "last_name": faculty.last_name,
                "email": faculty.email,
                "dept": faculty.dept,
                "faculty_phone": faculty.faculty_phone,
                "room_no": faculty.room_no,
                "category": faculty.category,
                "photo": faculty.photo if faculty.photo else "No photo available.jpg"
            }
            for faculty in faculty_members
        ]

        return jsonify({"success": True, "faculty": faculty_data})

    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

@app.route('/get_faculty', methods=['GET'])
def get_faculty():
    try:
        email = request.args.get('email')

        if not email:
            return jsonify({"success": False, "message": "Email is required."}), 400

        # Find the faculty member by email
        faculty = Faculty.query.filter_by(email=email).first()

        if not faculty:
            return jsonify({"success": False, "message": "Faculty member not found."}), 404

        # Return faculty details
        faculty_data = {
            "first_name": faculty.first_name,
            "last_name": faculty.last_name,
            "email": faculty.email,
            "dept": faculty.dept,
            "faculty_phone": faculty.faculty_phone,
            "room_no": faculty.room_no,
            "category": faculty.category,
        }

        return jsonify({"success": True, "faculty": faculty_data})

    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500




@app.route('/modify_faculty', methods=['POST'])
def modify_faculty():
    try:
        # Get form data
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        new_email = request.form.get('email')  # New email from the form
        dept = request.form.get('dept')
        faculty_phone = request.form.get('faculty_phone')
        room_no = request.form.get('room_no')
        category = request.form.get('category').upper()
        photo = request.files.get('photo')
        original_email = request.form.get('original_email')  # Original email from the hidden field

        # Find the faculty member by the original email
        faculty = Faculty.query.filter_by(email=original_email).first()

        if not faculty:
            return jsonify({"success": False, "message": "Faculty member not found."}), 404

        # Check if the new email is already in use by another faculty member
        if new_email != original_email:  # Only check if the email is being changed
            existing_faculty = Faculty.query.filter_by(email=new_email).first()
            if existing_faculty:
                return jsonify({"success": False, "message": "Email is already in use by another faculty member."}), 400

        # Update faculty details (including email)
        faculty.first_name = first_name
        faculty.last_name = last_name
        faculty.email = new_email  # Update email
        faculty.dept = dept
        faculty.faculty_phone = faculty_phone
        faculty.room_no = room_no
        faculty.category = category

        # Update photo (if provided)
        if photo:
            photo_filename = secure_filename(photo.filename)
            photo_path = os.path.join(app.config['UPLOAD_FOLDER'], photo_filename)
            photo.save(photo_path)
            faculty.photo = f"static/uploads/{photo_filename}"

        # Commit changes to the database
        db.session.commit()

        return jsonify({"success": True, "message": "Faculty details updated successfully!"})

    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "message": str(e)}), 500

@app.route('/get_all_faculty', methods=['GET'])
def get_all_faculty():
    try:
        # Fetch all faculty members from the database
        faculty_members = Faculty.query.all()

        if not faculty_members:
            return jsonify({"success": False, "message": "No faculty members found."}), 404

        # Return faculty details
        faculty_data = [
            {
                "first_name": faculty.first_name,
                "last_name": faculty.last_name,
                "email": faculty.email,
                "dept": faculty.dept,
                "faculty_phone": faculty.faculty_phone,
                "room_no": faculty.room_no,
                "category": faculty.category,
                "photo": faculty.photo or "static/uploads/default.jpg",  # Default photo if none is provided
            }
            for faculty in faculty_members
        ]

        return jsonify({"success": True, "faculty": faculty_data})

    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

if __name__ == '__main__':
    with app.app_context():
        try:
            db.create_all()
            print("✅ Database connection successful!")
        except Exception as e:
            print(f"❌ Database connection failed: {e}")
        # db.session.query(User).delete()
        # db.session.commit()
        # print("✅ All users deleted. Now re-upload CSV.")
        # print(app.url_map)
    scheduler = BackgroundScheduler()
    scheduler.add_job(func=check_expired_permissions_and_notify, trigger="interval", minutes=2)
    scheduler.start()
    atexit.register(lambda: scheduler.shutdown())  
    app.run(host='192.168.0.104',port=5002,ssl_context='adhoc',debug=True)   