from app import app,db
from app import Faculty  # Assuming you have a User model
from werkzeug.security import generate_password_hash

# Dummy data
faculty = [
    Faculty( first_name="Shiva rama rao", last_name="Akula", email="premkumar.pragada@sasi.ac.in", dept="CIC", faculty_phone="9876543201",room_no="23101",category="HOD",  password_hash=generate_password_hash("hod@123"), photo="static/faculty/cic.png"),
    Faculty( first_name="Priya", last_name="Sharma", email="priya@example.com", dept="ECE", faculty_phone="9876543202",room_no="23102", category="HOD", password_hash=generate_password_hash("hod@123"), photo="static/faculty/cse.jpg"),
    Faculty( first_name="Arun", last_name="Verma", email="arun@example.com", dept="MECH", faculty_phone="9876543203",room_no="23103", category="HOD", password_hash=generate_password_hash("hod@123"), photo="static/faculty/csm.jpg"),
    Faculty( first_name="Sneha", last_name="Mishra", email="sneha@example.com", dept="CIVIL", faculty_phone="9876543204",room_no="23201",category="HOD", password_hash=generate_password_hash("hod@123"), photo="static/faculty/csd.jpg"),
    Faculty( first_name="Nagendra", last_name="Nadh", email="premfreefire345@gmail.com", dept="CSE", faculty_phone="9876543205",room_no="231202", category="HOD", password_hash=generate_password_hash("hod@123"), photo="static/faculty/ece.jpg"),
    Faculty( first_name="Anjali", last_name="Yadav", email="anjali@example.com", dept="CST", faculty_phone="9876543206",room_no="23203",category="HOD",  password_hash=generate_password_hash("hod@123"), photo="static/faculty/cst.jpg"),
    Faculty( first_name="Vikram", last_name="Patel", email="vikram@example.com", dept="IT", faculty_phone="9876543207",room_no="23301",  category="HOD", password_hash=generate_password_hash("hod@123"), photo="static/faculty/ect.jpg"),
    Faculty( first_name="Shanmukha", last_name="cherukuri", email="pavan.nuni@sasi.ac.in", dept="HOSTEL", faculty_phone="9876543208",room_no="23302",category="Incharge",  password_hash=generate_password_hash("incharge@123"), photo="static/faculty/incharge.jpg"),
    Faculty( first_name="Bhargava", last_name="Reddy", email="admin@sasi.ac.in", dept="ADMIN", faculty_phone="9876543209",room_no="23303",category="admin",  password_hash=generate_password_hash("admin@123"), photo="static/faculty/admin.jpg"),
    
]

# Add to database
with app.app_context():
    db.session.add_all(faculty)
    db.session.commit()
    faculty_members = Faculty.query.all()  
    for faculty in faculty_members:
        print(faculty.first_name, faculty.last_name, faculty.email, faculty.dept, faculty.category)
print("faculty added successfully!")    

