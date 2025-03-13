from app import app,db
from app import User  # Assuming you have a User model
from werkzeug.security import generate_password_hash

# Dummy data
students = [
    User(regd="22K61A4701", first_name="Nani Prasad", last_name="Arella", email="naniprasad.arella@sasi.ac.in", dept="ECT", student_phone="9876543201", parent_phone="8765432101", address="Hyderabad", password="22K61A4701", photo="static/uploads/22K61A4701.jpg",category="Student"),
    User(regd="22K61A4702", first_name="Naga Sai Shanmukha", last_name="Cherukuri", email="shanmukha.cherukuri@sasi.ac.in", dept="CIC", student_phone="8074034329", parent_phone="6304079895", address="Anakapalli", password="22K61A4702", photo="static/uploads/22K61A4702.jpg",category="Student"),
    User(regd="22K61A4703", first_name="Sindhu Abhirami", last_name="Kunireddy", email="sindhu.kunireddy@sasi.ac.in", dept="CIC", student_phone="8106549566", parent_phone="8500468609", address="Rajahmundry", password="22K61A4703", photo="static/uploads/22K61A4713.jpg",category="Student"),
    User(regd="22K61A4704", first_name="Monika", last_name="Eluri", email="monika.eluri@sasi.ac.in", dept="CIC", student_phone="7671035752", parent_phone="9949329157", address="Kadiyadda", password="22K61A4704", photo="static/uploads/22K61A4704.jpg",category="Student"),
    User(regd="22K61A4705", first_name="Suvarna", last_name="Enugu", email="suvarna.enugu@sasi.ac.in", dept="CIC", student_phone="9704953023", parent_phone="8106076204", address="Arugolanu", password="22K61A4705", photo="static/uploads/22K61A4705.jpg",category="Student"),
    User(regd="22K61A4706", first_name="Sindhu Bhargavi", last_name="Garapati", email="bhargavi.garapati@sasi.ac.in", dept="CIC", student_phone="9502917209", parent_phone="9502581112", address="Nidadavole", password="22K61A4706", photo="static/uploads/22K61A4706.jpg",category="Student"),
    User(regd="22K61A4707", first_name="Ganapathi", last_name="Itakula", email="ganapathi.itakula@sasi.ac.in", dept="CIC", student_phone="9550987918", parent_phone="9885837349", address="Relangi", password="22K61A4707", photo="static/uploads/22K61A4707.jpg",category="Student"),
    User(regd="22K61A4708", first_name="Subhash", last_name="Naidu", email="subhash.naidu@sasi.ac.in", dept="CIC", student_phone="9640038330", parent_phone="9640038332", address="Pothavaram", password="22K61A4708", photo="static/uploads/22K61A4708.jpg",category="Student"),
    User(regd="22K61A4709", first_name="Pavan Venkata Kumar", last_name="Nuni", email="pavan.nuni@sasi.ac.in", dept="CIC", student_phone="7337224253", parent_phone="7337294253", address="Chodavaram", password="22K61A4709", photo="static/uploads/22K61A4709.jpg",category="Student"),
    User(regd="22K61A4710", first_name="Prem Kumar", last_name="Pragada", email="premkumar.pragada@sasi.ac.in", dept="CSE" ,student_phone="9440963616", parent_phone="9440963616", address="Tanuku", password="22K61A4710", photo="static/uploads/22K61A4710.jpg",category="Student"),
    User(regd="22K61A4711", first_name="Dhana Kishore", last_name="Gummala", email="kishore.gummalla@sasi.a.in", dept="CIC", student_phone="7893715148", parent_phone="7893715148", address="Undrajavaram", password="22K61A4711", photo="static/uploads/22K61A4711.jpg",category="Student"),
    User(regd="22K61A4712", first_name="Pooja", last_name="Vema", email="pooja.vema@sasi.ac.in", dept="CSE-B", student_phone="9876543212", parent_phone="8765432112", address="Jaipur", password="22K61A4712", photo="static/uploads/22K61A4712.jpg",category="Student"),
    User(regd="22K61A4713", first_name="Vishnu Vardhan", last_name="Muramulla", email="vishnu.muramulla@sasi.ac.in", dept="CSE-A", student_phone="7075685064", parent_phone="7075685064", address="Rajahmundry", password="22K61A4713", photo="static/uploads/22K61A4714.jpg",category="Student"),
    User(regd="22K61A4714", first_name="Venkat", last_name="Thummalapalli", email="venkat.tummulapalli@sasi.ac.in", dept="MECH", student_phone="9876543215", parent_phone="8765432115", address="Pothavaram", password="22K61A4714", photo="static/uploads/22K61A4715.jpg",category="Student"),
    User(regd="22K61A4715", first_name="Harish", last_name="Subbu", email="harish.sabbu@sasi.ac.in", dept="CIVIL", student_phone="8121929288", parent_phone="9959732599", address="Thanuku", password="22K61A4715", photo="static/uploads/22K61A4716.jpg",category="Student"),
    User(regd="22K61A4716", first_name="Chanikya Akkaiah", last_name="Kolli", email="chanikya.kolli@sasi.ac.in", dept="CST", student_phone="9391722533", parent_phone="9391722533", address="Gudipadu", password="22K61A4716", photo="static/uploads/22K61A4717.jpg",category="Student"),
]

# Add to database
with app.app_context():
    db.session.add_all(students)
    db.session.commit()

print("Students added successfully!")


