from sqlite3 import IntegrityError
from flask import Flask, redirect, url_for, render_template, request, session, flash
import sys
import hashlib
import uuid
import binascii
import os
import json
import random
from datetime import timedelta, datetime
from flask_sqlalchemy import SQLAlchemy
import configparser
from sqlalchemy import text


app = Flask(__name__)



config = configparser.ConfigParser()
config.read('config.ini')

database_filename = config['DATABASE']['filename']
database_path = os.path.join(os.path.dirname(__file__), database_filename)
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{database_path}"

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.secret_key = "WziLNrfRES7L+964Q3vDnIhkqWgKxf9PFjBm1iwiiu1ZWH9lScgPdy7oyGZkcx4668sV/lkQd4YFg8JX/Pn9Fg=="
portchoice = config['FLASK']['port']



with app.app_context():
    db = SQLAlchemy(app)
    db.create_all()


# Database Initializations

class patients(db.Model):
    _id = db.Column("id", db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    dob = db.Column(db.String(8))
    gender = db.Column(db.String(10))
    address = db.Column(db.String(255))
    phone = db.Column(db.String(8))
    email = db.Column(db.String(100))
    age = db.Column(db.Integer)
    medicalhistory = db.Column(db.String(100))
    currentsymptoms = db.Column(db.String(100))
    currentmedicines = db.Column(db.String(100))
    doctorname = db.Column(db.String(100))
    doctorprescription = db.Column(db.String(100))

    def __init__(self, name, dob, gender, address, phone, email,age,medicalhistory,currentsymptoms,currentmedicines,doctorname,doctorprescription):
        self.name = name
        self.dob = dob
        self.gender = gender
        self.address = address
        self.phone = phone
        self.email = email
        self.age= age
        self.medicalhistory=medicalhistory
        self.currentsymptoms= currentsymptoms
        self.currentmedicines= currentmedicines
        self.doctorname = doctorname
        self.doctorprescription = doctorprescription

class users(db.Model):
    _id = db.Column("id", db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    fullname = db.Column(db.String(100))
    pwdsalt = db.Column(db.String(100))
    pwdhash = db.Column(db.String(100))
    email = db.Column(db.String(100))

    def __init__(self, name, pwdsalt, pwdhash, email):
        self.name = name
        self.pwdsalt = pwdsalt
        self.pwdhash = pwdhash
        self.email = email

class doctor(db.Model):
    doctorid = db.Column(db.String(100))
    pwdsalt = db.Column(db.String(100))
    pwdhash = db.Column(db.String(100))
    id = db.Column("id", db.Integer, primary_key=True)

    def __init__(self, doctorid, pwdsalt, pwdhash):
        self.doctorid = doctorid
        self.pwdsalt = pwdsalt
        self.pwdhash = pwdhash

class privileges(db.Model):
    user = db.Column(db.String(100), db.ForeignKey(
        "users.name"), primary_key=True)
    priv = db.Column(db.String(100), primary_key=True)

    def __init__(self, user, priv):
        self.user = user
        self.priv = priv

class doctor_patients(db.Model):
    doctor = db.Column(db.String(100), db.ForeignKey("users.name"), primary_key=True)
    patient = db.Column(db.String(100), primary_key=True)

    def __init__(self, doctor, patient):
        self.doctor = doctor
        self.patient = patient

class patient_notes(db.Model):
    _id = db.Column("id", db.Integer, primary_key=True)
    patient = db.Column(db.Integer, db.ForeignKey("patients.id"))
    note = db.Column(db.String(1000))

    def __init__(self, patient, note):
        self.patient = patient
        self.note = note


port = 8000 if len(sys.argv) == 1 else sys.argv[1]

# Routes & their logics

@app.errorhandler(404)
def page_not_found(e):
    flash("Error 404, page does not exist!")
    return redirect(url_for("user"))

@app.route("/")
def home():
    if "user" in session:
        return redirect(url_for("index"))
    return redirect(url_for("index"))

@app.route("/index")
def index():
    return render_template("index.html")

@app.route("/register", methods=["POST", "GET"])
def register():
    if "user" in session:
        flash("You are already logged in!")
        return redirect(url_for("user"))

    if request.method == "POST":
        user = request.form.get("nm")
        pwa = request.form.get("pwa")
        pwb = request.form.get("pwb")

        if (user == "") or (pwa == "") or (pwb == ""):
            flash("Please complete all fields.")
            return redirect(url_for("register"))

        if pwa != pwb:
            flash("Passwords do not match!")
            return redirect(url_for("register"))

        if users.query.filter_by(name=user).first():
            flash("Username taken!")
            return redirect(url_for("register"))

        session["user"] = user
        hashed_pw = hash_password(pwa)
        usr = users(user, hashed_pw["salt"], hashed_pw["pwdhash"], None)
        db.session.add(usr)
        db.session.commit()

        flash("Registration successful")
        return redirect(url_for("user"))

    else:
        return render_template("register.html")
    

@app.route("/registerdoctor", methods=["POST", "GET"])
def registerdoctor():
    if "user" in session:
        flash("You are already logged in!")
        return redirect(url_for("user"))

    if request.method == "POST":
        doctorid = request.form.get("inputdoctorid")
        inputdoctorpassword1 = request.form.get("inputdoctorpassword1")
        inputdoctorpassword2 = request.form.get("inputdoctorpassword2")

        if (doctorid == "") or (inputdoctorpassword1 == "") or (inputdoctorpassword2 == ""):
            flash("Please complete all fields.")
            return redirect(url_for("registerdoctordoctor"))

        if inputdoctorpassword1 != inputdoctorpassword2:
            flash("Passwords do not match!")
            return redirect(url_for("registerdoctor"))

        if doctor.query.filter_by(doctorid=doctorid).first():
            flash("ID taken!")
            return redirect(url_for("registerdoctor"))

        session["user"] = doctorid
        hashed_pw = hash_password(inputdoctorpassword1)
        usr = doctor(doctorid, hashed_pw["salt"], hashed_pw["pwdhash"],)
        db.session.add(usr)
        db.session.commit()

        flash("Registration successful")
        return redirect(url_for("user"))

    else:
        return render_template("registerdoctor.html")

@app.route("/patients", methods=["POST","GET"])
def patients_page():
    if "user" not in session:
        flash("Please login first!")
        return redirect(url_for("login"))
    admin=session['user']
    myquery = text("SELECT doctorid FROM doctor WHERE doctorid = :admin")
    result = db.session.execute(myquery, {'admin': admin})
    rows = result.fetchall()
    try:
        if not admin=='admin' and not admin==rows[0][0]:
            if not check_privilege(session["user"], "view_patients"):
                flash("You do not have permission to view this page!")
                return redirect(url_for("user"))
    except IndexError:
        flash("You do not have permission to view this page!")
        return redirect(url_for("user"))
    # print(session['user'])
    # if not check_privilege(session["user"], "view_patients"):
    #         flash("You do not have permission to view this page!")
    #         return redirect(url_for("user"))
    if request.method == "POST":
        name = request.form.get("name")
        dob = request.form.get("dob")
        gender = request.form.get("gender")
        address = request.form.get("address")
        phone = request.form.get("phone")
        email = request.form.get("email")
        age = request.form.get("age")
        medicalhistory = request.form.get("medical")
        currentsymptoms = request.form.get("currentsymptoms")
        currentmedicines = request.form.get("currentmedicines")
        doctorname = request.form.get("doctorname")
        doctorprescription = request.form.get("doctorprescription")

        add_patient(name, dob, gender, address, phone, email,age,medicalhistory,currentsymptoms,currentmedicines,doctorname,doctorprescription)


    return render_template("patients.html", patients=get_patients())

@app.route("/login", methods=["POST", "GET"])
def login():
    if request.method == "POST":

        user = request.form["nm"]
        pwd = request.form.get("pwd")
        remember = request.form.get("rmb")

        found_user = users.query.filter_by(name=user).first()
        found_doctor = doctor.query.filter_by(doctorid=user).first()
        found_admin = users.query.filter_by(name='admin').first()

        if found_user:
            hashed_pw = {
                "salt": found_user.pwdsalt,
                "pwdhash": found_user.pwdhash
            }
            if verify_password(hashed_pw, pwd):

                flash("Login Successful!")
                session["user"] = user
                return redirect(url_for("user"))
            
        if found_doctor:
            hashed_pw = {
                "salt": found_doctor.pwdsalt,
                "pwdhash": found_doctor.pwdhash
            }
            if verify_password(hashed_pw, pwd):

                flash("Login Successful!")
                session["user"] = user
                return redirect(url_for("patients_page"))
            
        if found_admin:
            hashed_pw = {
                "salt": found_admin.pwdsalt,
                "pwdhash": found_admin.pwdhash
            }
            if verify_password(hashed_pw, pwd):

                flash("Login Successful!")
                session["user"] = user
                return redirect(url_for("patients"))

        flash("Invalid details")
        return redirect(url_for("login"))

    else:
        if "user" in session:
            flash("You are already logged in!")
            return redirect(url_for("user"))

        return render_template("login.html")

@app.route("/logout")
def logout():
    if not "user" in session:
        return redirect(url_for("login"))
    session.pop("user", None)
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))

@app.route("/usernew")
def usernew():
    return render_template("userpage_new.html")

@app.route("/user", methods=["POST", "GET"])
def user():
    email = None
    if "user" in session:
        user = session["user"]
        values = query_privileges(user)

        return render_template("user.html", user=user, email=email, values=values)
    else:
        flash("You are not logged in!")
        return redirect(url_for("login"))

@app.route("/view/")
def view():
    if not check_privilege(session["user"], "view"):
        flash("You do not have permission to view this page!")
        return redirect(url_for("user"))

    values = list_users_and_privs()
    print(values)
    return render_template("view.html", values=values)

@app.route("/test")
def test():
    return render_template("new.html")

@app.route("/manageusers/", methods=["POST", "GET"])
def manageusers():
    if not check_privilege(session["user"], "manageusers"):
        flash("You do not have permission to view this page!")
        return redirect(url_for("user"))
    
    if request.method == "POST":
        user = request.form.get("user")
        
        print(user)
        return redirect("/manageusers/"+user)
    else:
        return render_template("manage_users.html", users=get_users())
    
@app.route("/manageusers/<user>", methods=["POST", "GET"])
def manageusers1(user):
    if not check_privilege(session["user"], "manageusers"):
        flash("You do not have permission to view this page!")
        return redirect(url_for("user"))
    if request.method == "POST":
        priv = request.form.get("priv")
        if (priv == ""):
            flash("Please complete all fields.")
            return redirect("/manageusers/"+user)
        add_privilege(user, priv)
        flash("Privilege "+priv+" added to user "+user+" successfully!")
        return redirect("/manageusers/"+user)
    else:
        return render_template("manage_user.html", user=user, privs=query_privileges(user))

@app.route("/patients/<pid>", methods=["POST", "GET"])
def patient_page(pid):
    patient = get_patient(pid)
    medical_notes = get_notes(pid)
    if request.method == "POST":
        note = request.form.get("note")
        add_note(int(pid), note)
        return redirect("/patients/"+pid)

    if patient != None:
        return render_template("patient.html", medical_notes=medical_notes, patient=patient)
    

@app.route("/ap/<user>/<priv>")
def addprivy(user, priv):
    priv = privileges(user, priv)
    db.session.add(priv)
    db.session.commit()

    return redirect(url_for(user))

@app.route("/removepriv/<user>/<priv>")
def removepriv(user, priv):
    if not check_privilege(session["user"], "manageusers"):
        flash("You do not have permission to view this page!")
        return redirect(url_for("user"))

    remove_privilege(user, priv)
    flash("Privilege "+priv+" removed from user "+user+" successfully!")
    return redirect("/manageusers/"+user)

# Database Queries aka definitions

def list_users_and_privs():
    result = users.query.all()
    formatted_result = []
    for i in result:
        print(i)
        formatted_result.append([i.name, query_privileges(i.name)])
    return formatted_result


def query_privileges(user):  # Returns a list of privileges for a given user
    j = db.join(users, privileges, users.name ==
                privileges.user)  # Join creation
    stmt = db.select(privileges.priv).select_from(
        j).where(users.name == user)  # create Query
    result = db.session.execute(stmt).all()
    formatted_result = [i[0] for i in result]
    return formatted_result

def check_privilege(user, privilege):
    user_privileges = query_privileges(user)
    if privilege in user_privileges:
        return True
    return False

def get_patient(id):
    result = patients.query.filter_by(_id=id).first()
    return result

def get_users():
    result = users.query.all()
    formatted_result = [i.name for i in result]
    return formatted_result

def get_patients():
    result = patients.query.all()
    return result

def get_notes(id):
    result = patient_notes.query.filter_by(patient=id).all()
    return result

def add_patient(name, dob, gender, address, phone,email,age,medicalhistory,currentsymptoms,currentmedicines,doctorname,doctorprescription):
    patient = patients(name, dob, gender, address, phone,email,age,medicalhistory,currentsymptoms,currentmedicines,doctorname,doctorprescription)
    db.session.add(patient)
    db.session.commit()

def add_note(patient, note):
    note = patient_notes(patient, note)
    db.session.add(note)
    db.session.commit()

def add_privilege(user, priv):
    priv = privileges(user, priv)
    db.session.add(priv)
    db.session.commit()

def remove_privilege(user, priv):
    priv = privileges.query.filter_by(user=user, priv=priv).first()
    db.session.delete(priv)
    db.session.commit()


# Password hashing functions


def hash_password(password):

    salt = binascii.b2a_base64(hashlib.sha256(os.urandom(60)).digest()).strip()
    pwdhash = binascii.b2a_base64(hashlib.pbkdf2_hmac(
        'sha256', password.encode('utf-8'), salt, 10000)).strip().decode()
    return {'salt': salt.decode(), 'pwdhash': pwdhash}


def verify_password(stored_password, provided_password):

    pwdhash = hashlib.pbkdf2_hmac('sha256',
                                  provided_password.encode('utf-8'),
                                  stored_password['salt'].encode(),
                                  10000)
    return pwdhash == binascii.a2b_base64(stored_password['pwdhash'])


if __name__ == "__main__":
    with app.app_context():

        #db.create_all()

        app.run(
            debug=True,
            host='0.0.0.0',
            port=port)