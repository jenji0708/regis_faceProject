import base64
import io
from PIL import Image
from flask import Flask, json, request, jsonify, render_template, redirect, url_for, make_response,session, flash, send_from_directory
import pymongo
import os
import face_recognition
import jwt
import cv2
import bcrypt
from werkzeug.utils import secure_filename
from werkzeug.security import check_password_hash, generate_password_hash
import numpy as np
from datetime import datetime, timedelta
from pymongo import MongoClient
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import uuid
from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt

app = Flask(__name__)
app.secret_key = 'mySuperSecretKey12345'
mongo = PyMongo(app)
bcrypt = Bcrypt(app)

# Connect to MongoDB
client = pymongo.MongoClient('mongodb://localhost:27017/')
db = client['user_database']
users_collection = db['users']

# JWT_SECRET = 'mySuperSecretKey12345!'
UPLOAD_FOLDER = './static/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# ฟังก์ชันช่วยในการสร้าง JWT
def generate_token(user_id):
    payload = {
        'user_id': user_id,
        'exp': datetime.utcnow() + timedelta(hours=2)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm='HS256')

# ฟังก์ชันช่วยในการตรวจสอบ JWT
def verify_token(token):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        return payload['user_id']
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

# Helper function to save user face data to MongoDB
def save_user_data(firstname, lastname, student_id, password, face_encodings, image_files):
     # เข้ารหัส face encodings ด้วย base64 ก่อนบันทึก
    encoded_face_data = [base64.b64encode(json.dumps(encoding).encode()).decode() for encoding in face_encodings]
    
    user_data = {
        "firstname": firstname,
        "lastname": lastname,
        "student_id": student_id,
        "password": password,  # Store the hashed password
        "face_encodings": face_encodings,
        "images": image_files
    }
    users_collection.insert_one(user_data)

@app.route('/')
def index():
    if 'user' in session:
        return redirect(url_for('home'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        try:
            user = users.find_one({'email': email})
            if user and bcrypt.check_password_hash(user['password'], password):
                # Store both email and name in session
                session['user'] = user['email']
                session['name'] = user['name']  # Add name to session
                flash("Login successful!", "success")
                return redirect(url_for('home'))
            else:
                flash("Invalid email or password", "danger")
                return redirect(url_for('login'))
        except Exception as e:
            flash(f"Error during login: {str(e)}", "danger")
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/home')
def home():
    if 'user' not in session:
        flash("Please log in to access the dashboard", "warning")
        return redirect(url_for('login'))

    try:
        user = users.find_one({'email': session['user']})
        if user:
            return render_template('home.html', user=user)
        else:
            session.clear()  # Clear invalid session
            flash("User not found. Please login again.", "danger")
            return redirect(url_for('login'))
    except Exception as e:
        flash(f"Error accessing home page: {str(e)}", "danger")
        return redirect(url_for('login'))
    
# เส้นทางสำหรับการลงทะเบียนใบหน้า
@app.route('/register_face', methods=['GET', 'POST'])
def register_face():
    if request.method == 'POST':
        firstname = request.form['name']
        lastname = request.form['surname']
        student_id = request.form['student_id']

        # จัดการการอัปโหลดรูปภาพ
        images = {
            "front": request.files['imageFront'],
            "left": request.files.get('imageLeft'),
            "right": request.files.get('imageRight')
        }

        face_encodings = []
        image_files = []

        for view, file in images.items():
            if file:
                filename = secure_filename(f"{student_id}_{view}.jpg")
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)

                # ตรวจสอบประเภทของไฟล์ภาพ
                if not file.mimetype.startswith('image/'):
                    return jsonify({"message": f"The file for {view} is not a valid image."}), 400

                # ประมวลผลภาพและรับค่า face encoding
                image = face_recognition.load_image_file(file_path)
                encoding = face_recognition.face_encodings(image)

                if len(encoding) == 0:
                    return jsonify({"message": f"No face detected in the {view} image. Please upload a clear image."}), 400
                
                face_encodings.append(encoding[0].tolist())
                image_files.append(filename)

        # บันทึกข้อมูลลง MongoDB
        user_data = {
            "firstname": firstname,
            "lastname": lastname,
            "student_id": student_id,
            "face_encodings": face_encodings,
            "images": image_files
        }
        users_collection.insert_one(user_data)

        # เปลี่ยนเส้นทางไปยังหน้าเปรียบเทียบใบหน้า
        return redirect(url_for('compare_face'))
    else:
        return render_template('upload_face.html')


# @app.route('/register', methods=['POST'])
# def register_user():
#     student_id = request.form['studentID']
#     email = request.form['email']
#     password = request.form['password']
#     confirm_password = request.form['confirmPassword']

#     if password != confirm_password:
#         return jsonify({'message': 'Passwords do not match'}), 400

#     # เข้ารหัสรหัสผ่านก่อนบันทึกลงในฐานข้อมูล
#     hashed_password = generate_password_hash(password)

#     # ตรวจสอบว่าผู้ใช้มีอยู่แล้วในฐานข้อมูลหรือไม่
#     if users_collection.find_one({"student_id": student_id}):
#         return jsonify({'message': 'User already exists'}), 400

#     # บันทึกข้อมูลผู้ใช้ลงใน MongoDB
#     user_data = {
#         "student_id": student_id,
#         "email": email,
#         "password": hashed_password  # บันทึกเป็น hashed password
#     }
#     users_collection.insert_one(user_data)
#     return redirect(url_for('login_page'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirmPassword')
        
        if password != confirm_password:
            flash("Passwords do not match!", "danger")
            return redirect(url_for('register'))

        # Check if email already exists
        if mongo.db.users.find_one({'email': email}):
            flash("Email already registered", "danger")
            return redirect(url_for('register'))

        # Hash the password before saving
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        # Insert the user into the MongoDB database
        mongo.db.users.insert_one({
            'name': name,
            'email': email,
            'password': hashed_password
        })

        flash("Registration successful! Please login.", "success")
        return redirect(url_for('login'))

    return render_template('register.html')


# เส้นทางสำหรับการเข้าสู่ระบบ
# @app.route('/auth/login', methods=['POST'])
# def login():
#     student_id = request.form['studentID']
#     password = request.form['password']

#     # ดึงข้อมูลผู้ใช้จากฐานข้อมูลตาม student_id
#     user = users_collection.find_one({"student_id": student_id})

#     # ตรวจสอบว่าผู้ใช้มีอยู่และรหัสผ่านถูกต้อง
#     if user and check_password_hash(user['password'], password):  # ตรวจสอบรหัสผ่านที่ถูกเข้ารหัส
#         token = generate_token(user['student_id'])
#         response = make_response(redirect(url_for('home')))
#         response.set_cookie('jwt_token', token)  # เก็บ JWT token ใน cookies
#         return response
#     else:
#         return render_template('login.html', message='Invalid credentials'), 401
# ฟังก์ชันการเข้าสู่ระบบ

@app.route('/edit/<student_id>', methods=['POST'])
def edit_user(student_id):
    user = users_collection.find_one({"student_id": student_id})
    
    if not user:
        return jsonify({"message": "User not found"}), 404
    
    new_name = request.form['name']
    new_surname = request.form['surname']

    # Update user data
    update_data = {
        "firstname": new_name,
        "lastname": new_surname
    }
    
    if 'imageFront' in request.files:
        front_image = request.files['imageFront']
        filename = secure_filename(f"{student_id}_front.jpg")
        front_image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        
        # Update face encoding
        image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        image = face_recognition.load_image_file(image_path)
        encoding = face_recognition.face_encodings(image)
        
        if encoding:
            update_data["face_encodings"] = [encoding[0].tolist()]
            update_data["images"] = [filename]
    
    users_collection.update_one({"student_id": student_id}, {"$set": update_data})
    return redirect(url_for('home'))

# เส้นทางสำหรับการตรวจสอบใบหน้า
@app.route('/compare_face', methods=['GET', 'POST'])
def compare_face():
    if request.method == 'POST':
        if 'image' in request.files:
            # รับภาพที่ถูกส่งมาเป็น multipart/form-data
            image_data = request.files['image']
            # แปลงเป็นภาพและตรวจสอบใบหน้า
            image = face_recognition.load_image_file(image_data)
        elif 'image' in request.form:
            # รับข้อมูลภาพที่ส่งมาในรูปแบบ base64
            image_data = request.form.get('image')
            # แปลง base64 เป็นไฟล์ภาพ
            image_bytes = base64.b64decode(image_data.split(',')[1])
            image = Image.open(io.BytesIO(image_bytes))
            image = np.array(image)
        else:
            return jsonify({"message": "No image data provided."}), 400

        # ตรวจสอบใบหน้าในภาพที่รับมา
        face_encodings = face_recognition.face_encodings(image)

        if len(face_encodings) == 0:
            return jsonify({"message": "No face detected. Please try again."}), 400

        encoding_to_check = face_encodings[0]

        # เปรียบเทียบใบหน้ากับฐานข้อมูล
        users = users_collection.find()
        for user in users:
            for known_encoding in user['face_encodings']:
                matches = face_recognition.compare_faces([np.array(known_encoding)], encoding_to_check)
                if matches[0]:
                    return jsonify({'message': f"Face matched! Welcome {user['firstname']}!"}), 200

        return jsonify({'message': 'No matching face found.'}), 400
    else:
        # แสดงหน้า compare_face.html สำหรับคำขอ GET
        return render_template('compare_face.html')

# เส้นทางสำหรับ Logout
# @app.route('/auth/logout', methods=['GET'])
# def logout():
#     response = make_response(redirect(url_for('login_page')))
#     response.delete_cookie('jwt_token')  # ลบ JWT token ใน cookies
#     return response

@app.route('/profile', methods=['GET'])
def profile():
    token = request.headers.get('Authorization')

    if not token:
        return jsonify({'message': 'Token is missing!'}), 403

    try:
        decoded_token = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user_id = decoded_token['user_id']
        user = users_collection.find_one({'_id': user_id})

        if not user:
            return jsonify({'message': 'User not found!'}), 404

        return jsonify({'username': user['username'], 'faces': user['faces']}), 200
    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Token has expired!'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid token!'}), 401


# เส้นทางสำหรับหน้า Login
@app.route('/login')
def login_page():
    return render_template('login.html')

# เส้นทางสำหรับหน้า Register
@app.route('/register', methods=['GET'])
def register_page():
    return render_template('register.html')

# Serve the header (if included dynamically)
@app.route('/header.html')
def header():
    return render_template('header.html')
# เส้นทางสำหรับหน้า gra-Inv
@app.route('/gra-Inv')
def gra_inv():
    return render_template('gra-Inv.html')

# เส้นทางสำหรับหน้า showInformation
@app.route('/showInformation')
def show_information():
    return render_template('showInformation.html')

# เส้นทางสำหรับหน้า Address
@app.route('/address', methods=['GET', 'POST'])
def address():
    if request.method == 'POST':
        # จัดการข้อมูลที่ได้รับจากฟอร์มที่อยู่
        # เช่น การบันทึกที่อยู่ลงในฐานข้อมูล
        return redirect(url_for('home'))
    return render_template('address.html')

@app.route('/upload_face', methods=['POST'])
def upload_face():
    # ตรวจสอบการอัปโหลดไฟล์
    file = request.files.get('file')
    if not file:
        return jsonify({'message': 'No file uploaded!'}), 400

    # อ่านภาพจากไฟล์ที่อัปโหลด
    img = face_recognition.load_image_file(file)
    face_locations = face_recognition.face_locations(img)

    # หากไม่พบใบหน้า
    if not face_locations:
        return jsonify({'message': 'No face detected!'}), 400

    # บันทึกข้อมูลใบหน้า
    encoded_face = face_recognition.face_encodings(img)[0].tolist()  # การแปลงข้อมูลเป็น JSON ที่สามารถจัดเก็บได้
    username = request.form.get('username')

    # อัปเดตข้อมูลใบหน้าผู้ใช้ในฐานข้อมูล
    users_collection.update_one(
        {'username': username},
        {'$push': {'faces': encoded_face}}
    )

    return jsonify({'message': 'Face uploaded successfully!'}), 200

@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        email = request.form['email']
        user = users.find_one({'email': email})
        if user:
            token = str(uuid.uuid4())
            reset_tokens[token] = email

            # Placeholder for email sending (you could implement an alternative)
            # For now, we just simulate sending a reset link
            print(f"Reset link (placeholder): {url_for('new_password', token=token, _external=True)}")

        return "If the email exists, a reset link has been sent!"

    return render_template('reset_password.html')

@app.route('/new-password', methods=['GET', 'POST'])
def new_password():
    token = request.args.get('token') or request.form.get('token')
    email = reset_tokens.get(token)

    if not email:
        return "Invalid or expired token", 400

    if request.method == 'POST':
        password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
        users.update_one({'email': email}, {'$set': {'password': password}})
        reset_tokens.pop(token, None)
        return redirect(url_for('login'))

    return render_template('new_password.html', token=token)
@app.route('/edit-profile', methods=['GET', 'POST'])
def edit_profile():
    if 'user' not in session:
        flash("Please log in to edit your profile", "warning")
        return redirect(url_for('login'))

    try:
        user = users.find_one({'email': session['user']})
        if not user:
            flash("User not found", "danger")
            return redirect(url_for('login'))

        if request.method == 'POST':
            new_name = request.form.get('name')
            new_email = request.form.get('email')

            # Validate inputs
            if not new_name:
                flash("Name cannot be empty", "danger")
                return redirect(url_for('edit_profile'))

            if new_email != user['email']:  # Only check if email is being changed
                # Check if new email already exists
                if users.find_one({'email': new_email}):
                    flash("Email already exists", "danger")
                    return redirect(url_for('edit_profile'))

            # Update user information
            update_data = {}
            if new_name:
                update_data['name'] = new_name
            if new_email:
                update_data['email'] = new_email
                session['user'] = new_email  # Update session with new email

            if update_data:
                users.update_one(
                    {'email': user['email']}, 
                    {'$set': update_data}
                )
                flash("Profile updated successfully!", "success")
            
            return redirect(url_for('profile'))

        return render_template('edit_profile.html', user=user)

    except Exception as e:
        flash(f"Error updating profile: {str(e)}", "danger")
        return redirect(url_for('profile'))
    
@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)


