from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash, send_from_directory
import numpy as np
import json
from pymongo import MongoClient
from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt
from werkzeug.utils import secure_filename
import os
import bcrypt
import cv2
import face_recognition
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import uuid
from bson import ObjectId
import base64
from io import BytesIO
from PIL import Image
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

app = Flask(__name__)
app.config["MONGO_URI"] = "mongodb://localhost:27017"

jwt = JWTManager(app)
# Database Configuration
client = MongoClient("mongodb://localhost:27017/")
db = client['face_registration_db']
users_collection = db['users']
collection = db["addresses"] 
# MongoDB configuration
app.config["UPLOAD_FOLDER"] = "uploads"
app.secret_key = os.urandom(24)

# Allowed image extensions
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}

# Helper function to check allowed extensions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# Password Hashing
bcrypt = Bcrypt(app)
mongo = PyMongo(app)

# Set the upload folder path
UPLOAD_FOLDER = './static/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
@app.after_request
def add_header(response):
    # Disable caching for static files (adjust as needed)
    response.cache_control.no_store = True
    return response

@app.route('/static/<path:path>')
def send_static(path):
    return send_from_directory(app.static_folder, path)

# A placeholder for the reference face(s)
reference_face_encoding = None

# Upload Folder
# UPLOAD_FOLDER = os.path.join('static', 'uploads')
# app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Helper function to save user face data to MongoDB
def save_user_data(firstname, lastname, student_id, password, face_encodings, image_files):
    # Encoding face encodings to base64
    encoded_face_data = [base64.b64encode(json.dumps(encoding.tolist()).encode()).decode() for encoding in face_encodings]

    user_data = {
        "firstname": firstname,
        "lastname": lastname,
        "student_id": student_id,
        "password": password,  # Store the hashed password
        "face_encodings": encoded_face_data,
        "images": image_files
    }
    users_collection.insert_one(user_data)

@app.route('/upload_face', methods=['POST'])
def upload_face():
    # รับและบันทึกภาพจากฟอร์ม
    files = ['imageFront', 'imageLeft', 'imageRight']
    face_encodings = []

    for file_key in files:
        uploaded_file = request.files[file_key]
        if uploaded_file and allowed_file(uploaded_file.filename):
            filename = secure_filename(uploaded_file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            uploaded_file.save(file_path)
            # ตรวจจับใบหน้า
            image = face_recognition.load_image_file(file_path)
            encodings = face_recognition.face_encodings(image)
            if encodings:
                face_encodings.append(encodings[0])
    
    if len(face_encodings) == 3:  # หากพบใบหน้าทั้ง 3 ภาพ
        # บันทึกข้อมูลใบหน้า
        users_collection.insert_one({
            'name': request.form['name'],
            'surname': request.form['surname'],
            'student_id': request.form['student_id'],
            'face_encodings': [enc.tolist() for enc in face_encodings]
        })
        return redirect(url_for('compare_face'))
    else:
        flash('Please upload clear images of your face.')
        return redirect(url_for('upload_face'))

@app.route('/register_face', methods=['GET', 'POST'])
def register_face():
    if request.method == 'POST':
        name = request.form.get('name')
        student_id = request.form.get('student_id')
        email = request.form.get('email')

        # Check if all required images are uploaded
        front_image = request.files.get('imageFront')
        left_image = request.files.get('imageLeft')
        right_image = request.files.get('imageRight')

        # Create upload directory if not exists
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

        # Save image paths
        front_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(front_image.filename))
        left_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(left_image.filename))
        right_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(right_image.filename))

        # Save images
        front_image.save(front_path)
        left_image.save(left_path)
        right_image.save(right_path)

        # Extract face encodings
        face_encodings = []
        image_paths = [front_path, left_path, right_path]

        for image_path in image_paths:
            image = face_recognition.load_image_file(image_path)
            encodings = face_recognition.face_encodings(image)
            
            if not encodings:
                flash("Could not detect face in one of the images.", "danger")
                return redirect(url_for('register_face'))
            
            face_encodings.append(encodings[0].tolist())

        # Save user data with face encodings
        user_data = {
            "name": name,
            "student_id": student_id,
            "email": email,
            "images": image_paths,
            "face_encodings": face_encodings
        }
        users_collection.insert_one(user_data)

        # Set session for face verification
        session['registration_student_id'] = student_id
        
        return redirect(url_for('compare_face'))

    return render_template('upload_face.html')

@app.route('/compare_face', methods=['GET', 'POST'])
def compare_face():
    # Validate user's authentication or registration process
    if 'user' not in session and 'registration_student_id' not in session:
        flash("Please log in or complete registration", "warning")
        return redirect(url_for('login'))

    if request.method == 'POST':
        image_data = request.form.get('image')
        
        if not image_data:
            app.logger.error("No image provided")
            return jsonify({"message": "No image provided"}), 400

        try:
            # Strip base64 metadata (e.g., data:image/jpeg;base64,)
            image_bytes = base64.b64decode(image_data.split(',')[1])
            image = Image.open(BytesIO(image_bytes))
            image_np = np.array(image)

            # Detect face encodings in the image
            face_encodings = face_recognition.face_encodings(image_np)

            if not face_encodings:
                app.logger.warning("No face detected in the image")
                return jsonify({"message": "No face detected"}), 400

            encoding_to_check = face_encodings[0]
            app.logger.debug(f"Detected face encodings: {encoding_to_check}")

            # Check if in registration process
            if 'registration_student_id' in session:
                student_id = session['registration_student_id']
                app.logger.debug(f"Registration process for student_id: {student_id}")
                # Replace with your actual MongoDB collection
                user = users_collection.find_one({"student_id": student_id})

                if user and 'face_encodings' in user:
                    known_encodings = [np.array(enc) for enc in user['face_encodings']]
                    matches = face_recognition.compare_faces(known_encodings, encoding_to_check)
                    
                    if any(matches):
                        session.pop('registration_student_id', None)  # Clear registration session
                        app.logger.info(f"Face matched successfully for student_id: {student_id}")
                        return jsonify({"message": "Registration Matched"}), 200
                    else:
                        app.logger.warning("Face not matching registration")
                        return jsonify({"message": "Face not matching registration"}), 400

            # Regular login comparison if registration not in progress
            app.logger.debug("Performing regular login comparison")
            return jsonify({"message": "No match found"}), 400

        except Exception as e:
            app.logger.error(f"Error processing face verification: {str(e)}")
            return jsonify({"message": f"Error: {str(e)}"}), 500

    return render_template('compare_face.html')

    
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
            user = users_collection.find_one({'email': email})
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
        user = users_collection.find_one({'email': session['user']})
        if user:
            return render_template('home.html', user=user)
        else:
            session.clear()  # Clear invalid session
            flash("User not found. Please login again.", "danger")
            return redirect(url_for('login'))
    except Exception as e:
        flash(f"Error accessing home page: {str(e)}", "danger")
        return redirect(url_for('login'))
    
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name')
        if not name:
            flash("Name is required", "danger")
            return redirect(url_for('register'))
        
        email = request.form['email']
        
        # Check if email already exists
        if users_collection.find_one({'email': email}):
            flash("Email already registered", "danger")
            return redirect(url_for('register'))

        password = request.form['password']
        confirm_password = request.form['confirm-password']

        # Check if passwords match
        if password != confirm_password:
            flash("Passwords do not match", "danger")
            return redirect(url_for('register'))

        password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

        # Save to MongoDB without image processing
        try:
            users_collection.insert_one({
                'name': name,
                'email': email,
                'password': password_hash,
            })
            flash("Registration successful! Please login.", "success")
            return redirect(url_for('login'))
        except Exception as e:
            flash(f"Error during registration: {str(e)}", "danger")
            return redirect(url_for('register'))

    return render_template('register.html')


@app.route('/profile', methods=['GET'])
def profile():
    if 'user' not in session:
        flash("Please log in to access your profile", "warning")
        return redirect(url_for('login'))

    user = users_collection.find_one({'email': session['user']})
    return render_template('profile.html', user=user)

# Route for password reset page
@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        email = request.form['email']
        user = mongo.db.users.find_one({'email': email})

        if user:
            # Send reset email logic (simplified)
            msg = MIMEMultipart()
            msg['From'] = 'your_email@example.com'
            msg['To'] = email
            msg['Subject'] = 'Password Reset'
            body = "Click the link to reset your password: [Reset Link]"
            msg.attach(MIMEText(body, 'plain'))
            
            try:
                with smtplib.SMTP('smtp.example.com', 587) as server:
                    server.starttls()
                    server.login('your_email@example.com', 'your_password')
                    text = msg.as_string()
                    server.sendmail('your_email@example.com', email, text)
                flash("Password reset link sent to your email.")
            except Exception as e:
                flash(f"Error sending email: {e}")
        else:
            flash("Email not found.")

    return render_template('reset_password.html')

@app.route('/new-password', methods=['GET', 'POST'])
def new_password():
    token = request.args.get('token') or request.form.get('token')
    email = reset_tokens.get(token)

    if not email:
        return "Invalid or expired token", 400

    if request.method == 'POST':
        password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
        users_collection.update_one({'email': email}, {'$set': {'password': password}})
        reset_tokens.pop(token, None)
        return redirect(url_for('login'))

    return render_template('new_password.html', token=token)

@app.route('/edit-profile', methods=['GET', 'POST'])
def edit_profile():
    if 'user' not in session:
        flash("Please log in to edit your profile", "warning")
        return redirect(url_for('login'))

    try:
        user = users_collection.find_one({'email': session['user']})
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
                if users_collection.find_one({'email': new_email}):
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
                users_collection.update_one(
                    {'email': user['email']}, 
                    {'$set': update_data}
                )
                flash("Profile updated successfully!", "success")
            
            return redirect(url_for('profile'))

        return render_template('edit_profile.html', user=user)

    except Exception as e:
        flash(f"Error updating profile: {str(e)}", "danger")
        return redirect(url_for('profile'))

@app.route('/gra-Inv')
def gra_inv():
    return render_template('gra-Inv.html')  # Render the gra-Inv.html page

@app.route('/address')
def address():
    return render_template('address.html')  # Render the address.html page

@app.route("/address",  methods=['GET', 'POST'])
def save_address():
    if request.method == "POST":
        try:
            # Get form data
            full_name = request.form["fullName"]
            address = request.form["address"]
            city = request.form["city"]
            postal_code = request.form["postalCode"]

            # Create a document to store
            address_data = {
                "full_name": full_name,
                "address": address,
                "city": city,
                "postal_code": postal_code,
            }

            # Insert into MongoDB
            collection.insert_one(address_data)
            flash("Address saved successfully!", "success")
        except Exception as e:
            flash(f"An error occurred: {str(e)}", "danger")
            return redirect(url_for("home"))

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=False)

 # @app.route('/update-settings', methods=['POST'])
# def update_settings():
#     user = get_current_user()  # Get the current user from session or DB
#     name = request.form['name']
#     email = request.form['email']
#     phone = request.form['phone']
#     profile_picture = request.files.get('profile_picture')
    
#     # Process the uploaded file (if any)
#     if profile_picture:
#         profile_picture_path = save_profile_picture(profile_picture)
#         user.profile_picture = profile_picture_path
    
#     user.name = name
#     user.email = email
#     user.phone = phone
#     db.session.commit()  # Save updated information to the database
    
#     flash('Settings updated successfully!', 'success')
#     return redirect(url_for('settings'))

# @app.route('/settings')
# def settings():
#     # Assuming you have a way to get the logged-in user (e.g., from session or database)
#     user = get_user_from_session_or_db()  # Replace with actual logic to fetch the user data
    
#     # Pass the user object to the template
#     return render_template('settings.html', user=user)


# @app.route('/face-login', methods=['GET', 'POST'])
# def face_login():
#     if request.method == 'POST':
#         photo = request.files['photo']
#         filename = secure_filename(photo.filename)
#         filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
#         photo.save(filepath)

#         try:
#             # Encode face
#             image = face_recognition.load_image_file(filepath)
#             face_encodings = face_recognition.face_encodings(image)
#             if not face_encodings:
#                 flash("No face detected in the image.", "danger")
#                 return redirect(url_for('face_login'))

#             face_encoding = face_encodings[0]

#             # Compare with stored encodings
#             for user in users.find():
#                 known_encodings = [np.array(enc) for enc in user['face_encodings']]
#                 matches = face_recognition.compare_faces(known_encodings, face_encoding)
#                 if any(matches):
#                     session['user'] = user['name']
#                     flash(f"Welcome {user['name']}!", "success")
#                     return redirect(url_for('home'))

#             flash("No matching face found. Please try again.", "danger")
#         finally:
#             # Remove uploaded file to save space
#             os.remove(filepath)

#         return redirect(url_for('face_login'))

#     return render_template('face_login.html')

# @app.route('/compare_face', methods=['POST'])
# def compare_face():
#     # Get the image from the request
#     image_data = request.form['image']
#     image_data = image_data.split(',')[1]  # Remove base64 header
#     image_data = base64.b64decode(image_data)
    
#     # Convert byte data to image
#     img = Image.open(BytesIO(image_data))
#     img = np.array(img)

#     # Convert to RGB
#     img_rgb = cv2.cvtColor(img, cv2.COLOR_BGR2RGB)
    
#     # Use face_recognition to detect faces
#     face_locations = face_recognition.face_locations(img_rgb)
#     face_encodings = face_recognition.face_encodings(img_rgb, face_locations)
    
#     if len(face_encodings) > 0:
#         # You can compare face_encodings with a known face encoding stored in your database
#         return jsonify({"message": "Face verified successfully!"})
#     else:
#         return jsonify({"message": "No face detected. Please try again."})

# @app.route('/compare_face', methods=['POST'])
# def compare_face():
#     # Assuming form data is processed here
#     name = request.form['name']
#     surname = request.form['surname']
#     student_id = request.form['student_id']
#     image_front = request.files['imageFront']
#     image_left = request.files['imageLeft']
#     image_right = request.files['imageRight']

#     # You can process the images and data here as needed
#     # For example, save the images or compare faces, etc.

#     return render_template('compare_face.html', name=name, surname=surname, student_id=student_id)

# เส้นทางสำหรับการลงทะเบียนใบหน้า
# @app.route('/register_face', methods=['GET', 'POST'])
# def register_face():
#     if request.method == 'POST':
#         # Extract form data
#         name = request.form.get('name')
#         surname = request.form.get('surname')
#         student_id = request.form.get('student_id')
#         email = request.form.get('email')

#         # Check if all required images are uploaded
#         front_image = request.files.get('imageFront')
#         left_image = request.files.get('imageLeft')
#         right_image = request.files.get('imageRight')

#         if not front_image or not left_image or not right_image:
#             flash("Please upload all required face images.", "danger")
#             return redirect(url_for('register_face'))

#         # Create upload directory if not exists
#         os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

#         # Save image paths
#         front_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(front_image.filename))
#         left_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(left_image.filename))
#         right_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(right_image.filename))

#         # Save images
#         front_image.save(front_path)
#         left_image.save(left_path)
#         right_image.save(right_path)

#         # Extract face encodings
#         face_encodings = []
#         image_paths = [front_path, left_path, right_path]

#         for image_path in image_paths:
#             image = face_recognition.load_image_file(image_path)
#             encodings = face_recognition.face_encodings(image)
            
#             if not encodings:
#                 flash("Could not detect face in one of the images. Please try again.", "danger")
#                 return redirect(url_for('register_face'))
            
#             face_encodings.append(encodings[0].tolist())

#         # Save user data with face encodings
#         users_collection.insert_one({
#             "name": name,
#             "surname": surname,
#             "student_id": student_id,
#             "email": email,
#             "images": [front_path, left_path, right_path],
#             "face_encodings": face_encodings
#         })

#         # Redirect to face comparison/verification
#         return redirect(url_for('compare_face'))

#     return render_template('upload_face.html')

# เส้นทางสำหรับการตรวจสอบใบหน้า
# @app.route('/compare_face', methods=['GET', 'POST'])
# def compare_face():
#     # Check if user is logged in or in registration process
#     if 'user' not in session and 'registration_student_id' not in session:
#         flash("Please log in or complete registration", "warning")
#         return redirect(url_for('login'))

#     if request.method == 'POST':
#         # Existing face comparison logic
#         image_data = request.form.get('image')
#         if not image_data:
#             return jsonify({"message": "No image provided"}), 400

#         # Convert base64 image to numpy array
#         image_bytes = base64.b64decode(image_data.split(',')[1])
#         image = Image.open(BytesIO(image_bytes))
#         image_np = np.array(image)

#         # Detect face encodings
#         face_encodings = face_recognition.face_encodings(image_np)
#         if not face_encodings:
#             return jsonify({"message": "No face detected"}), 400

#         encoding_to_check = face_encodings[0]
        
#         # Check if this is a registration process
#         if 'registration_student_id' in session:
#             student_id = session['registration_student_id']
#             user = users_collection.find_one({"student_id": student_id})
            
#             if user and 'face_encodings' in user:
#                 known_encodings = [np.array(enc) for enc in user['face_encodings']]
#                 matches = face_recognition.compare_faces(known_encodings, encoding_to_check)
                
#                 if any(matches):
#                     # Clear registration session
#                     session.pop('registration_student_id', None)
#                     flash("Face registration successful!", "success")
#                     return redirect(url_for('home'))
#                 else:
#                     flash("Face does not match the registered images. Please try again.", "danger")
#                     return redirect(url_for('register_face'))
        
#         # Regular login comparison logic remains the same
#         users = users_collection.find()
#         for user in users:
#             if 'face_encodings' in user:
#                 for known_encoding in user['face_encodings']:
#                     matches = face_recognition.compare_faces([np.array(known_encoding)], encoding_to_check)
#                     if matches[0]:
#                         # Log in the user
#                         session['user'] = user['email']
#                         session['name'] = user['name']
#                         flash(f"Welcome, {user['name']}!", "success")
#                         return redirect(url_for('home'))

#         return jsonify({"message": "No match found"}), 400

    # GET request: show face comparison page
    # return render_template('compare_face.html')

# @app.route('/upload_face', methods=['GET', 'POST'])
# def upload_face():
#     if request.method == 'POST':
#         name = request.form['name']
#         surname = request.form['surname']
#         student_id = request.form['student_id']
        
#         # Handle file uploads
#         imageFront = request.files['imageFront']
#         imageLeft = request.files['imageLeft']
#         imageRight = request.files['imageRight']
        
#         if imageFront and allowed_file(imageFront.filename):
#             filename_front = secure_filename(imageFront.filename)
#             imageFront.save(os.path.join(app.config['UPLOAD_FOLDER'], filename_front))
#         if imageLeft and allowed_file(imageLeft.filename):
#             filename_left = secure_filename(imageLeft.filename)
#             imageLeft.save(os.path.join(app.config['UPLOAD_FOLDER'], filename_left))
#         if imageRight and allowed_file(imageRight.filename):
#             filename_right = secure_filename(imageRight.filename)
#             imageRight.save(os.path.join(app.config['UPLOAD_FOLDER'], filename_right))
        
#         # Optionally, you could save the user info and filenames into a database here
        
#         flash('Registration successful!', 'success')
#         return redirect(url_for('upload_face'))
    
#     return render_template('upload_face.html')