import base64
import io
from PIL import Image
from flask import Flask, json, request, jsonify, render_template, redirect, url_for, make_response, session
import pymongo
import os
import face_recognition
import jwt
from werkzeug.utils import secure_filename
from werkzeug.security import check_password_hash, generate_password_hash
import numpy as np
from datetime import datetime, timedelta
import cv2

app = Flask(__name__)

# Connect to MongoDB
client = pymongo.MongoClient('mongodb://localhost:27017/')
db = client['user_database']
users_collection = db['users']

# # Define a single database
# db = client['user_database']

# # Define collections
# users_collection = db['users']  # This is the users collection
# face_recognition_collection = db['face_recognition'] 

JWT_SECRET = 'mySuperSecretKey12345!'

# UPLOAD_FOLDER = './static/uploads'
# app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['UPLOAD_FOLDER'] = 'uploads/'  # Folder to save uploaded images


# ฟังก์ชันช่วยในการสร้าง JWT
# Registration route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        student_id = request.form['studentID']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirmPassword']

        # Check if passwords match
        if password != confirm_password:
            return render_template('register.html', message="Passwords do not match.")

        # Check if the user already exists
        if users_collection.find_one({"student_id": student_id}):
            return render_template('register.html', message="User already exists.")

        # Hash the password
        hashed_password = generate_password_hash(password, method='sha256')

        # Store user in the database
        users_collection.insert_one({
            "student_id": student_id,
            "email": email,
            "password": hashed_password
        })

        return redirect(url_for('login'))

    return render_template('register.html')


# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        student_id = request.form['studentID']
        password = request.form['password']

        # Find user by student_id
        user = users_collection.find_one({"student_id": student_id})

        if user and check_password_hash(user['password'], password):
            # Store student_id in session after successful login
            session['student_id'] = student_id
            return redirect('/home')
        else:
            return render_template('login.html', message="Invalid credentials. Please try again.")

    return render_template('login.html')

# Home route (only accessible after login)
@app.route('/home')
def home():
    if 'student_id' in session:
        return render_template('home.html')
    return redirect(url_for('login'))


# Logout route
@app.route('/logout')
def logout():
    session.pop('student_id', None)
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True)
