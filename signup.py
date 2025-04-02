from flask import render_template, request, redirect, url_for, abort, flash
import data_handler as data_handler
import encrypt as encrypt
import os
import logging
from werkzeug.utils import secure_filename

logger = logging.getLogger(__name__)

UPLOAD_FOLDER = 'static/uploads'  # Directory to save uploaded files
os.makedirs(UPLOAD_FOLDER, exist_ok=True)  # Ensure the upload folder exists


def form_signup():
    if request.method == "GET" and request.args.get("url"): # dont realy know what this does
        url = request.args.get("url", "")
        return redirect(url, code=302)
    if request.method == "POST":
        try:
            # Retrive form data
            username = request.form["username"]
            password = request.form["password"]
            mobile = request.form["mobile"]
            address = request.form["address"]
            sq1 = request.form["security_question_1"]
            sqa1 = request.form["security_answer_1"]
            sq2 = request.form["security_question_2"]
            sqa2 = request.form["security_answer_2"]

            if 'image' not in request.files: # Check if the image is in the request
                flash("Image is required.", "error")
                return redirect(url_for('signup'))
            
            file = request.files['image']        
            filename_secure = secure_filename(file.filename)# Use secure_filename to sanitise the filename

            if filename_secure == "": # Check if the filename is empty
                flash("Filename cannot be empty.", "error")
                return redirect(url_for('signup'))
            
            if not data_handler.is_valid_image_file(filename_secure, file): # Check if the file is a valid image
                flash("Invalid file type. Only PNG and JPG are allowed.", "error")
                return redirect(url_for('signup'))

            #Check if valid format of username
            if not data_handler.validate_username(username):
                flash("Invalid username. It must be 3-9 characters long and can only contain letters, numbers, and underscores.", "error")
                return redirect(url_for('signup'))

            # Check if the username is unique
            if not data_handler.is_user_unique(username):
                flash("Username already exists.", "error")
                return redirect(url_for('signup'))

            if not data_handler.validate_number(mobile):
                flash("Invalid mobile number.", "error")
                return redirect(url_for('signup'))

            # Check the password meets our requirements
            if not data_handler.simple_check_password(password):
                flash("Password does not meet the requirements.", "error")
                return redirect(url_for('signup'))

            # Encrypt Data
            hashed_password, encrypted_mobile, encrypted_address, encrypted_sqa1, encrypted_sqa2 = encrypt.encrypt_sensitive_signup_form_data(password, mobile, address, sqa1, sqa2)

            unique_filename = data_handler.save_file(file, filename_secure)

            # Insert user data into the database
            data_handler.insert_user(username, hashed_password, encrypted_mobile, encrypted_address, sq1, encrypted_sqa1, sq2, encrypted_sqa2, unique_filename)

            # Clear sensitive data from memory
            username = None
            password = None
            mobile = None
            address = None
            sq1 = None
            sqa1 = None
            sq2 = None
            sqa2 = None
            hashed_password = None
            encrypted_mobile = None
            encrypted_address = None
            encrypted_sqa1 = None
            encrypted_sqa2 = None
            file = None

            return redirect(url_for('login')) # Redirect to login page
        except Exception as e:
            logger.error(f"Error signing up: {str(e)}", exc_info=True)
            abort(500)

    return render_template("/signup.html")