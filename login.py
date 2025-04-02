from flask import render_template, request, redirect, url_for, flash, session
import encrypt as encrypt
import data_handler
import time
import random
import logging

# Logging configuration
login_log = logging.getLogger(__name__)

def clear_login_session() -> None:
    # Clear all login-related session data
    session_keys = ['login_attempts', 'login_blocked_until', 'profile_image', 'Admin', 'Username_Login', 'pending_admin', 'admin_pin_hash', 'pin_expiry']
    for key in session_keys:
        session.pop(key, None)

def form_login():
    try:
        if request.method == "GET":
            if session.get('Username_Login'):
                flash("You are already logged in.", "info")
                return redirect(url_for("user_dashboard"))  # Redirect to the dashboard or home page
        # and request.args.get("url"): #dont realy know what this does
        # url = request.args.get("url", "")
        # return redirect(url, code=302)
        
        if request.method == "POST":
            username = request.form["username"]
            password = request.form["password"]

            # Check if user is temporarily blocked
            block_until = session.get('login_blocked_until', 0)
            if time.time() < block_until:
                remaining = int(block_until - time.time())
                flash(f"Too many failed attempts. Try again in {remaining} seconds.", "error")
                login_log.warning(f"Blocked login attempt for {username} from {request.remote_addr}")
                return redirect(url_for('login'))

            # Initialise attempts if not exists
            if 'login_attempts' not in session:
                session['login_attempts'] = 0

            if not data_handler.validate_username(username) or not data_handler.simple_check_password(password): # should not run, just a 3rd line of deffence
                session['login_attempts'] += 1 # Increment attempts
                remaining = 5 - session['login_attempts']
                if remaining > 0:
                    flash(f"Invalid username or password. {remaining} attempts remaining.", "error")
                if session['login_attempts'] >= 5:
                    session['login_blocked_until'] = time.time() + 300  # Block for 5 minutes
                    session['login_attempts'] = 0
                    flash("login temporarily locked. Try again in 5 minutes.", "error")
                login_log.warning(f"Failed login attempt for {username} from {request.remote_addr}")
                return redirect(url_for("login"))

            login_success, privilege_id = data_handler.login_check_db(username, password)

            if login_success: # True
                # Reset attempts on successful login
                session.pop('login_attempts', None)
                session.pop('login_blocked_until', None)
                session['Username_Login'] = username
                session['last_activity'] = time.time()  # Set last activity time   
                if privilege_id == 2:
                    session['Admin'] = False  # Not fully authenticated yet
                    session['pending_admin'] = True
                    # Generate 6-digit PIN and store hashed version with timestamp
                    admin_pin = ''.join([str(random.randint(0, 9)) for _ in range(6)]) # Generate a random 6-digit PIN
                    pin_expiry = time.time() + 120  # 2 minute expiry
                    session['admin_pin_hash'] = encrypt.hash_password(admin_pin) # Hash the PIN
                    session['pin_expiry'] = pin_expiry # Store the expiry time
                    print(f"Admin {username} verification PIN: {admin_pin}")  # In production, this would be sent via SMS
                    login_log.info(f"Admin {username} logged in and pending verification from {request.remote_addr}")
                    return redirect(url_for('admin_verify'))
                else:
                    session['Admin'] = False
                    login_log.info(f"User {username} logged in successfully from {request.remote_addr}")

            else:
                flash("Invalid username or password", "error")
                login_log.warning(f"Failed login attempt for {username} from {request.remote_addr}")
                return redirect(url_for('login'))  # Redirect back to the login page

            # Retrieve the user's profile image filename from the database
            user_info = data_handler.get_pfp_info(username)  # Implement this function to get user info
            
            if not user_info:
                logging.error(f"No profile image found for user {username}")
                return redirect(url_for('user_dashboard')) 
            session['profile_image'] = user_info  # Store the image filename in the session

            return redirect(url_for('user_dashboard')) # Redirect to a success page
    except Exception as e:
        login_log.critical(f"Unhandled exception during login: {e}", exc_info=True) # exc_info=True means include traceback 
        flash("An unexpected error occurred. Please try again later.", "error")
        clear_login_session()
        return redirect(url_for('login'))

    session.pop("profile_image", None)
    session.pop("Admin", None)
    session.pop("Username_Login", None)
    return render_template("/login.html")