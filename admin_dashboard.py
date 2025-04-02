from flask import render_template, request, redirect, url_for, flash, session, abort
from flask_wtf.csrf import CSRFProtect
import data_handler
import user_dashboard
import encrypt
import time
import logging


logger = logging.getLogger(__name__)

ADMIN_TIMEOUT = 300  # 5 minutes in seconds

def clear_admin_session():
    # Clear all admin-related session data
    session_keys = ["pin_attempts","pending_admin","admin_pin_hash","pin_expiry"]
    for key in session_keys:
        session.pop(key, None)

def check_admin_session_timeout():
    try:
        if session.get('admin_last_activity'):
            if time.time() - session['admin_last_activity'] > ADMIN_TIMEOUT: # If the session has timed out
                session.clear()# Clear all session data
                flash("Admin session timed out. Please login again.", "warning")
                return True
        return False
    except Exception as e:
        logger.error(f"Error checking admin session timeout: {str(e)}", exc_info=True)
        session.clear()  # Clear session on error
        flash("An error occurred while checking session timeout. Please login again.", "error")
        abort(500)

def session_check_admin():
    try:
        if check_admin_session_timeout(): # If the session has timed out
            return redirect(url_for('login')) # Redirect to login page
            
        if not session.get("Admin"): # If the user is not an admin
            if session.get("Username_Login"): # If the user is logged in but not an admin
                return redirect(url_for("user_dashboard"))
            flash("Access is forbidden!")
            flash("Please login, to access the dashboard")
            return redirect(url_for("login")) # Redirect to login page
        
        # Update admin last activity time
        session['admin_last_activity'] = time.time() 
        return None
    except Exception as e:
        logger.error(f"Error during admin session check: {str(e)}", exc_info=True)
        abort(500)

def verify_admin_pin():
    try:
        if request.method == "POST":
            # Initialise attempts
            if 'pin_attempts' not in session:
                session['pin_attempts'] = 0

            entered_pin = request.form.get("pin") # Get the entered PIN
            if not entered_pin: # Check if the entered PIN is empty
                flash("PIN cannot be empty", "error")
                return render_template("admin_verify.html")
            if len(entered_pin) != 6: # Check if the entered PIN is 6 digits
                flash("PIN must be 6 digits", "error")
                return render_template("admin_verify.html")
            
            pin_hash = session.get('admin_pin_hash') # Get the stored PIN hash
            pin_expiry = session.get('pin_expiry') # Get the stored PIN expiry time

            # Check if PIN has expired
            if not pin_hash or not pin_expiry or time.time() > pin_expiry:
                clear_admin_session() # Clear all session data
                session.pop('Username_Login', None)
                flash("PIN has expired. Please login again.", "error")
                return redirect(url_for('login')) # Redirect to login page

            if encrypt.check_password(pin_hash, entered_pin): # True
                session['Admin'] = True
                session['admin_last_activity'] = time.time()  # Initialise admin session timer
                clear_admin_session() # Clear all admin session data
                return redirect(url_for('admin_dashboard'))
            else:
                session['pin_attempts'] = session.get('pin_attempts', 0) + 1 # Increment attempts
                remaining = 3 - session['pin_attempts']  # Changed to 3 attempts from 5 in other files
                if remaining > 0:
                    flash(f"Invalid PIN. {remaining} attempts remaining.", "error") 
                    return render_template("admin_verify.html")
                else:
                    # Clear all relevant session data after 3 failed attempts
                    clear_admin_session()
                    session.pop('Username_Login', None)  # Force complete re-login
                    flash("Too many failed PIN attempts. Please login again.", "error") 
                    return redirect(url_for('login')) # Redirect to login page
        return render_template("admin_verify.html") # Render the PIN verification page
    except Exception as e:
        session.clear() # Clear all session data in evnet of error
        logger.error(f"Error in verify_admin_pin: {str(e)}", exc_info=True)
        flash("An error occurred during admin verification. Please try again later.", "error")
        return redirect(url_for('login')) # Redirect to login page

def admin_dash():
    redirect_response = session_check_admin() # Check if the session is valid
    if redirect_response:
        return redirect_response  # This ensures the flow stops if there's an issue with the session
    
    if request.method == "GET":
        try:
            # Get user stats
            total_users = data_handler.get_total_users()
            basic_users = data_handler.get_basic_users_count()
            admin_users = data_handler.get_admin_users_count()

            users = [] # Initialise

            if session.get('Admin') == True:
                session['Admin_DELETE'] = True  # Set Admin flag based on privilege_id (Ture/False)
            else:
                session['Admin_DELETE'] = False

            user_data, profile_image = user_dashboard.dash() # Get user data and profile image
            return render_template("admin_dashboard.html", user_data=user_data, profile_image=profile_image, total_users=total_users, basic_users=basic_users, admin_users=admin_users, users=users)
        except Exception as e:
            logger.error(f"Error loading admin dashboard: {str(e)}", exc_info=True)
            abort(500)

    if request.method == "POST":
        try:
            search_query = request.form.get("search_query")
            if not search_query: # Check if search query is empty
                flash("Please enter a search term", "warning")
                return redirect(url_for("admin_dashboard"))
            
            users = data_handler.search_users(search_query)  # Function to search users based on the query
            total_users = data_handler.get_total_users()# Get user statistics
            basic_users = data_handler.get_basic_users_count()
            admin_users = data_handler.get_admin_users_count()
            
            if not users: # Check if no users were found
                flash("No users found matching your search", "info")

            return render_template("admin_dashboard.html", total_users=total_users, basic_users=basic_users, admin_users=admin_users, users=users, hide=True)
        except Exception as e:
            logger.error(f"Error searching users: {str(e)}", exc_info=True)
            flash("An error occurred while searching users. Please try again.", "error")
            abort(500)