#Star
#python3 -m venv env
#Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass (Temporay solution for curent session of terminal only)
#env\Scripts\Activate
#
#Do once:
# '''
# pip3 install flask
# pip3 install flask-csp
# pip install pillow
# pip install bcrypt
# pip install cryptography
# pip install Flask-WTF #Added on 12/03
# pip install Flask-Limiter #Added on 14/03
# pip install requests Added on 19/03
# pip install pytest
# If flask not working go to command palete under view and change to the recomnded version should be were it says env
# '''
# Use jinja2 to auto escapre xxs
# cmd + / to comment


from flask import Flask
from flask import render_template #What does render temp do?
from flask import request
from flask import redirect
from flask import url_for
from flask import blueprints
from flask import session
from flask import abort
from flask import flash

# Ensure sessions are removed (pop) perhaps using limiter after a certain time?

import os
import data_handler
import logging
import encrypt as encrypt
import time

# from flask_wtf import CSRFProtect Cross site rquest forgery protection HAVE TO PIP INSTALL
from flask_csp.csp import csp_header
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_limiter.errors import RateLimitExceeded
from datetime import timedelta

from signup import form_signup #imports the signup function
from login import form_login
from forgot_password import forgot_password, reset_security_questions, new_password_process
from user_dashboard import user_dash
from admin_dashboard import admin_dash, verify_admin_pin
from user_change import user_edit, user_delete
from rate_limit import init_limiter, handle_rate_limit_error
from lock_manager import lock_manager
from url_validation import safe_redirect, is_safe_url

# Logging configuration
app_log = logging.getLogger(__name__)
logging.basicConfig(
    filename="security_log.log",
    encoding="utf-8",  # Supports a variety of more letters not just ASCII (eng and basic symbols)
    level=logging.DEBUG, # Set to DEBUG for development, WARNING for production
    format="%(asctime)s %(message)s", # Format of the log messages (date, time, message)
)

app = Flask(__name__)
secret_key_ = os.environ.get("VSCODE_SK_") # $env:VSCODE_SK_='secrect_key/'
app.secret_key = secret_key_
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # Limit to 5 MB
app.config.update(
    SESSION_COOKIE_HTTPONLY=True, # Prevents JavaScript access to cookies
    SESSION_COOKIE_SAMESITE='Strict', # Prevents cookies from being sent in cross-site requests
    SESSION_COOKIE_NAME='_secure_session', # Changes default name from 'session' Makes it harder to identify Flask
    SESSION_COOKIE_PATH='/',  # Cookie path
    SESSION_COOKIE_DOMAIN=None  # Restrict to current domain
)
csrf = CSRFProtect(app)  # Enable CSRF protection

# Initialise Flask Limiter
limiter = init_limiter(app)

# Session timeout settings
SESSION_TIMEOUT = 900 # In seconds-15 minutes

def check_session_timeout():
    # Check if the session has timed out
    if 'last_activity' in session:
        if time.time() - session['last_activity'] > SESSION_TIMEOUT:
            session.clear()  # Clear the session
            flash("Your session has expired due to inactivity. Please log in again.", "warning")
            return True #  Return a flag indicating that the session has expired
    session['last_activity'] = time.time()  # Update last activity time
    return False

def redirect_directions():
    target = None
    if request.endpoint not in ['signup', 'password_forgot', 'new_password', 'reset', 'process_new_password', 'sq', 'index']:
        target = url_for("login")
    elif request.endpoint == 'signup':
        target = url_for('signup')
    elif request.endpoint in ['password_forgot', 'new_password', 'reset', 'process_new_password', 'sq']:
        target = url_for('password_forgot')
    else:
        target = url_for('index')
    return redirect(safe_redirect(target))


@app.before_request # This function runs before every request
def before_request():
    # Check session timeout before each request.
    if check_session_timeout():
        return redirect_directions() # Redirects to slected page if session expired
    
    for key, value in request.args.items(): # Check all GET parameters
        if 'redirect' in key.lower() or 'url' in key.lower() or 'next' in key.lower(): # Check for potential redirect parameters
            if not is_safe_url(value): # Check if the URL is safe
                app_log.warning(f"Blocked potentially malicious redirect: {value}")
                abort(400) # Bad request if URL is not safe

    app_log.info(f"Accessing {request.endpoint} by {request.remote_addr}") # Log the request

@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff' # Prevents MIME type sniffing
    response.headers['X-Frame-Options'] = 'DENY' # Prevents embedding in iframes
    response.headers['X-XSS-Protection'] = '1; mode=block' # Enables XSS filter
    return response

# Redirect index.html to domain root for UX
@app.route("/index", methods=["GET"])
@app.route("/index.htm", methods=["GET"])
@app.route("/index.html", methods=["GET"])
@app.route("/index.asp", methods=["GET"]) # Active server page
@app.route("/index.php", methods=["GET"])
def root():
    return redirect("/", 302)

@app.route("/")
@csp_header(
    {
        "base-uri": "'self'", # Restrict base URI to self
        "default-src": "'self'", # Default source for all content
        "style-src": "'self'", # Allow styles from self
        "script-src": "'self'", # Allow scripts from self only
        "img-src": "'self' data:", # Allow images from self and data URIs
        "media-src": "'self'", # Allow media from self
        "font-src": "'self'", # Allow fonts from self
        "object-src": "'self'", # Allow objects from self
        "child-src": "'self'", # Allow child resources from self
        "connect-src": "'self'", # Allow connections from self
        "worker-src": "'self'", # Allow web workers from self
        "report-uri": "/csp_report", # URL to report violations
        "frame-ancestors": "'none'", # Prevents the page from being embedded in iframes
        "form-action": "'self'", # Restrict form submissions to self
        "frame-src": "'none'", # Prevent embedding in iframes
    }
)
def index():
    #app_log.info("Home page accessed")             **Add back when logging fixed
    return render_template("/index.html")

@app.route("/signup", methods=["POST", "GET"])
@limiter.limit("5 per minute", methods=["POST"])  # Limit POST requests
@limiter.limit("10 per minute", methods=["GET"])  # Limit GET requests 
def signup():
    return form_signup()

@app.route("/login", methods=["POST", "GET"])
@limiter.limit("8 per minute", methods=["POST"]) # Limit POST requests
@limiter.limit("12 per minute", methods=["GET"]) # Limit GET requests
def login():
    return form_login()

@app.route("/logout", methods=["GET"]) # Logout route
def logout():
    if not session.get('Username_Login'):
        flash("You need to be logged in to log out.", "warning") # Flash message if not logged in
        return redirect(url_for("index"))  # Redirect to the login page

    session.clear()  # Clear all session data
    flash("You have been logged out successfully.", "success")  # Flash message for logout
    return redirect(url_for("login"))  # Redirect to the login page

@app.route("/forgot_password", methods=["POST", "GET"])
def password_forgot():
    return forgot_password() # function to handle forgot password logic

@app.route("/forgot_password_sq", methods=["POST"])
def sq():
    if not session.get("forgot_password_verified"):  
        abort(403)
    return reset_security_questions()

@app.route("/new_password", methods=["POST", "GET"])
def new_password():
    if not session.get("SQ_verify"):  
        abort(403)  # Forbidden access if they haven't gone through forgot_password
    
    username = session.get("reset_username")  # Retrieve username from session
    return render_template("/new_password.html", username=username)

@app.route("/process_new_password", methods=["POST"])
def process_new_password():
    return new_password_process()

@app.route("/dashboard", methods=["GET"]) #changed from user_dashboard. Make it method get?
def user_dashboard():
    return user_dash()

@app.route("/admin_dashboard", methods=["GET", "POST"]) #make it so only admin can acces
def admin_dashboard():    
    return admin_dash()

@app.route("/admin_verify", methods=["GET", "POST"]) # Admin verification route
def admin_verify():
    if not session.get('pending_admin'): # Check if the user is pending admin
        return redirect(url_for('login'))
    return verify_admin_pin()

@app.route("/user/<int:user_id>/edit", methods=["GET", "POST"]) # Edit user route
@limiter.limit("5 per minute") # Prevent mass editing
def edit_user(user_id):
    return user_edit(user_id)

@app.route("/delete_user/<int:user_id>", methods=["POST"])
@limiter.limit("2 per minute") # Prevent mass deletion
def delete_user(user_id):
    return user_delete(user_id)

@app.route("/release_lock/<int:user_id>", methods=["POST"])
def release_lock(user_id):
    admin_username = session.get('Username_Login')# Check if user is logged in as admin
    if not admin_username or not session.get('Admin'):
        abort(403)
    
    lock_manager.release_lock(user_id, admin_username) # Release the lock and return no content
    return '', 204 # request has succeeded, but the client doesn't need to go away from its current page

@app.errorhandler(400) # Bad Request
def bad_request(error):
    app_log.warning(f"Bad request: {request.path} by {request.remote_addr}")
    return render_template("400.html", error="Bad Request - Invalid URL or parameters"), 400

@app.errorhandler(401) # Unauthorised
def Unauthorised(error):
    app_log.warning(f"Unauthorised access attempt to {request.path} by {request.remote_addr}")
    return render_template("401.html", error="Unauthorised access"), 401

@app.errorhandler(403) # Forbidden
def forbidden_access(error):
    app_log.warning(f"Forbidden access attempt to {request.path} by {request.remote_addr}")
    return render_template("401.html", error="Access is forbidden"), 403

@app.errorhandler(404) # Not Found
def page_not_found(e):
    app_log.error(f"Page not found: {request.path} by {request.remote_addr}")
    return render_template('404.html'), 404

@app.errorhandler(405) # Method Not Allowed
def method_not_allowed(error):
    app_log.error(f"Method not allowed: {request.method} on {request.path} by {request.remote_addr}")
    return render_template('405.html', error="Method not allowed"), 405

@app.errorhandler(413) # Payload Too Large
def content_too_large(error):
    app_log.warning(f"File size too large: {error}")
    return render_template("passerror.html", error="File is too large. Maximum size is 5 MB."), 413

@app.errorhandler(429) # Too Many Requests
@app.errorhandler(RateLimitExceeded) # Flask Specfic Limiter Error
def rate_limit_handler(e):
    app_log.warning(f"Rate limit exceeded: {e.description} on {request.path} by {request.remote_addr}")
    return handle_rate_limit_error(e)

@app.errorhandler(500) # Internal Server Error
def internal_server_error(e):
    app_log.error(f"Internal server error: {e}")
    return render_template('500.html'), 500

@app.errorhandler(Exception) # Unhandled Exception
def handle_exception(e):
    app_log.critical(f"Unhandled exception: {e}", exc_info=True)
    return render_template("418.html"), 418


if __name__ == "__main__":
    try:
        app_log.info("Starting Flask app...")
        app.run(debug=True, host="0.0.0.0", port=5000)  # Debug enabled in production
    except Exception as e:
        app_log.critical(f"Failed to start Flask app: {e}", exc_info=True)
