# Source Code Security Documentation

## Session Management Implementation
```python
# filepath: main.py
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,    # Prevents JavaScript access
    SESSION_COOKIE_SAMESITE='Strict', # Prevents CSRF attacks  
    SESSION_COOKIE_NAME='_secure_session', # Changes default name from 'session' Makes it harder to identify Flask
    SESSION_COOKIE_PATH='/', # Cookie path
    SESSION_COOKIE_DOMAIN=None # Restrict to current domain
)
```

Related files:
- `main.py`: Session creation/management

## Rate Limiting Protection
```python
# filepath: rate_limit.py
def init_limiter(app):
    limiter = Limiter(
        get_remote_address,# Function to get the IP
        app=app, # Flask app instance
        default_limits=["200 per day", "50 per hour"], # Subject to change in production environment
        storage_uri="memory://"  # Store in memory for development
    )

# filepath: main.py
@app.errorhandler(429)
def ratelimit_handler(e):
    return render_template("429.html", error="Too many requests. Please try again later.", retry_after=e.description), 429
```

Related files:
- `main.py`: Route-specific limits
- `login.py`: Login attempt limits
- `signup.py`: Registration limits

## SQL Injection Prevention
```python
# filepath: data_handler.py
def validate_user(username, password):
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,)) # Parameterised query
sanitised_query = query.replace('%', '')... # Contunies
# Sanitises user input
```

Related files:
- `signup.py`: User creation
- `login.py`: User validation
- `admin_dashboard.py`: User management
- `data_handler.py`: Database Queries

## XSS Protection
```python
# filepath: main.py
@csp_header({
    "default-src": "'self'",  # Default source for all content
    "script-src": "'self'", # Allow scripts from self only
    "style-src": "'self'" # Allow styles from self
})

@app.after_request
def set_security_headers(response):
    response.headers['X-XSS-Protection'] = '1; mode=block' # Enables XSS filter

import html
def make_web_safe(string: str) -> str:
    try:
        sanitised = html.escape(string) # Libray which sanitises characters
        return sanitised
```
```js
// filepath: static/JS/form_validation.js
function sanitiseInput(inputField) { // Client Side Prevenation
    const sanitisedValue = inputValue
        .replace(/&/g, "&amp;") // Escape ampersands
        .replace(/</g, "&lt;") // Escape less-than signs
        .replace(/>/g, "&gt;") // Escape greater-than signs
        .replace(/"/g, "&quot;") // Escape double quotes
        .replace(/'/g, "&#39;") // Escape single quotes
        .replace(/`/g, "&#96;") // Escape backticks
        .replace(/\(/g, "&#40;") // Escape left parentheses
        .replace(/\)/g, "&#41;") // Escape right parentheses
        .replace(/\//g, "&#47;") // Escape forward slashes
        .replace(/\\/g, "&#92;"); // Escape backslashes
}
```
Related files:
- `templates/*.html`: Jinja2 autoescape
- `data_handler.py`: Input sanitisation
- `login.py/signup.py`: Form validation

## CSRF Protection
```python
# filepath: main.py
csrf = CSRFProtect(app)
```

Related files:
- `templates/*.html`: CSRF tokens in all forms

## Secure File Handling
```python
# filepath: signup.py
import mimetypes
def is_valid_image_file(filename, file_object):
    allowed_extensions = {'png', 'jpg', 'jpeg'} # Set of allowed file extensions
    mime_type, _ = mimetypes.guess_type(file.filename)  # Get the MIME type
```

Related files:
- `data_handler.py`: File saving/checking
- `user_dashboard.py`: File retrieval
- `satic/uploads/`: File storage

## Error Handling & Logging
```python
# filepath: main.py
app_log = logging.getLogger(__name__)
logging.basicConfig(
    filename="security_log.log",
    encoding="utf-8",  # Supports a variety of more letters not just ASCII (eng and basic symbols)
    level=logging.DEBUG # # Set to DEBUG for development, WARNING for production
    format="%(asctime)s %(message)s", # Format of the log messages (date, time message)
)

@app.errorhandler(Exception) #This also cathes 400 errors with csrf
def handle_exception(e):
    app_log.critical(f"Unhandled exception: {e}", exc_info=True) # Provides traceback and the error in log
    return render_template("418.html"), 418 # Returns General Error Message
```

Related files:
- All `.py` files: Sytem failures/errors or info logging

## HTTP Security Headers
```python
# filepath: main.py
@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff' # Prevents MIME type sniffing
    response.headers['X-Frame-Options'] = 'DENY' # Prevents embedding in iframes
    response.headers['X-XSS-Protection'] = '1; mode=block' # Enables XSS filter
```

Related files:
- `templates/layout.html`: Base template
- `static/js/*.js`: Client-side security

## Password Hashing
```python
# filepath: encrypt.py
def hash_password(password: str) -> bytes:
    salt = bcrypt.gensalt() # Create salt
    return bcrypt.hashpw(password.encode(), salt) # Hash password
```

Related files:
- `signup.py`: Password creation
- `login.py`: Password verification
- `forgot_password.py`: Password reset

## Race Condition Prevention
```python
# filepath: lock_manager.py
from threading import Lock
class LockManager:
    def acquire_lock(self, resource_id, admin_id):
        self.cleanup_stale_locks()  # Cleanup before acquiring new lock
        lock = self._locks[resource_id]  # Get or create a Lock object
        if lock.acquire(timeout=timeout):  # Try to acquire the lock with timeout
            # Critical section - update lock information
            with self._cleanup_lock:  # Update lock information
                self._lock_info[resource_id] = {
                    'admin_id': admin_id,  # Who holds the lock
                    'timestamp': time()  # When the lock was acquired
                }
```
```js
// filepath: form_validation.js
function disableSubmitButton(form) {
    const submitButton = form.querySelector("button[type='submit'], input[type='submit']"); // Find the submit button within the form
    if (submitButton) {
        submitButton.disabled = true;
    }
}
```
Related files:
- `admin_dashboard.py`: Resource locking
- `user_change.py`: Editing/deleting users
- `data_handler.py`: Database operations
- `form_validation.js`: Prevent double submission

## Invalid Redirect Protection
```python
# filepath: signup.py
if not is_safe_url(value):
    abort(400) 
```

Related files:
- `url_validation`: Contains the functionality

## Side Channel Attack Prevention
```python
# filepath: encrypt.py
def random_delay(min_ms=1, max_ms=5):            
    delay = random.uniform(min_ms / 1000, max_ms / 1000)
    time.sleep(delay)
```

Related files:
- `encrypt.py`: Encryption timing
- `data_handler.py`: login and forgot password timing

## Admin Two-Factor Authentication
```python
# filepath: admin_dashboard.py
admin_pin = ''.join([str(random.randint(0, 9)) for _ in range(6)]) # Generate a random 6-digit PIN
pin_expiry = time.time() + 120  # 2 minute expiry
session['admin_pin_hash'] = encrypt.hash_password(admin_pin) # Hash the PIN
session['pin_expiry'] = pin_expiry # Store the expiry time
print(f"Admin {username} verification PIN: {admin_pin}")  # In production, this would be sent via SMS
```

Related files:
- `login.py`: Initial authentication
- `encrypt.py`: PIN hashing
- `main.py`: Session management
- `admin_verify.py`: Verification

## Input Validation & Sanitisation
```javascript
// filepath: static/JS/form_validation.js
function validateUsername(username, usernameErrorMessage)
function validateMobileNumber(mobile, mobileErrorMessage)
function validatePassword(password, passwordErrorMessage)
```

Related files:
- `templates/*.html`: Client-side validation
- `data_handler.py`: Server-side validation
- `colour_change_val.js`: Real-time validation

## Content Size Limitations
```python
# filepath: main.py
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5MB file size limit

@app.errorhandler(413)  # Handles files exceeding size limit
def request_entity_too_large(error):
    return render_template('413.html'), 413
```

Related files:
- `signup.py`: File upload handling
- `data_handler.py`: Profile validation
- `templates/signup.html`: Form constraints

## Session Timeout Management
```python
# filepath: main.py
@app.before_request
def check_session_timeout():
    if 'last_activity' in session:
        if time.time() - session['last_activity'] > SESSION_TIMEOUT:  # Check if session expired
            session.clear()  # Clear the session data
            flash("Your session has expired due to inactivity. Please log in again.", "warning")
            return True # Return a flag indicating that the session has expired
    session['last_activity'] = time.time()  # Update last activity timestamp
    return False # Return session has not expired
```

Related files:
- `admin_dashboard.py`: Admin timeouts
- `user_dashboard.py`: User sessions
- `login.py`: Session creation

## Key Variable Table

| Variable Name         | File                | Description                                                                 |
|-----------------------|---------------------|-----------------------------------------------------------------------------|
| `SESSION_COOKIE_NAME` | `main.py`          | Name of the session cookie used for secure session management.             |
| `MAX_PIN_ATTEMPTS`    | `admin_dashboard.py`| Maximum number of PIN attempts before locking the admin session.           |
| `allowed_extensions`  | `signup.py`        | Set of allowed file extensions for uploaded images.                        |
| `MAX_CONTENT_LENGTH`  | `main.py`          | Maximum allowed size for uploaded content (5MB).                           |
| `csrf`                | `main.py`          | CSRF protection object for the application.                                |
| `app_log`             | `main.py`          | Logger instance for application security logs.                             |
| `default_limits`      | `rate_limit.py`    | Default rate limits for API requests.                                      |

## Session Table

| Session Key               | File                | Description                                                                 |
|---------------------------|---------------------|-----------------------------------------------------------------------------|
| `Username_Login`          | `main.py`          | Stores the username of the logged-in user.                                 |
| `client_ip`               | `main.py`          | Stores the IP address of the client for session validation.                |
| `user_agent`              | `main.py`          | Stores the user agent string for session validation.                       |
| `pin_attempts`            | `admin_dashboard.py`| Tracks the number of failed PIN attempts for admin authentication.         |
| `admin_id`                | `admin_dashboard.py`| Stores the ID of the currently logged-in admin.                            |
| `session_timeout`         | `main.py`          | Tracks the session timeout for the user.                                   |
| `file_upload_status`      | `user_dashboard.py`| Tracks the status of file uploads for the user.                            |
| `last_activity`           | `main.py`          | Tracks the last activity timestamp for the session.                        |
| `SQ_verify`               | `login.py`         | Tracks the status of security question verification.                       |
| `reset_username`          | `forgot_password.py`| Stores the username for password reset operations.                         |
| `pending_admin`           | `admin_dashboard.py`| Tracks pending admin actions.                                              |
| `Admin`                   | `admin_dashboard.py`| Indicates whether the user is an admin.                                    |
| `admin_last_activity`     | `admin_dashboard.py`| Tracks the last activity timestamp for the admin session.                  |
| `admin_pin_hash`          | `encrypt.py`       | Stores the hashed admin PIN for two-factor authentication.                 |
| `pin_expiry`              | `admin_dashboard.py`| Tracks the expiration time for the admin PIN.                              |
| `Admin_DELETE`            | `admin_dashboard.py`| Tracks admin delete actions.                                               |
| `forgot_blocked_until`    | `forgot_password.py`| Tracks when the user can attempt another password reset.                   |
| `forgot_attempts`         | `forgot_password.py`| Tracks the number of password reset attempts.                              |
| `forgot_password_verified`| `forgot_password.py`| Indicates whether the password reset was verified.                         |
| `sq_blocked_until`        | `login.py`         | Tracks when the user can attempt another security question verification.   |
| `sq_attempts`             | `login.py`         | Tracks the number of security question verification attempts.              |
| `profile_image`           | `user_dashboard.py`| Stores the profile image of the user.                                      |
| `login_attempts`          | `login.py`         | Tracks the number of login attempts.                                       |
| `login_blocked_until`     | `login.py`         | Tracks when the user can attempt another login.                            |
| `rate_limit_until`        | `rate_limit.py`    | Tracks when the rate limit will be lifted for the user.                    |

## Database Documentation

### Tables

#### `users`
| Column Name        | Data Type   | Description                                                                 |
|--------------------|-------------|-----------------------------------------------------------------------------|
| `id`               | INTEGER     | Primary key for the user.                                                  |
| `username`         | TEXT        | Unique username for the user.                                              |
| `hashed_password`  | TEXT        | Hashed password for the user.                                              |
| `address`          | TEXT        | Address of the user.                                                       |
| `security_question`| TEXT        | Security question for account recovery.                                    |
| `security_answer1` | TEXT        | First answer to the security question.                                     |
| `security_answer2` | TEXT        | Second answer to the security question.                                    |
| `image_path`       | TEXT        | Path to the user's profile image.                                          |
| `privilege_id`     | INTEGER     | Foreign key referencing the user's privilege level.                        |

#### `privileges`
| Column Name   | Data Type   | Description                                                                 |
|---------------|-------------|-----------------------------------------------------------------------------|
| `id`          | INTEGER     | Primary key for the privilege entry.                                       |
| `privilege_name`| TEXT       | Description of the privilege (e.g., admin, editor).                       |

### Relationships

- `users.privilege_id` is referenced by `privileges.id`.
- `privileges` tracks the roles and permissions assigned to users.


## Production Security Notes
- Set DEBUG = False
- Use environment variables for secrets
- Enable HTTPS only
- Regular security audits