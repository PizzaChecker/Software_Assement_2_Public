import re
import html
import bcrypt
import os
import sqlite3
import encrypt as encrypt
import uuid
import mimetypes
from werkzeug.utils import secure_filename
from PIL import Image
from flask import render_template, request, redirect, url_for, flash, abort
from miscellaneous_security import random_delay
import logging

UPLOAD_FOLDER = 'static/uploads'  # Directory to save uploaded files
os.makedirs(UPLOAD_FOLDER, exist_ok=True)  # Ensure the upload folder exists

# Get the logger configured in main
logger = logging.getLogger(__name__)

# A simple password check function that checks if the password is valid
def simple_check_password(password: str) -> bytes:
    try:
        if not isinstance(password, str):  # Ensure it's a string
            return False
        if len(password) < 8 or len(password) > 20:
            # Handle special HTML character cases like '&lt;', '&amp;', etc.
            html_entities = ["&amp;", "&lt;", "&gt;", "&quot;", "&#39;"]
            # Check if the password contains any HTML entities
            if any(entity in password for entity in html_entities):
                # After decoding HTML, check if the length is still valid
                if normalise_password_length(password) < 8 or normalise_password_length(password) > 20:
                    return False
            else:
                return False
        if re.search(r"[ ]", password): # Check for spaces
            return False
        if not re.search(r"[A-Z]", password): # Check for uppercase letters
            return False
        if not re.search(r"[a-z]", password): # Check for lowercase letters
            return False
        if not re.search(r"[0-9]", password): # Check for digits
            return False
        if not re.search(r"[@$!%*?&]", password): # Check for special characters
            return False
        # Password is returned encoded so it can't be accidently logged in a human readable format
        return True #password.encode() #hash here?
    except Exception as e:
        logger.critical(f"Error checking password: {str(e)}", exc_info=True)
        abort(500)

def normalise_password_length(password):
    try:
        # Decode any HTML entities back to their original characters
        decoded_password = html.unescape(password)
        # Return the length of the decoded password
        return len(decoded_password)
    except Exception as e:
        logger.error(f"Error normalising password length: {str(e)}", exc_info=True)
        return 0


# Function to sanitise text using a library (NOT USED)############################
def make_web_safe(string: str) -> str:
    try:
        sanitised = html.escape(string) # Libray which sanitises characters
        logger.info("Input string sanitised successfully")
        return sanitised
    except Exception as e:
        logger.error(f"Error sanitising string: {str(e)}", exc_info=True)
        return ""

#Validate username
def validate_username(username: str) -> bool:
    try:
        if not isinstance(username, str): # Ensure it's a string
            logger.warning(f"Invalid username type provided: {type(username)}")
            return False
            
        if len(username) < 3 or len(username) > 9: # Check length
            logger.info(f"Username validation failed - length: {len(username)} chars")
            return False
        
        if not re.match(r'^[a-zA-Z0-9_]+$', username): # Check for valid characters
            logger.info("Username validation failed - invalid characters")
            return False
            
        logger.info(f"Username '{username}' validated successfully")
        return True
        
    except Exception as e:
        logger.error(f"Username validation error: {str(e)}", exc_info=True)
        return False

#validates phone number
def validate_number(number: str) -> bool: 
    try:
        if not isinstance(number, str): # Ensure it's a string
            logger.warning(f"Invalid phone number type: {type(number)}")
            return False
            
        if number.isalpha(): # Check if the number contains letters
            logger.info("Phone validation failed - contains letters")
            return False
        
        # Remove any spaces or special characters
        cleaned_number = ''.join(filter(str.isdigit, number))
        
        if not re.search(r"[0-9]", number): # Check for digits
            logger.info("Phone validation failed - contains more than numbers")
            return False

        # Check if exactly 10 digits
        if len(cleaned_number) != 10:
            logger.info(f"Phone validation failed - length is {len(cleaned_number)} digits, expected 10")
            return False

        logger.info("Phone number validated successfully")
        return True
        
    except Exception as e:
        logger.critical(f"Phone validation error: {str(e)}", exc_info=True)
        abort(500)

def is_valid_image_file(filename_secure, file):
    try:
        allowed_extensions = {'png', 'jpg', 'jpeg'} # Set of allowed file extensions
        file_extension = filename_secure.rsplit('.', 1)[1].lower() # Get the file extension
            
        if file_extension not in allowed_extensions: # Check if the file extension is allowed
            logger.warning(f"Invalid file extension: {file_extension}")
            return False

        mime_type, _ = mimetypes.guess_type(file.filename) # Get the MIME type
        if mime_type not in ['image/png', 'image/jpeg']: # Check if the MIME type is allowed
            logger.warning(f"Invalid MIME type: {mime_type}")
            return False
        
        #removed image.verify here as could not view file when used

        logger.info("Image file validated successfully")
        return True
    except Exception as e:
        logger.critical(f"Image validation error: {str(e)}", exc_info=True)
        return False
    
#Prevent executable files
def set_file_permissions(file_path):
    try:
        os.chmod(file_path, 0o644)  # Sets permissions to (read/write for owner, read-only for others)
        logger.info(f"Permissions set for file {file_path}")
    except Exception as e:
        logger.critical(f"Failed to set permissions for file {file_path}: {e}", exc_info=True)
        os.remove(file_path) # Remove potentially dangerous file
        abort(500)

#Creates a unique file name using uuid and the original file extension
def save_file(file, filename_secure):
    try:
        os.makedirs(UPLOAD_FOLDER, exist_ok=True)  # Ensure the upload folder exists
        file_extension = filename_secure.rsplit('.', 1)[1].lower()  # Get the file extension
        unique_filename = f"{uuid.uuid4()}.{file_extension}"  # Create a unique filename
        file_path = os.path.join(UPLOAD_FOLDER, unique_filename)  # Create the full file path
        file.save(file_path)  # Save the file
        set_file_permissions(file_path)  # Set file permissions to prevent security vulnerabilities
        return unique_filename, file_path  # Return the unique filename for database storage
    except Exception as e:
        logger.critical(f"Unexpected error saving file: {str(e)}", exc_info=True)
        abort(500)


#Data Base Functions##########################################################

#checks if username is unqiue 
def is_user_unique(username: str) -> bool:
    connection = None
    try:
        connection = sqlite3.connect('database.db') # Establish a connection to the SQLite database
        cursor = connection.cursor() # Create a cursor object to execute SQL commands
        
        # Query to check if the username exists
        cursor.execute("SELECT COUNT(*) FROM users WHERE username = ?", (username,)) # Select all usesr from where it matches the username
        count = cursor.fetchone()[0] # Fetch the count of matching usernames
        
        logger.info(f"Checked uniqueness for username: {username}")
        return count == 0  # Returns True if the username is unique (does not exist), False if it exists
        
    except sqlite3.OperationalError as e:
        logger.critical(f"Database operation error while checking username: {str(e)}", exc_info=True)
        return False
    except sqlite3.DatabaseError as e:
        logger.critical(f"Database error while checking username: {str(e)}", exc_info=True)
        return False
    except Exception as e:
        logger.critical(f"Unexpected error while checking username: {str(e)}", exc_info=True)
        return False
    finally:
        if connection:
            try:
                connection.close()
            except Exception as e:
                logger.error(f"Error closing database connection: {str(e)}", exc_info=True)
                abort(500)

def insert_user(username, hashed_password, mobile, address, sq1, sqa1, sq2, sqa2, image_path):
    connection = None
    try:
        # Establish a connection to the SQLite database
        connection = sqlite3.connect('database.db')
        cursor = connection.cursor()
        
        # Prepare the SQL statement
        sql = '''INSERT INTO users (username, hashed_password, mobile, address, security_question_1, security_answer_1, security_question_2, security_answer_2, image_path, privilege_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'''
        
        # Default privilege ID for "user"
        default_privilege_id = 1

        # Execute the SQL statement with the provided data
        cursor.execute(sql, (username, hashed_password, mobile, address, sq1, sqa1, sq2, sqa2, image_path[0], default_privilege_id))
        
        # Commit the changes
        connection.commit()
        
        logger.info(f"Inserted user: {username}")
    except sqlite3.OperationalError as e:
        logger.critical(f"Database operation error while inserting user: {str(e)}", exc_info=True)
        abort(500)
    except sqlite3.DatabaseError as e:
        logger.critical(f"Database error while inserting user: {str(e)}", exc_info=True)
        abort(500)
    except Exception as e:
        logger.critical(f"Unexpected error while inserting user: {str(e)}", exc_info=True)
        abort(500)
    finally:
        # Ensure the connection is closed
        if connection:
            try:
                connection.close()
            except Exception as e:
                logger.error(f"Error closing database connection: {str(e)}", exc_info=True)
                abort(500)

#Check User and Password
def login_check_db(username, password):
    random_delay(2, 5)  # Add random delay before check
    connection = None  # Initialise variable to avoid "UnboundLocalError: cannot access local variable 'connection' where it is not associated with a value"
    try:               # Which occours when the username is not in DB
        if is_user_unique(username):
            return False, None
        
        connection = sqlite3.connect('database.db')
        cursor = connection.cursor()
        
        # Query to check if the username exists
        cursor.execute("SELECT username, hashed_password, privilege_id FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()

        if result is None: # Prevents an error in the event that the user does not exist and happend to bypass is_user_unique
            return False, None

        if result[0] == username and encrypt.check_password(result[1], password) == True:
            logger.info(f"Login check performed for username: {username}")
            return True, result[2]
        else:
            #log incorect password
            return False, None

#Simple EXAMPLE:
# y ="1234Abcd@"
# z = encrypt.hash_password(y)
# x = encrypt.check_password(z, y)
# print(x) #If true PASSWORDS MATCH

    except sqlite3.OperationalError as e:
        logger.critical(f"Database operation error during login check: {str(e)}", exc_info=True)
        return False, None
    except sqlite3.DatabaseError as e:
        logger.critical(f"Database error during login check: {str(e)}", exc_info=True)
        return False, None
    except Exception as e:
        logger.critical(f"Unexpected error during login check: {str(e)}", exc_info=True)
        return False, None

    finally:
        if connection:
            try:
                connection.close()
            except Exception as e:
                logger.error(f"Error closing database connection: {str(e)}", exc_info=True)
                abort(500)

#Retrieve the profile picture filename for a given username.
def get_pfp_info(username: str):
    connection = None
    try:
        # Establish a connection to the database
        connection = sqlite3.connect('database.db')
        cursor = connection.cursor()
        
        # Query to retrieve the profile picture filename
        cursor.execute("SELECT image_path FROM users WHERE username = ?", (username,))
        result = cursor.fetchone() # Fetch the result
        
        if result:
            logger.info(f"Retrieved profile picture info for username: {username}")
            return result[0]  # Return the image_path if found
        else:
            return None  # Return None if the user is not found

    except sqlite3.OperationalError as e:
        logger.critical(f"Database operation error while retrieving profile picture info: {str(e)}", exc_info=True)
        return None
    except sqlite3.DatabaseError as e:
        logger.critical(f"Database error while retrieving profile picture info: {str(e)}", exc_info=True)
        return None
    except Exception as e:
        logger.critical(f"Unexpected error while retrieving profile picture info: {str(e)}", exc_info=True)
        return None

    finally:
        if connection:
            try:
                connection.close()
            except Exception as e:
                logger.error(f"Error closing database connection: {str(e)}", exc_info=True)
                abort(500)

#Forgot Password
def validate_forgot_user(username, phone):
    random_delay(2, 5)  # Add random delay before validation
    connection = None   # Initialise variable to avoid "UnboundLocalError: cannot access local variable 'connection' where it is not associated with a value"
    try:                # Which occours when the username is not in DB
        
        connection = sqlite3.connect('database.db')
        cursor = connection.cursor()
        
        cursor.execute("SELECT username, mobile FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()

        if result is None: #Prevents an error in the event that the user does not exist and happend to bypass is_user_unique
            return False

        if result[0] == username and encrypt.decrypt_data(result[1]) == phone:
            logger.info(f"Validated forgot password for username: {username}")
            return True
        else:
            logger.info(f"Invalid forgot password validation for username: {username}")
            return False

    except sqlite3.OperationalError as e:
        logger.critical(f"Database operation error during forgot password validation: {str(e)}", exc_info=True)
        return False
    except sqlite3.DatabaseError as e:
        logger.critical(f"Database error during forgot password validation: {str(e)}", exc_info=True)
        return False
    except Exception as e:
        logger.critical(f"Unexpected error during forgot password validation: {str(e)}", exc_info=True)
        return False

    finally:
        if connection:
            try:
                connection.close()
            except Exception as e:
                logger.error(f"Error closing database connection: {str(e)}", exc_info=True)
                abort(500)

#Get security quesitons for user
def get_security_questions(username: str):
    try:
        connection = sqlite3.connect('database.db')
        cursor = connection.cursor()
        
        # Query to retrieve security questions for the given username
        cursor.execute("SELECT security_question_1, security_question_2 FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        
        if result:
            return {
                "question_1": result[0],
                "question_2": result[1]
            }
        else:
            return None  # User not found
    except sqlite3.OperationalError as e:
        logger.critical(f"Database operation error while retrieving security questions: {str(e)}", exc_info=True)
        abort(500)
    except sqlite3.DatabaseError as e:
        logger.critical(f"Database error while retrieving security questions: {str(e)}", exc_info=True)
        abort(500)
    except Exception as e:
        logger.critical(f"Unexpected error while retrieving security questions: {str(e)}", exc_info=True)
        abort(500)
    finally:
        if connection:
            try:
                connection.close()
            except Exception as e:
                logger.error(f"Error closing database connection: {str(e)}", exc_info=True)
                abort(500)

def check_security_answers(username: str):
    # Fetch the correct security answers for the user from the database.

    try:
        connection = sqlite3.connect('database.db')
        cursor = connection.cursor()
        
        # Query to retrieve security answers for the given username
        cursor.execute("SELECT security_answer_1, security_answer_2 FROM users WHERE username = ?", (username,)) # Query
        result = cursor.fetchone()
        
        if result:
            stored_answer_1 = encrypt.decrypt_data(result[0]).strip().lower() # Decrypt stored data
            stored_answer_2 = encrypt.decrypt_data(result[1]).strip().lower() # Decrypt stored data
            return stored_answer_1, stored_answer_2 
        return None  # User not found
    except sqlite3.OperationalError as e:
        logger.critical(f"Database operation error while checking security answers: {str(e)}", exc_info=True)
        return None
    except sqlite3.DatabaseError as e:
        logger.critical(f"Database error while checking security answers: {str(e)}", exc_info=True)
        return None
    except Exception as e:
        logger.critical(f"Unexpected error while checking security answers: {str(e)}", exc_info=True)
        return None
    finally:
        if connection:
            try:
                connection.close()
            except Exception as e:
                logger.error(f"Error closing database connection: {str(e)}", exc_info=True)
                abort(500)

#updates user password
def update_user_password(username: str, new_password: str) -> bool:
    random_delay(2, 5)  # Add random delay before password update
    connection = None
    try:
        connection = sqlite3.connect('database.db')
        cursor = connection.cursor()
        new_hashed_password = encrypt.hash_password(new_password)
        # Update the user's password
        cursor.execute("UPDATE users SET hashed_password = ? WHERE username = ?", (new_hashed_password, username))
        connection.commit()

        logger.info(f"Updated password for username: {username}")
        return cursor.rowcount > 0  # Return True if the update was successful
    except sqlite3.OperationalError as e:
        logger.critical(f"Database operation error while updating password: {str(e)}", exc_info=True)
        return False
    except sqlite3.DatabaseError as e:
        logger.critical(f"Database error while updating password: {str(e)}", exc_info=True)
        return False
    except Exception as e:
        logger.critical(f"Unexpected error while updating password: {str(e)}", exc_info=True)
        return False
    finally:
        if connection:
            try:
                connection.close()
            except Exception as e:
                logger.critical(f"Error closing database connection: {str(e)}", exc_info=True)
                abort(500)

# Retrieve user data for a given username.
def get_user_data(username: str):
    connection = None
    try:
        connection = sqlite3.connect('database.db')
        cursor = connection.cursor()
        # Query to retrieve user data
        cursor.execute("""
            SELECT username, mobile, address, security_question_1, security_question_2, privilege_id
            FROM users 
            WHERE username = ?
        """, (username,))
        
        result = cursor.fetchone()
        
        if result:
            logger.info(f"Retrieved user data for username: {username}")
            # Return a dictionary with user data
            return {
                'username': result[0],
                'mobile': encrypt.decrypt_data(result[1]),
                'address': encrypt.decrypt_data(result[2]),
                'security_question_1': result[3],
                'security_question_2': result[4],
                'privilege_id': result[5]
            }
        else:
            return None  # Return None if the user is not found

    except sqlite3.OperationalError as e:
        logger.critical(f"Database operation error while retrieving user data: {str(e)}", exc_info=True)
        return None
    except sqlite3.DatabaseError as e:
        logger.critical(f"Database error while retrieving user data: {str(e)}", exc_info=True)
        return None
    except Exception as e:
        logger.critical(f"Unexpected error while retrieving user data: {str(e)}", exc_info=True)
        return None

    finally:
        if connection:
            try:
                connection.close()
            except Exception as e:
                logger.error(f"Error closing database connection: {str(e)}", exc_info=True)
                abort(500)


#Dashboard
def get_total_users(): # Gets number of all users in db admin and user roles
    connection = None
    try:
        connection = sqlite3.connect('database.db')
        cursor = connection.cursor()
        cursor.execute("SELECT COUNT(*) FROM users")
        total = cursor.fetchone()[0]
        logger.info("Retrieved total user count")
        return total
    except sqlite3.OperationalError as e:
        logger.critical(f"Database operation error while retrieving total users: {str(e)}", exc_info=True)
        return 0
    except sqlite3.DatabaseError as e:
        logger.critical(f"Database error while retrieving total users: {str(e)}", exc_info=True)
        return 0
    except Exception as e:
        logger.critical(f"Unexpected error while retrieving total users: {str(e)}", exc_info=True)
        return 0
    finally:
        if connection:
            try:
                connection.close()
            except Exception as e:
                logger.critical(f"Error closing database connection: {str(e)}", exc_info=True)
                return 0

def get_basic_users_count(): # Get total base user count
    connection = None
    try:
        connection = sqlite3.connect('database.db')
        cursor = connection.cursor()
        cursor.execute("SELECT COUNT(*) FROM users WHERE privilege_id = 1")
        total = cursor.fetchone()[0]
        logger.info("Retrieved basic users count")
        return total
    except sqlite3.Error as e:
        logger.critical(f"Database error while retrieving basic users count: {str(e)}", exc_info=True)
        return 0
    except Exception as e:
        logger.critical(f"Unexpected error while retrieving basic users count: {str(e)}", exc_info=True)
        return 0
    finally:
        if connection:
            try:
                connection.close()
            except Exception as e:
                logger.error(f"Error closing database connection: {str(e)}", exc_info=True)
                return 0

def get_admin_users_count(): # Get total amount of Admins
    connection = None
    try:
        connection = sqlite3.connect('database.db')
        cursor = connection.cursor()
        cursor.execute("SELECT COUNT(*) FROM users WHERE privilege_id = 2")
        total = cursor.fetchone()[0]
        logger.info("Retrieved admin users count")
        return total
    except sqlite3.Error as e:
        logger.critical(f"Database error while retrieving admin users count: {str(e)}", exc_info=True)
        return 0
    except Exception as e:
        logger.critical(f"Unexpected error while retrieving admin users count: {str(e)}", exc_info=True)
        return 0
    finally:
        if connection:
            try:
                connection.close()
            except Exception as e:
                logger.error(f"Error closing database connection: {str(e)}", exc_info=True)
                return 0

def search_users(query):
    connection = None
    try:
        connection = sqlite3.connect('database.db')
        cursor = connection.cursor()
        sanitised_query = query.replace('%', '').replace('_', '').replace("'", "").replace('"', "").replace(';', '').replace('--', '').replace('/*', '').replace('*/', '').replace('\\', '')
        # Use parameterised queries to prevent SQL injection
        cursor.execute("""
            SELECT id, username, mobile, privilege_id 
            FROM users 
            WHERE username LIKE ? OR privilege_id LIKE ?
        """, (sanitised_query, sanitised_query))
        
        users = cursor.fetchall()
        logger.info(f"Searched users with query: {query}")
        # Return only necessary information
        return [
            {
                'id': user[0],
                'username': user[1],
                'mobile': (f"****{encrypt.decrypt_data((user)[2])[-4:]}"),
                'role': 'Admin' if user[3] == 2 else 'User '
            } for user in users
        ]
    except sqlite3.OperationalError as e:
        logger.critical(f"Database operation error while searching users: {str(e)}", exc_info=True)
        return []
    except sqlite3.DatabaseError as e:
        logger.critical(f"Database error while searching users: {str(e)}", exc_info=True)
        return []
    except Exception as e:
        logger.critical(f"Unexpected error while searching users: {str(e)}", exc_info=True)
        return []
    finally:
        if connection:
            try:
                connection.close()
            except Exception as e:
                logger.critical(f"Error closing database connection: {str(e)}", exc_info=True)
                return []

def get_user_by_id(user_id): # Get user data to display on dashboard
    connection = None
    try:
        connection = sqlite3.connect('database.db')
        cursor = connection.cursor()
        cursor.execute("SELECT id, username, mobile, privilege_id FROM users WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        if user:
            logger.info(f"Retrieved user by ID: {user_id}")
            return {'id': user[0], 'username': user[1], 'mobile': encrypt.decrypt_data((user)[2]), 'privilege_id': user[3]}
        return None
    except sqlite3.OperationalError as e:
        logger.critical(f"Database operation error while retrieving user by ID: {str(e)}", exc_info=True)
        return None
    except sqlite3.DatabaseError as e:
        logger.critical(f"Database error while retrieving user by ID: {str(e)}", exc_info=True)
        return None
    except Exception as e:
        logger.critical(f"Unexpected error while retrieving user by ID: {str(e)}", exc_info=True)
        return None
    finally:
        if connection:
            try:
                connection.close()
            except Exception as e:
                logger.critical(f"Error closing database connection: {str(e)}", exc_info=True)
                abort(500)

def update_user(user_id, username, mobile, privilege_id):
    connection = None
    try:
        connection = sqlite3.connect('database.db')
        cursor = connection.cursor()
        mobile = encrypt.encrypt_data(mobile)
        cursor.execute("UPDATE users SET username = ?, mobile = ?, privilege_id = ? WHERE id = ?", (username, mobile, privilege_id, user_id))
        connection.commit()
        logger.info(f"Updated user with ID: {user_id}")
        return cursor.rowcount > 0  # Return True if the update was successful
    except sqlite3.OperationalError as e:
        logger.critical(f"Database operation error while updating user: {str(e)}", exc_info=True)
        abort(500)
    except sqlite3.DatabaseError as e:
        logger.critical(f"Database error while updating user: {str(e)}", exc_info=True)
        abort(500)
    except Exception as e:
        logger.critical(f"Unexpected error while updating user: {str(e)}", exc_info=True)
        abort(500)
    finally:
        if connection:
            try:
                connection.close()
            except Exception as e:
                logger.critical(f"Error closing database connection: {str(e)}", exc_info=True)

def delete_user(user_id):
    connection = None
    try:
        connection = sqlite3.connect('database.db')
        cursor = connection.cursor()
        cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
        connection.commit()
        logger.info(f"Deleted user with ID: {user_id}")
        return cursor.rowcount > 0  # Return True if the delete was successful
    except sqlite3.OperationalError as e:
        logger.critical(f"Database operation error while deleting user: {str(e)}", exc_info=True)
        abort(500)
    except sqlite3.DatabaseError as e:
        logger.critical(f"Database error while deleting user: {str(e)}", exc_info=True)
        abort(500)
    except Exception as e:
        logger.critical(f"Unexpected error while deleting user: {str(e)}", exc_info=True)
        abort(500)
    finally:
        if connection:
            try:
                connection.close()
            except Exception as e:
                logger.critical(f"Error closing database connection: {str(e)}", exc_info=True)
                abort(500)
