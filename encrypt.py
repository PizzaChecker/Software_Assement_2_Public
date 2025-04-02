import logging
from cryptography.fernet import Fernet, InvalidToken
import os
import bcrypt
from miscellaneous_security import random_delay
import random
from flask import abort

# Configure logging - using the configuration from main.py
logger = logging.getLogger(__name__)

def generate_key():
    try:
        gen_key = Fernet.generate_key()
        return gen_key
    except Exception as e:
        print(f"Failed to generate key: {str(e)}") # Printed as the full program is not running when called
        return None

def load_key():
    try:
        key = os.environ.get("VSCODE_DOM") # Retive key from env
        if not key:
            logger.error("Encryption key not found in environment variables")
            return None
        logger.debug("Encryption key loaded successfully")
        random_delay(1, 5)
        return key
    except Exception as e:
        logger.critical(f"Error loading key: {str(e)}")
        abort(500)

def randomise_operation_order():
    # Randomise the order of cryptographic operations to prevent timing analysis
    # Using a list of operations that will be performed in random order
    # This makes it harder to determine the sequence through side-channel attacks
    ops = ['encode', 'encrypt', 'delay']
    random.shuffle(ops)
    return ops

def encrypt_data(data: str) -> str:
    try:
        key = load_key()
        if not key:
            logger.critical("Could not load encryption key")
            abort(500)
        random_delay(1, 5)
        cipher = Fernet(key) # Create a Fernet cipher object
        
        operations = randomise_operation_order()     # Get randomised operation sequence to prevent timing analysis
        encoded_data = None # Prevent predictable memory allocation
        encrypted_data = None
        
        for op in operations:
            if op == 'encode':
                encoded_data = data.encode() if not encoded_data else encoded_data
            elif op == 'encrypt':
                if encoded_data:
                    encrypted_data = cipher.encrypt(encoded_data)
                else:
                    encoded_data = data.encode()
                    encrypted_data = cipher.encrypt(encoded_data)
            elif op == 'delay':
                random_delay(1, 5)
        
        logger.info("Data encrypted successfully")
        return encrypted_data.decode()
    except (InvalidToken, ValueError) as e:
        logger.critical(f"Encryption error: {str(e)}")
        abort(500)
    except Exception as e:
        logger.critical(f"Unexpected error during encryption: {str(e)}")
        abort(500)

def decrypt_data(encrypted_data: str) -> str:
    try:
        key = load_key()
        if not key:
            logger.critical("Could not load encryption key")
            abort(500)
        cipher = Fernet(key)
        
        operations = randomise_operation_order()
        encoded_data = None
        decrypted_data = None
        
        for op in operations:
            if op == 'encode':
                encoded_data = encrypted_data.encode() if not encoded_data else encoded_data
            elif op == 'encrypt':
                if encoded_data:
                    decrypted_data = cipher.decrypt(encoded_data)
                else:
                    encoded_data = encrypted_data.encode()
                    decrypted_data = cipher.decrypt(encoded_data)
            elif op == 'delay':
                random_delay(1, 5)
        
        logger.info("Data decrypted successfully")
        return decrypted_data.decode()
    except InvalidToken as e:
        logger.critical("Invalid token or corrupted data")
        abort(500)
    except Exception as e:
        logger.critical(f"Decryption error: {str(e)}")
        abort(500)

#Simple example that works
#y ="gAAAAABnwmpI2bMIV05KAJTQhelVE14esoIcYirPq3uZCvg0B9IGEs7gVjOlOeolfTLHCMpxKyP65_H6qtnzXlNSOxbIKb12FQ=="
#x = encrypt.decrypt_data(y)
#print(x)
def encrypt_sensitive_signup_form_data(password, mobile, address, sqa1, sqa2):
    hashed_password = hash_password(password)
    encrypted_mobile = encrypt_data(mobile)
    encrypted_address = encrypt_data(address)
    encrypted_sqa1 = encrypt_data(sqa1)
    encrypted_sqa2 = encrypt_data(sqa2)
    return hashed_password, encrypted_mobile, encrypted_address, encrypted_sqa1, encrypted_sqa2

#Encryption of Password
def hash_password(password: str) -> bytes:
    try:
        operations = ['salt', 'hash', 'delay'] # Randomise salt generation and hashing sequence
        random.shuffle(operations)
        salt = None
        hashed_password = None
        
        for op in operations:
            if op == 'salt':
                salt = bcrypt.gensalt() if not salt else salt # Generate a new salt if not already generated
            elif op == 'hash':
                salt = bcrypt.gensalt() if not salt else salt # Use existing salt if there or generate new salt
                hashed_password = bcrypt.hashpw(password.encode(), salt) # Hash password
            elif op == 'delay':
                random_delay(1, 3)
        
        logger.info("Password hashed successfully")
        return hashed_password
    except Exception as e:
        logger.error(f"Password hashing error: {str(e)}")
        return bcrypt.gensalt()  # Return a safe default value

def check_password(hashed_password: bytes, password: str) -> bool:
    try:
        random_delay(1, 5)
        result = bcrypt.checkpw(password.encode(), hashed_password) # Check password with hashed password
        logger.info("Password check completed")
        return result
    except Exception as e:
        logger.error(f"Password verification error: {str(e)}")
        return False  # Return false on any error

if __name__ == "__main__":
    try:
        key = generate_key()
        if key:
            print(f"Generated key: {key.decode()}")
            print("Set this key in your environment variable:")
            print('$env:VSCODE_DOM="generated_key_here"')
        else:
            print("Failed to generate key")
    except Exception as e:
        print(f"Error in key generation: {str(e)}")