import os
import sys
import pytest
import sqlite3

# Add project root to Python path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from main import app

@pytest.fixture(scope='function')  # Create fresh database for each test
def test_db():
    # Create temporary in-memory database
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()
    
    # Create users table with specific fields
    cursor.execute('''CREATE TABLE IF NOT EXISTS users
                  (id INTEGER PRIMARY KEY AUTOINCREMENT,
                   username TEXT UNIQUE,
                   hashed_password TEXT,
                   mobile TEXT,
                   address TEXT,
                   security_question_1 TEXT,
                   security_answer_1 TEXT,
                   security_question_2 TEXT,
                   security_answer_2 TEXT,
                   image_path TEXT,
                   privilege_id INTEGER)''')
    
    # Insert test data for standard user and admin testing
    cursor.execute('''INSERT INTO users VALUES 
                  (1, 'test_user', 'hashed_password', '0412345678', 'test address',
                   'q1', 'a1', 'q2', 'a2', 'test.jpg', 1)''')
    cursor.execute('''INSERT INTO users VALUES 
                  (2, 'existing_user', 'hashed_password', '0412345678', 'test address',
                   'q1', 'a1', 'q2', 'a2', 'test.jpg', 1)''')
    conn.commit()
    
    # Configure test environment
    import data_handler
    data_handler.DATABASE = conn  # Use test database
    
    yield conn  # Provide database to tests
    conn.close()  # Clean up

@pytest.fixture
def client(test_db):
    # Configure Flask app for testing
    app.config['TESTING'] = True                  # Enable test mode
    app.config['WTF_CSRF_ENABLED'] = False        # Disable CSRF for testing
    app.config['DATABASE'] = test_db              # Use test database
    app.config['RATELIMIT_ENABLED'] = False       # Disable rate limiting
    
    with app.test_client() as client:  # Create test client
        yield client                   # Provide client to tests
