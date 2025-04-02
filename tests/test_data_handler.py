import pytest
import sqlite3
from unittest.mock import patch  # Import patch for mocking database connections
from data_handler import *

@pytest.fixture
def test_db():
    # Create an in-memory SQLite database for testing
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    # Create users table with all required columns
    cursor.execute('''CREATE TABLE users
                     (id INTEGER PRIMARY KEY,
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
    conn.commit()  # Save changes to database
    yield conn    # Provide database connection to test
    conn.close()  # Clean up after test finishes

@patch('data_handler.sqlite3.connect')  # Mock database connection
def test_user_validation(mock_connect, test_db):
    mock_connect.return_value = test_db  # Use our test database
    cursor = test_db.cursor()
    # Add a test user to check uniqueness against
    cursor.execute("INSERT INTO users (username, privilege_id) VALUES (?, ?)", 
                  ("existing_user", 1))
    test_db.commit()
    
    # Verify username checks work correctly
    assert is_user_unique("nonexistent_user") == True  # Should be unique
    assert is_user_unique("existing_user") == False    # Should not be unique

@patch('data_handler.sqlite3.connect')  # Mock database connection
def test_password_update(mock_connect, test_db):
    mock_connect.return_value = test_db  # Use our test database
    cursor = test_db.cursor()
    # Insert a test user with an old password hash
    cursor.execute("INSERT INTO users (username, hashed_password, privilege_id) VALUES (?, ?, ?)",
                  ("test_user", "old_hash", 1))
    test_db.commit()
    
    # Update the user's password and verify success
    result = update_user_password("test_user", "New_Password123")
    assert result == True

@patch('data_handler.sqlite3.connect')  # Mock database connection
def test_security_questions(mock_connect, test_db):
    mock_connect.return_value = test_db  # Use our test database
    cursor = test_db.cursor()
    # Insert a test user with security questions
    cursor.execute("""INSERT INTO users 
                     (username, security_question_1, security_question_2, privilege_id)
                     VALUES (?, ?, ?, ?)""",
                     ("test_user", "q1", "q2", 1))
    test_db.commit()
    
    # Retrieve security questions and verify correctness
    questions = get_security_questions("test_user")
    assert isinstance(questions, dict)
    assert questions["question_1"] == "q1"
    assert questions["question_2"] == "q2"

def test_error_handling():
    # Test error handling for invalid operations
    with pytest.raises(Exception):
        with sqlite3.connect(":memory:") as conn:
            conn.close()
            validate_forgot_user("test", "1234")
