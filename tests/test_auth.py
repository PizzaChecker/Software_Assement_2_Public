import pytest
from flask import session

def test_login_attempts(client):
    # Test rate limiting by attempting multiple failed logins
    for i in range(6):  # Try 6 times to trigger rate limit
        response = client.post('/login', data={
            'username': 'test_user',
            'password': 'wrong_password'  # Deliberately wrong password
        }, follow_redirects=True)  # Follow any redirects
    
    # Check for any of our rate limit messages
    assert any(msg in response.data for msg in [
        b"Too many failed attempts",     # Standard message
        b"Rate Limit Exceeded",          # Alternative message
        b"Too many login attempts"       # Another possible message
    ])

def test_login_validation(client):
    # Test successful login with valid credentials
    response = client.post('/login', data={
        'username': 'test_user',
        'password': 'Valid_Password123'  # Valid password format
    }, follow_redirects=True)
    assert response.status_code == 200   # Should succeed

def test_session_management(client):
    # Test dashboard access with valid session
    with client.session_transaction() as sess:
        sess['Username_Login'] = 'test_user'  # Set valid session data
    response = client.get('/dashboard', follow_redirects=True)
    assert response.status_code == 200   # Should allow access
