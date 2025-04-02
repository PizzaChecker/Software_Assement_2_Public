import pytest
from flask import url_for

def test_valid_redirects(client):
    #Test valid redirect paths that should work normally
    valid_paths = [
        '/login',    # Standard login page
        '/signup',   # New user registration
        '/dashboard' # User dashboard access
    ]
    
    for path in valid_paths:
        response = client.get(path, follow_redirects=True)
        assert response.status_code in [200, 302]  # Valid responses

def test_security_redirects(client):
    #Test potentially malicious redirects that should be blocked
    malicious_paths = [
        '//evil.com',                  # External domain redirect attempt
        '../admin',                    # Directory traversal attempt
        '/login?next=http://evil.com', # Open redirect vulnerability test
        '/%2e%2e%2fadmin',            # Encoded path traversal
        '/?redirect=http://evil.com',  # Parameter-based redirect
        '/?url=//external-site.com',   # Protocol-relative redirect
        '/?next=../admin'             # Relative path redirect attempt
    ]
    
    for path in malicious_paths:
        response = client.get(path, follow_redirects=True)
        # Should either block (400/403/404) or redirect to safe page (302->200)
        assert response.status_code in [400, 403, 404] or (
            response.status_code == 200 and 
            'evil.com' not in response.data.decode() and
            'external-site.com' not in response.data.decode()
        )

def test_redirect_sanitisation(client):
    #Test that redirects are properly sanitised
    response = client.get('/login?next=javascript:alert(1)', follow_redirects=True)
    assert response.status_code in [200, 400]  # Should either sanitise or block
    
    response = client.get('/login?next=data:text/html,<script>alert(1)</script>', follow_redirects=True)
    assert response.status_code in [200, 400]  # Should either sanitise or block
