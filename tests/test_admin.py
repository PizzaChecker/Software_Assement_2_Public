import pytest
from unittest.mock import patch
from admin_dashboard import admin_dash

@patch('admin_dashboard.user_dashboard.dash')
def test_admin_access(mock_dash, client):
    mock_dash.return_value = ({}, "test.jpg")  # Mock dashboard data
    # Set up admin session
    with client.session_transaction() as sess:
        sess['Admin'] = True                    # Grant admin privileges
        sess['Username_Login'] = 'admin_user'   # Set admin username
        sess['user_id'] = 3                     # Admin user ID
    
    # Test admin dashboard access
    response = client.get('/admin_dashboard', follow_redirects=True)
    assert response.status_code == 200  # Should allow access

@patch('admin_dashboard.user_dashboard.dash')
def test_user_management(mock_dash, client):
    mock_dash.return_value = ({}, "test.jpg")  # Mock dashboard data
    # Set up admin session
    with client.session_transaction() as sess:
        sess['Admin'] = True
        sess['Username_Login'] = 'admin_user'
        sess['user_id'] = 3
    
    # Test user editing functionality
    response = client.post('/user/1/edit', data={
        'username': 'edited_user',          # New username
        'mobile': '0412345678',            # Australian mobile format
        'address': 'test address',         # Test address
        'privilege_id': 1                  # Standard user privilege
    }, follow_redirects=True)
    assert response.status_code in [200, 302]  # Both codes acceptable

def test_admin_verification(client):
    # Test admin PIN verification system
    response = client.post('/admin_verify', data={
        'pin': '123456'  # Test admin PIN
    })
    assert response.status_code in [200, 302]  # Should accept valid PIN
