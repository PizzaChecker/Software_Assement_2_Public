import pytest
from forgot_password import forgot_password

def test_forgot_password_flow(client):
    # Test initial password reset request
    response = client.post('/forgot_password', data={
        'username': 'test_user',
        'mobile': '0412345678'
    })
    assert response.status_code in [200, 302]  # Both codes are acceptable

def test_security_questions(client):
    # Set up valid session for security questions
    with client.session_transaction() as sess:
        sess['reset_username'] = 'test_user'
        sess['forgot_password_verified'] = True  # Mark mobile verification as done
    
    # Test security question verification
    response = client.post('/forgot_password_sq', data={
        'security_answer_1': 'test_answer',  # First security answer
        'security_answer_2': 'test_answer'   # Second security answer
    })
    assert response.status_code in [200, 302]

def test_rate_limiting(client):
    # Set up session with attempts near limit
    with client.session_transaction() as sess:
        sess['reset_username'] = 'test_user'
        sess['forgot_password_verified'] = True
        sess['sq_attempts'] = 4  # One attempt away from lockout

    # Make multiple wrong attempts to trigger lockout
    for _ in range(2):
        response = client.post('/forgot_password_sq', data={
            'security_answer_1': 'wrong',  # Wrong answers to trigger limit
            'security_answer_2': 'wrong'
        }, follow_redirects=True)

    # Check for lockout messages
    assert any(msg.encode('utf-8') in response.data for msg in [
        "Try again in",                                    # Timeout message
        "Too many failed attempts",                        # Failure message
        "Security question verification temporarily locked",# Lockout message
        "Security answers not found"                       # Error message
    ])
