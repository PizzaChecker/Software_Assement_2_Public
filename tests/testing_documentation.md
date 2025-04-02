# Test Suite Documentation

## Overview
This test suite provides comprehensive coverage of the application's security, functionality, and reliability. All tests are written using pytest.

## Testing Approaches

### White Box Testing
| Category | Description | Examples |
|----------|-------------|----------|
| Unit Tests | Core function validation | `test_user_validation()`, `test_password_update()` |
| Path Coverage | Code path verification | `test_security_questions()` database operations |
| Error Handling | Exception management | `test_error_handling()` in data_handler tests |
| Database Ops | Data integrity checks | Database fixture in `conftest.py` |

### Grey Box Testing
| Category | Description | Examples |
|----------|-------------|----------|
| Integration Tests | Component interaction | `test_admin_access()` with mocked dashboard |
| Rate Limiting | Request throttling | `test_login_attempts()`, `test_rate_limiting()` |
| Session Management | State tracking | `test_session_management()` with client sessions |
| Database State | Data consistency | `test_user_management()` admin operations |

### Black Box Testing
| Category | Description | Examples |
|----------|-------------|----------|
| API Testing | Endpoint behaviour | `test_forgot_password_flow()` |
| Security Testing | Vulnerability checks | `test_security_redirects()` malicious paths |
| User Flow Testing | End-to-end scenarios | `test_security_questions()` reset flow |
| Input Validation | Boundary testing | `test_redirect_sanitisation()` XSS prevention |

## Test Implementation Details

### White Box Tests
- Direct database schema validation
- Error handling coverage
- Internal state verification
- Security implementation checks

### Grey Box Tests
- Session management verification
- Rate limiter effectiveness
- Database connection pooling
- Cache behaviour testing

### Black Box Tests
- API endpoint responses
- Form submission handling
- Security headers verification
- Cross-site scripting prevention

## List of Some Test Cases Used

- **Boundary Value Testing**:
  - Minimum and maximum input lengths for username, mobile number and password fields
  - Empty input fields for required parameters
  - Special characters in input fields

- **Input Categorisation**:
  - Valid and invalid phone number, password and username
  - Different user roles (e.g., admin, regular user, guest)

- **Error Guessing**:
  - Invalid file uploads (e.g., unsupported formats, oversised files)
  - Unexpected responses

- **Transition Testing**:
  - Valid and invalid session transitions (e.g. login, logout, session timeout)
  - Multi-step workflows (e.g. forgot password)

- **Security Testing**:
  - SQL injection attempts
  - Mock Cross-site scripting (XSS) attack
  - CSRF token validation

And more!

## Test Categories

### Authentication Tests (`test_auth.py`)
- Login attempt rate limiting
- Password validation
- Session management
- SQL injection prevention

### Password Reset Tests (`test_password_reset.py`)
- Security question validation
- Rate limiting protection
- Session state verification
- Mobile verification

### Admin Tests (`test_admin.py`)
- Access control verification
- User management functions
- Privilege escalation prevention
- Admin PIN validation

### Data Handler Tests (`test_data_handler.py`)
- Database operations
- Data validation
- Error handling
- Security checks

### Redirect Tests (`test_redirects.py`)
- Valid path handling
- Security redirect blocking
- Path traversal prevention
- XSS protection

## Test Execution

### Run All Tests
```bash
pytest tests/ -v
```

### Run Specific Categories
```bash
# Authentication tests
pytest tests/test_auth.py -v

# Password reset tests
pytest tests/test_password_reset.py -v

# Admin functionality
pytest tests/test_admin.py -v

# Data operations
pytest tests/test_data_handler.py -v

# Redirect security
pytest tests/test_redirects.py -v
```

## Coverage Report
To generate a coverage report:
```bash
pytest --cov=. tests/
```

## Test Requirements
- Python 3.8+
- pytest
- pytest-cov
- Flask testing tools
