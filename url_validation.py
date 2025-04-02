from urllib.parse import urlparse, urljoin
from flask import request, url_for
import logging

logger = logging.getLogger(__name__)

# Whitelist of allowed domains for redirects
ALLOWED_DOMAINS = {'localhost', '127.0.0.1'}
# Whitelist of allowed paths/endpoints
ALLOWED_PATHS = {
    'index', 'login', 'signup', 'user_dashboard', 'admin_dashboard',
    'password_forgot', 'new_password', 'admin_verify'
}

def is_safe_url(target):
    try:
        # Handle absolute URLs that start with http/https
        if target.startswith(('http://', 'https://')):
            logger.warning(f"Absolute URL not allowed: {target}")
            return False
            
        # Clean the target URL
        target = target.strip()
        
        # Prevent directory traversal
        if '..' in target:
            logger.warning(f"Directory traversal attempt detected: {target}")
            return False
            
        ref_url = urlparse(request.host_url)
        test_url = urlparse(urljoin(request.host_url, target))
        
        # Check if the URL is relative and starts with '/'
        if not target.startswith('/'):
            return False
            
        # Check if redirect URL matches allowed domains
        if test_url.netloc and test_url.netloc not in ALLOWED_DOMAINS: # Check if domain is in allowed domains
            logger.warning(f"Attempted redirect to unauthorised domain: {test_url.netloc}")
            return False
            
        # Validate the path
        path = test_url.path.lstrip('/') # Remove leading slash
        if path and path not in ALLOWED_PATHS: # Check if path is in allowed paths
            logger.warning(f"Attempted redirect to unauthorised path: {path}")
            return False
            
        return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc
    except Exception as e:
        logger.error(f"Error validating URL {target}: {str(e)}")
        return False

def safe_redirect(target):
    #Safely redirect to a validated URL
    if not target:
        return url_for('index')
    if not is_safe_url(target):
        logger.warning(f"Unsafe redirect attempted to: {target}")
        return url_for('index')
    return target
