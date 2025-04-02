from flask import session, flash, redirect, url_for, render_template
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_limiter.errors import RateLimitExceeded
from datetime import timedelta
import time
import logging
import sys

# Get the logger configured in main
logger = logging.getLogger(__name__)

def init_limiter(app):
    try:
        limiter = Limiter(
            get_remote_address,# Function to get the IP
            app=app, # Flask app instance
            default_limits=["200 per day", "50 per hour"], # Subject to change in production environment
            storage_uri="memory://"  # For development
        )
        logger.info("Rate limiter initialised successfully")
        return limiter
    except Exception as e:
        logger.critical(f"Failed to initialise rate limiter: {str(e)}", exc_info=True)
        print(f"Critical error: Rate limiter failed to initialise. Application cannot start: {str(e)}")
        sys.exit(1)  # Exit with error code 1

def calculate_rate_limit_time(time_str):
    # the number of seconds for rate limiting based on the time string
    try:
        if "minute" in time_str:
            return 60
        elif "hour" in time_str:
            return 3600
        elif "day" in time_str:
            return 86400
        logger.info(f"Using default rate limit time for: {time_str}")
        return 60  # Default fallback
    except Exception as e:
        logger.error(f"Error calculating rate limit time: {str(e)}")
        return 60  # Safe default

def handle_rate_limit_error(e):
    try:
        time_str = str(e.description)
        current_time = time.time()
        ip = get_remote_address()  # Get IP for logging
        
        # Check if there's an existing block time in session
        if 'rate_limit_until' not in session:
            seconds = calculate_rate_limit_time(time_str)
            # Store the block expiration time in session
            session['rate_limit_until'] = current_time + seconds
            reset_time = timedelta(seconds=seconds)  # Use initial seconds for first attempt
            logger.warning(f"New rate limit applied for IP {ip}: {seconds}s")
        else:
            # Calculate remaining time for subsequent attempts
            remaining = max(0, session['rate_limit_until'] - current_time)
            if remaining <= 0: # Reset if time has expired
                seconds = calculate_rate_limit_time(time_str) # Recalculate the seconds
                session['rate_limit_until'] = current_time + seconds
                reset_time = timedelta(seconds=seconds) # Use initial seconds for first attempt
                logger.info(f"Rate limit reset for IP {ip}: {seconds}s")
            else:
                reset_time = timedelta(seconds=int(remaining))
                logger.warning(f"Existing rate limit for IP {ip}: {int(remaining)}s remaining")

        return render_template('429.html', reset_time=reset_time), 429
    except Exception as e:
        logger.error(f"Error handling rate limit: {str(e)}", exc_info=True)
        flash("An error occurred while processing your request. Please try again later.", "error")
        return redirect(url_for("index"))