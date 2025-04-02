from flask import render_template, request, redirect, url_for, flash, session, abort
import data_handler
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import time
import logging

# Get the logger configured in main
logger = logging.getLogger(__name__)

def forgot_password():
    try:
        if request.method == "POST":
            # Check if temporarily blocked
            block_until = session.get('forgot_blocked_until', 0)
            if time.time() < block_until: # Check if the block time has passed
                remaining = int(block_until - time.time())
                logger.warning(f"Blocked attempt to reset password - remaining time: {remaining}s")
                flash(f"Too many failed attempts. Try again in {remaining} seconds.", "error")
                return redirect(url_for('password_forgot'))

            # Initialise attempts if not already set
            if 'forgot_attempts' not in session:
                session['forgot_attempts'] = 0

            # Retrieve username and phone from the form
            username = request.form["username"]
            phone = request.form["mobile"]

            # Log the password reset attempt
            logger.info(f"Password reset attempt for username: {username}")

            if data_handler.validate_forgot_user(username, phone):
                # Reset attempts on success
                session.pop('forgot_attempts', None)
                session.pop('forgot_blocked_until', None)
                security_questions = data_handler.get_security_questions(username)

                if security_questions:
                    # Store username and verification status in session
                    session["reset_username"] = username
                    session["forgot_password_verified"] = True
                    flash("Identity verified. Please answer your security questions.", "success")
                    logger.info(f"Initial password reset verification successful for: {username}")
                    return render_template("reset_password.html", questions=security_questions)
                else:
                    # Log error if security questions are not found
                    logger.error(f"Security questions not found for user: {username}")
                    flash("Security questions not found.", "error")
                    return redirect(url_for('password_forgot'))
            else:
                # Increment failed attempts
                session['forgot_attempts'] = session.get('forgot_attempts', 0) + 1
                remaining = 5 - session['forgot_attempts']
                logger.warning(f"Failed password reset attempt for {username}. Remaining attempts: {remaining}")
                
                if remaining > 0:
                    flash(f"Invalid credentials. {remaining} attempts remaining.", "error")
                if session['forgot_attempts'] >= 5:
                    # Block further attempts for 5 minutes
                    session['forgot_blocked_until'] = time.time() + 300
                    session['forgot_attempts'] = 0
                    logger.warning(f"Password reset blocked for 5 minutes due to multiple failures for: {username}")
                    flash("Password reset temporarily locked. Try again in 5 minutes.", "error")
                return redirect(url_for('password_forgot'))

        return render_template("forgot_password.html")
        
    except Exception as e:
        # Log unexpected errors
        logger.error(f"Error in forgot_password: {str(e)}", exc_info=True)
        flash("An error occurred while processing your request. Please try again later.", "error")
        return redirect(url_for('index'))

def reset_security_questions():
    try:
        if request.method == "POST":
            # Check if temporarily blocked
            block_until = session.get('sq_blocked_until', 0)
            if time.time() < block_until:
                remaining = int(block_until - time.time())
                logger.warning(f"Blocked attempt to answer security questions - remaining time: {remaining}s")
                flash(f"Too many failed attempts. Try again in {remaining} seconds.", "error")
                return redirect(url_for('password_forgot'))

            # Initialise attempts if not already set
            if 'sq_attempts' not in session:
                session['sq_attempts'] = 0

            # Retrieve username from session
            username = session.get("reset_username")
            if not username:
                logger.error("Reset attempt without valid session")
                flash("Session expired. Please try again.", "error")
                return redirect(url_for('password_forgot'))

            # Retrieve answers from the form
            answer_1 = request.form.get("security_answer_1", "").strip().lower()
            answer_2 = request.form.get("security_answer_2", "").strip().lower()

            # Fetch correct answers from DB
            correct_answers = data_handler.check_security_answers(username)

            if correct_answers:
                correct_answer_1, correct_answer_2 = correct_answers

                if answer_1 == correct_answer_1 and answer_2 == correct_answer_2:
                    # Reset attempts on success
                    session.pop('sq_attempts', None)
                    session.pop('sq_blocked_until', None)
                    session["SQ_verify"] = True # Allow access to new_password
                    logger.info(f"Security questions answered correctly for: {username}")
                    return redirect(url_for('new_password'))
                else:
                    # Increment failed attempts
                    session['sq_attempts'] = session.get('sq_attempts', 0) + 1
                    remaining = 5 - session['sq_attempts']
                    logger.warning(f"Failed security question attempt for {username}. Remaining: {remaining}")
                    
                    if remaining > 0:
                        flash(f"Incorrect security answers. {remaining} attempts remaining.", "error")
                    if session['sq_attempts'] >= 5:
                        # Block further attempts for 5 minutes
                        session['sq_blocked_until'] = time.time() + 300
                        session['sq_attempts'] = 0
                        logger.warning(f"Security questions blocked for 5 minutes for: {username}")
                        flash("Security question verification temporarily locked. Try again in 5 minutes.", "warning")
                    return redirect(url_for('password_forgot'))
            else:
                # Log error if security answers are not found
                logger.error(f"Security answers not found for user: {username}")
                flash("Security answers not found.", "error")
                return redirect(url_for('password_forgot'))

        return render_template("reset_password.html")
        
    except Exception as e:
        # Log unexpected errors
        logger.error(f"Unexpected error in reset: {str(e)}", exc_info=True)
        flash("An unexpected error occurred. Please try again later.", "error")
        return redirect(url_for('password_forgot'))

def process_new_password():
    try:
        # Check if user is verified
        if not session.get("forgot_password_verified"):
            abort(403)  # Forbidden

        # Retrieve username and new password from session and form
        username = session.get("reset_username")
        new_password = request.form.get("new_password")
        confirm_new_password = request.form.get("confirm_password")

        # Password Check
        if new_password != confirm_new_password:
            flash("Passwords do not match", "error")
            return redirect(url_for("new_password"))

        if not data_handler.simple_check_password(new_password):
            flash("New password does not meet requirements", "error")
            return redirect(url_for("new_password"))

        # Update password in the database
        data_handler.update_user_password(username, new_password)

        # Clear session flags after reset
        session.pop("forgot_password_verified", None)
        session.pop("reset_username", None)
        session.pop("SQ_verify", None)

        flash("Password updated successfully! Please login with your new password.", "success")
        return redirect(url_for("login"))
    except Exception as e:
        # Log unexpected errors
        logger.error(f"Error in process_new_password: {str(e)}", exc_info=True)
        flash("An error occurred while resetting your password. Please try again later.", "error")
        return redirect(url_for("new_password"))