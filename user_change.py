from flask import render_template, request, redirect, url_for, flash, session, abort
import data_handler
import logging
from admin_dashboard import session_check_admin
from lock_manager import lock_manager
import sqlite3

logger = logging.getLogger(__name__)

def user_edit(user_id):
    try:
        redirect_response = session_check_admin() # Check if the user is logged in as admin
        if redirect_response:
            return redirect_response

        admin_username = session.get('Username_Login')  # Get admin username from session for lock management
        if not admin_username:
            logger.warning(f"Unauthorised edit attempt for user {user_id}")
            abort(403)

        # Only check existing lock for new edit attempts (GET requests)
        if request.method == "GET":
            try:
                if lock_manager.is_locked(user_id):
                    lock_holder = lock_manager.get_lock_holder(user_id)
                    if lock_holder != admin_username:
                        flash(f"This user is currently being edited by administrator '{lock_holder}'", "warning")
                        return redirect(url_for('admin_dashboard'))
                    # If same admin, continue with existing lock
                    return render_template("edit_user.html", user_data=data_handler.get_user_by_id(user_id))

                # Try to acquire lock for new edit
                if not lock_manager.acquire_lock(user_id, admin_username):
                    flash("Could not acquire lock for editing this user. Please try again later.", "warning")
                    return redirect(url_for('admin_dashboard'))
                
                user_data = data_handler.get_user_by_id(user_id)
                if user_data is None:
                    lock_manager.release_lock(user_id, admin_username)  # Release lock if user not found
                    flash("User not found.", "error")
                    return redirect(url_for('admin_dashboard'))
                return render_template("edit_user.html", user_data=user_data)
            except Exception as e:
                logger.error(f"Error during GET request in user_edit: {str(e)}", exc_info=True)
                abort(500)

        # Handle POST request
        elif request.method == "POST":
            try:
                # Retrieve form data
                username = request.form.get("username")
                mobile = request.form.get("mobile")
                privilege_id = request.form.get("privilege_id")

                #Check if valid format of username
                if not data_handler.validate_number(mobile):
                    flash("Invalid mobile number", "error")
                    return
                
                #Check if valid format of username
                if not data_handler.validate_username(username):
                    flash("Invalid username. It must be 3-9 characters long and can only contain letters, numbers, and underscores.", "error")
                    return

                success = data_handler.update_user(user_id, username, mobile, privilege_id) # Update user in the database
                if success:
                    flash("User updated successfully.", "success")
                    logger.info(f"User {user_id} updated successfully by {admin_username}.")
                else:
                    flash("Error updating user.", "error")
            except Exception as e:
                logger.error(f"Error during POST request in user_edit: {str(e)}", exc_info=True)
                flash(f"An error occurred while editing user: {str(e)}", "error")
            finally:
                lock_manager.release_lock(user_id, admin_username)  # Always release lock after POST
                return redirect(url_for('admin_dashboard'))
    except sqlite3.Error as e:
        logger.error(f"Database error in user_edit: {str(e)}", exc_info=True)
        flash("An error occurred while accessing the database.", "error") # Flash message because user is admin
        return redirect(url_for('admin_dashboard'))
    except Exception as e:
        logger.critical(f"Critical error in user_edit: {str(e)}", exc_info=True)
        abort(500)

def user_delete(user_id):
    try:
        redirect_response = session_check_admin()
        if redirect_response:
            return redirect_response

        # Get admin username for lock management
        admin_username = session.get('Username_Login')
        if not admin_username:
            abort(403)

        if not session.get('Admin_DELETE'):
            flash("Access is forbidden!")
            return redirect(url_for("index"))

        # Check if user is currently being edited
        if lock_manager.is_locked(user_id):
            flash("This user is currently being edited. Please wait until editing is complete.", "warning")
            return redirect(url_for('admin_dashboard'))

        # Try to acquire lock for deletion
        if not lock_manager.acquire_lock(user_id, admin_username):
            flash("Could not acquire lock for deleting this user. Please try again later.", "warning")
            return redirect(url_for('admin_dashboard'))

        try:
            success = data_handler.delete_user(user_id)
            if success:
                flash("User deleted successfully.", "success")
            else:
                flash("Error deleting user.", "error")
            session.pop("Admin_DELETE", None)
            return redirect(url_for('admin_dashboard'))
        except Exception as e:
            logger.critical(f"Error during user deletion: {str(e)}", exc_info=True)
            flash(f"An error occurred while deleting user: {str(e)}", "error") # Flash error message because user is admin
        finally:
            lock_manager.release_lock(user_id, admin_username)# Always release lock after delete attempt
    except Exception as e:
        logger.critical(f"Critical error in user_delete: {str(e)}", exc_info=True)
        flash(f"An error occurred while deleting user: {str(e)}", "error") # Flash error message because user is admin
        abort(500)