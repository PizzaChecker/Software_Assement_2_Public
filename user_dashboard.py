from flask import render_template, request, redirect, url_for, flash, session
import data_handler
import logging

logger = logging.getLogger(__name__)

def dash():
    try:
        profile_image = session.get('profile_image')
        username = session.get('Username_Login')  # session created in login
        user_data = data_handler.get_user_data(username)  # Retrieve user data

        if user_data is None:
            flash("User data not found.", "error")
            session.pop('Username_Login', None)  # Clear session if user data is not found
            session.pop('profile_image', None)  # Clear profile image session
            session.pop('Admin', None)  # Clear admin session if applicable
            return redirect(url_for('login'))  # Redirect to login if user data is not found

        # Format the mobile number to show only the last 4 digits
        if user_data['mobile']:
            user_data['mobile'] = "****" + user_data['mobile'][-4:]

        # Optionally, format the address to show only part of it
        if user_data['address']:
            address_parts = user_data['address'].split(",")
            if len(address_parts) > 1:
                user_data['address'] = address_parts[0] + ", ****"  # Show only the first part and hide the rest

        return user_data, profile_image
    except Exception as e:
        logger.critical(f"Error in dash function: {str(e)}", exc_info=True)
        flash("An error occurred while loading the dashboard.", "error")
        return redirect(url_for('login'))

def user_dash():
    try:
        if not session.get("Username_Login"):  # Session for user login successful (stores username)
            flash("Please login, in order to access the dashboard", "warning")
            return redirect(url_for("login"))
        
        user_data, profile_image = dash()
        if user_data.get('privilege_id') == 2:
            if session.get('Admin') == True:  # Set Admin flag based on privilege_id (True/False)
                return redirect(url_for('admin_dashboard'))  # Redirect to admin dashboard
            else:
                logger.warning("User with admin privilege did not have 'Admin' session variable set properly.")

        return render_template("/user_dashboard.html", user_data=user_data, profile_image=profile_image)
    except Exception as e:
        logger.error(f"Error in user_dash function: {str(e)}", exc_info=True)
        flash("An error occurred while accessing the user dashboard.", "error")
        return redirect(url_for('login'))