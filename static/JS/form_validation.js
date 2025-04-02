// form_validation.js

// Common function to validate the password field
function validatePassword(password, passwordErrorMessage) {
    passwordErrorMessage.textContent = ""; // Clear previous error messages

    // Password length validation
    if (password.length < 8) {
        passwordErrorMessage.textContent = "Password must be at least 8 characters long.";
        return false;
    }
    if (password.length > 20) {
        passwordErrorMessage.textContent = "Password must be no more than 20 characters long.";
        return false;
    }

    // Password spaces check
    if (/\s/.test(password)) {
        passwordErrorMessage.textContent = "Password cannot contain spaces.";
        return false;
    }

    // Password uppercase check
    if (!/[A-Z]/.test(password)) {
        passwordErrorMessage.textContent = "Password must contain at least one uppercase letter.";
        return false;
    }

    // Password lowercase check
    if (!/[a-z]/.test(password)) {
        passwordErrorMessage.textContent = "Password must contain at least one lowercase letter.";
        return false;
    }

    // Password digit check
    if (!/[0-9]/.test(password)) {
        passwordErrorMessage.textContent = "Password must contain at least one digit.";
        return false;
    }

    // Password special character check
    if (!/[@$!%*?&]/.test(password)) {
        passwordErrorMessage.textContent = "Password must contain at least one special character (@$!%*?&).";
        return false;
    }

    return true;
}

// Function to validate the mobile number (only for signup form & forgot_password)
function validateMobileNumber(mobile, mobileErrorMessage) {
    mobileErrorMessage.textContent = ""; // Clear previous error messages
    if (!/^[0-9]{10}$/.test(mobile)) {//Only number from 0-9 and has to be exactly 10 numbers, no spaces
        mobileErrorMessage.textContent = "Mobile number must be exactly 10 digits.";
        return false;
    }
    return true;
}

function validateUsername(username, usernameErrorMessage) {
    usernameErrorMessage.textContent = ""; // Clear previous error messages

    // Check for length (3-9 characters)
    if (username.length < 3 || username.length > 9) {
        usernameErrorMessage.textContent = "Username must be between 3 and 9 characters long.";
        return false;
    }

    // Check for valid characters (a-z, 0-9, and underscores)
    if (!/^[a-zA-Z0-9_]+$/.test(username)) {
        usernameErrorMessage.textContent = "Username must only contain letters (a-z, A-Z), digits (0-9), and underscores (_).";
        return false;
    }

    return true; // If all checks pass
}

// Function to sanitise and validate input fields
function sanitiseInput(inputField) {
    const inputValue = inputField.value.trim(); // Trim whitespace
    // Escape special characters to prevent XSS
    const sanitisedValue = inputValue
        .replace(/&/g, "&amp;") // Escape ampersands
        .replace(/</g, "&lt;") // Escape less-than signs
        .replace(/>/g, "&gt;") // Escape greater-than signs
        .replace(/"/g, "&quot;") // Escape double quotes
        .replace(/'/g, "&#39;") // Escape single quotes
        .replace(/`/g, "&#96;") // Escape backticks
        .replace(/\(/g, "&#40;") // Escape left parentheses
        .replace(/\)/g, "&#41;") // Escape right parentheses
        .replace(/\//g, "&#47;") // Escape forward slashes
        .replace(/\\/g, "&#92;"); // Escape backslashes
    
    inputField.value = sanitisedValue;
    return true;
}

// Function to disable the submit button to prevent double submission
function disableSubmitButton(form) {
    const submitButton = form.querySelector("button[type='submit'], input[type='submit']"); // Find the submit button within the form
    if (submitButton) {
        submitButton.disabled = true;
    }
}

document.getElementById("forgot_password")?.addEventListener("submit", function (event) {// Every part Works
    const username = document.getElementById("username").value;
    const usernameErrorMessage = document.getElementById("username-error-message");

    const mobile = document.getElementById("mobile").value;
    const mobileErrorMessage = document.getElementById("mobile-error-message");
    // Validate mobile number
    if (!validateUsername(username, usernameErrorMessage)) {
        event.preventDefault(); // Prevent form submission
        return;
    }

    // Validate mobile number
    if (!validateMobileNumber(mobile, mobileErrorMessage)) {
        event.preventDefault(); // Prevent form submission
        return;
    }
    // Sanitise the inputs before validation
    sanitiseInput(document.getElementById("username"));
    sanitiseInput(document.getElementById("mobile"));
    disableSubmitButton(this);
});

document.getElementById("forgot_password_sq")?.addEventListener("submit", function (event) {
    // Sanitise the inputs before validation
    sanitiseInput(document.getElementById("security-answer-1"));
    sanitiseInput(document.getElementById("security-answer-2"));
    disableSubmitButton(this);
});

// Password reset form validation
document.getElementById("process_new_plw")?.addEventListener("submit", function (event) {// Every part Works
    const newPassword = document.getElementById("new_password").value;
    const confirmPassword = document.getElementById("confirm_password").value;
    const passwordErrorMessage = document.getElementById("password-error-message");

    // Validate password
    if (!validatePassword(newPassword, passwordErrorMessage)) {
        event.preventDefault(); // Prevent form submission
        return;
    }

    // Check if new password and confirm password match
    if (newPassword !== confirmPassword) {
        passwordErrorMessage.textContent = "Passwords do not match.";
        event.preventDefault(); // Prevent form submission
        return;
    }
    // Sanitise the inputs before validation
    sanitiseInput(document.getElementById("new_password"));
    sanitiseInput(document.getElementById("confirm_password"));
    disableSubmitButton(this);
});

// Login form validation/sanitisation
document.getElementById("login_form")?.addEventListener("submit", function (event) {// Every part Works
    // const password = document.getElementById("password").value;
    const username = document.getElementById("username").value;
    const passwordErrorMessage = document.getElementById("password-error-message")
    // Validate password not needed for login as the 5 attempts are handled by the server and would not be able to check client side

    // Validate mobile number
    if (!validateUsername(username, passwordErrorMessage)) {
        passwordErrorMessage.textContent = "Invalid username or password. Ensure your username contains 3-9 characters, and only contain letters, numbers, and underscores."
        event.preventDefault(); // Prevent form submission
        return;
    }

    // Sanitise the inputs before validation
    sanitiseInput(document.getElementById("password"));
    sanitiseInput(document.getElementById("username"));
    disableSubmitButton(this);
});


// Signup form validation
document.getElementById("reg-form")?.addEventListener("submit", function (event) {// Every part Works
    const password = document.getElementById("password").value;
    const passwordErrorMessage = document.getElementById("password-error-message");

    const mobile = document.getElementById("mobile").value;
    const mobileErrorMessage = document.getElementById("mobile-error-message");
    
    const username = document.getElementById("username").value;
    const usernameErrorMessage = document.getElementById("username-error-message");

    

    if (!validatePassword(password, passwordErrorMessage)){
        event.preventDefault(); // Prevent form submission
        return;
    }

    // Validate mobile number
    if (!validateMobileNumber(mobile, mobileErrorMessage)) {
        event.preventDefault(); // Prevent form submission
        return;
    }

    // Validate mobile number
    if (!validateUsername(username, usernameErrorMessage)) {
        event.preventDefault(); // Prevent form submission
        return;
    }
    // Sanitise the inputs before validation
    sanitiseInput(document.getElementById("password"));// Sanitise password
    sanitiseInput(document.getElementById("mobile"));// Sanitise mobile number
    sanitiseInput(document.getElementById("username"));// Sanitise username
    sanitiseInput(document.getElementById("address"));// 
    sanitiseInput(document.getElementById("security-answer-1")); // Sanitise sqa1
    sanitiseInput(document.getElementById("security-answer-2"));// Sanitise sqa2
    sanitiseInput(document.getElementById("security-question-1")); // Sanitise sq1
    sanitiseInput(document.getElementById("security-question-2"));// Sanitise sq2
    disableSubmitButton(this);
});

document.getElementById("user_search")?.addEventListener("submit", function (event) {// Every part Works
    // Sanitise the inputs before validation
    sanitiseInput(document.getElementById("search_query"));
    disableSubmitButton(this);
});


document.getElementById("edit_user")?.addEventListener("submit", function (event) {// Every part Works
    const username = document.getElementById("username").value;
    const usernameErrorMessage = document.getElementById("username-error-message");
    //const usernameErrorMessage = "Invalid username or password. Ensure your username contains 3-9 characters, and only contain letters, numbers, and underscores.";

    const mobile = document.getElementById("mobile").value;
    const mobileErrorMessage = document.getElementById("mobile-error-message");
    //const mobileErrorMessage = "ensure your mobile number is exatly 10 numbers, no spaces";
    // // Validate mobile number
    if (!validateUsername(username, usernameErrorMessage)) {
        event.preventDefault(); // Prevent form submission
        return;
    }

    // Validate mobile number
    if (!validateMobileNumber(mobile, mobileErrorMessage)) {
        event.preventDefault(); // Prevent form submission
        return;
    }
    // Sanitise the inputs before validation
    sanitiseInput(document.getElementById("username"));
    sanitiseInput(document.getElementById("mobile"));
    disableSubmitButton(this);
});


// If all checks pass, the form will be submitted where it will undergo another set of checks sever side