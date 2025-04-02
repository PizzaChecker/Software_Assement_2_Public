// colour_change_val.js changes clours based on if input passes requirements

// Check if the username input exists before adding event listener
const usernameInput = document.getElementById("username");
if (usernameInput) {
    usernameInput.addEventListener("input", validateUsernameColor); // Add event listener only if element exists
}

// Check if the password inputs exist before adding event listeners
const passwordFields = document.querySelectorAll("#password, #new_password");
passwordFields.forEach((input) => {
    if (input) {
        input.addEventListener("input", validatePasswordColor);  // Ensure element exists before adding listener
    }
});

// Check if the mobile input exists before adding event listener
const mobileInput = document.getElementById("mobile");
if (mobileInput) {
    mobileInput.addEventListener("input", validateMobileColor); // Prevents error if mobile input is missing
}

// Show requirements and reset colo
function showRequirements(id) {
    const requirementsList = document.getElementById(id);
    if (!requirementsList) return; // Ensure element exists before modifying it
    requirementsList.style.display = "block";

    // Trigger validation based on input type
    if (id === "username-requirements") {
        validateUsernameColor();
    } else if (id === "password-requirements") {
        const passwordInput = document.getElementById("password") || document.getElementById("new_password");
        if (passwordInput) {
            validatePasswordColor(passwordInput);
        }
    } else if (id === "mobile-requirements") {
        validateMobileColor();
    }
}

function hideRequirements(id) {
    const requirementsList = document.getElementById(id);
    if (requirementsList) {
        requirementsList.style.display = "none"; // Ensure element exists before modifying it
    }
}

function validateUsernameColor() {
    const usernameInput = document.getElementById("username");
    if (!usernameInput) return; // Prevents errors if username field is missing

    const username = usernameInput.value;
    const requirementsList = document.getElementById("username-requirements");
    if (!requirementsList) return; // Prevents errors if requirements list is missing

    const items = requirementsList.getElementsByTagName("li");

    // Check each requirement and update color
    items[0].style.color = username.length >= 3 && username.length <= 9 ? "green" : "red"; // Length
    items[1].style.color = /^[a-zA-Z0-9_]{3,9}$/.test(username) ? "green" : "red"; // Allowed characters
    items[2].style.color = !/\s/.test(username) ? "green" : "red"; // No spaces
}

//Validate password

function validatePasswordColor(event) {
    const passwordInput = event.target || event; // Allow both event-based and direct function calls
    if (!passwordInput) return; // Prevent errors if input is missing

    const password = passwordInput.value;
    const requirementsList = document.getElementById("password-requirements");
    if (!requirementsList) return; // Prevents errors if requirements list is missing

    const items = requirementsList.getElementsByTagName("li");

     // Check each requirement and update color
    items[0].style.color = password.length >= 8 && password.length <= 20 ? "green" : "red"; // Length
    items[1].style.color = /[A-Z]/.test(password) ? "green" : "red"; // Uppercase
    items[2].style.color = /[a-z]/.test(password) ? "green" : "red"; // Lowercase
    items[3].style.color = /[0-9]/.test(password) ? "green" : "red"; // Digit
    items[4].style.color = /[@$!%*?&]/.test(password) ? "green" : "red"; // Special character
    items[5].style.color = !/\s/.test(password) ? "green" : "red"; // No spaces
}

// validate moble
function validateMobileColor() {
    const mobileInput = document.getElementById("mobile");
    if (!mobileInput) return; // Prevents errors if mobile field is missing

    const mobile = mobileInput.value;
    const requirementsList = document.getElementById("mobile-requirements");
    if (!requirementsList) return; // Prevents errors if requirements list is missing

    const items = requirementsList.getElementsByTagName("li");

    // Check each requirement and update color
    items[0].style.color = mobile.length === 10 && /^[0-9]+$/.test(mobile) ? "green" : "red"; // Length and digits
    items[1].style.color = !/\s/.test(mobile) ? "green" : "red"; // No spaces
}