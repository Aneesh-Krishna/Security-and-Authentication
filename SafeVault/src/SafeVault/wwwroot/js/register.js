// Shows a "Passwords do not match" message before the form is sent.
// This is only for convenience; the server checks the passwords match as well.
const password = document.getElementById("password");
const confirmPassword = document.getElementById("confirmPassword");

function validatePasswordMatch() {
    confirmPassword.setCustomValidity(
        confirmPassword.value === password.value ? "" : "Passwords do not match.");
}

password.addEventListener("input", validatePasswordMatch);
confirmPassword.addEventListener("input", validatePasswordMatch);
