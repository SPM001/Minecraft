// Password visibility toggle function
function togglePasswordVisibility(passwordId, toggleIconId) {
    const passwordInput = document.getElementById(passwordId);
    const toggleIcon = document.getElementById(toggleIconId);
    const isPassword = passwordInput.getAttribute('type') === 'password';
    
    passwordInput.setAttribute('type', isPassword ? 'text' : 'password');
    toggleIcon.classList.toggle('fa-eye');
    toggleIcon.classList.toggle('fa-eye-slash');
}

// Form validation and submission
function validateForm(event) {
    event.preventDefault();

    // Clear previous error messages
    document.getElementById('emailError').textContent = '';
    document.getElementById('passwordError').textContent = '';
    document.getElementById('formError').textContent = '';

    const email = document.getElementById('usermail').value.trim();
    const password = document.getElementById('passlog').value.trim();
    let hasError = false;

    // Email validation
    const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailPattern.test(email)) {
        document.getElementById('emailError').textContent = 'Please enter a valid email address.';
        hasError = true;
    }

    // Password validation (minimum 8 characters)
    if (password.length < 8) {
        document.getElementById('passwordError').textContent = 'Password must be at least 8 characters long.';
        hasError = true;
    }

    if (hasError) return;

    // Submit the form data using fetch
    fetch('/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: email, password: password }),
        credentials: 'include' // Include credentials for session cookies
    })
    .then(response => response.json().then(data => {
        if (!response.ok) {
            throw new Error(data.message || 'Login failed.');
        }
        return data;
    }))
    .then(data => {
        if (data.success) {
            // Redirect based on user role
            window.location.href = data.role === 'admin' ? '/admin_dashboard.html' : '/dashboard.html';
        } else {
            // Display form error message
            document.getElementById('formError').textContent = data.message;
        }
    })
    .catch(error => {
        console.error('Error during login:', error);
        document.getElementById('formError').textContent = error.message || 'An error occurred during login.';
    });
}
