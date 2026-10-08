<?php
// dashboard.php

// Include the functions file to check login status
require_once "includes/functions.php";

// If the user is not logged in, redirect them to the login page
require_login();

// Define page title for the header (after auth so redirects can still send headers)
 $page_title = "Dashboard";

// Include the header
require_once "includes/header.php";

// Get the username from the session
 $username = $_SESSION['username'];
?>

<div class="dashboard-content">
    <h2>Welcome, <?php echo htmlspecialchars($username); ?>!</h2>
    <p>This is your secure dashboard. From here, you can manage your profile and security settings.</p>
    <p><strong>Next Steps:</strong> Feel free to setup security for your account.</p>
</div>

<?php
// Include the footer
require_once "includes/footer.php";
?>