<?php
// logout.php
// Initialize the session
session_start();

// Include functions file
require_once "includes/functions.php";

// Unset all of the session variables
 $_SESSION = array();

// Destroy the session.
session_destroy();

// Log the logout event
log_security_event(0, 'logout', 'success', 'User session destroyed.');

// Redirect to login page
header("location: login.php");
exit;
?>