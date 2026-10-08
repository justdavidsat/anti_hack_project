<?php
// logout.php
// Initialize the session
session_start();

// Include functions file
require_once "includes/functions.php";

// Capture the user ID before the session is cleared
 $logout_user_id = isset($_SESSION["id"]) ? $_SESSION["id"] : 0;

// Unset all of the session variables
 $_SESSION = array();

// Destroy the session.
session_destroy();

// Log the logout event against the account that logged out
log_security_event($logout_user_id, 'logout', 'success', 'User session destroyed.');

// Redirect to login page
header("location: login.php");
exit;
?>