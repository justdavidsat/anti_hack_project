<?php
// includes/functions.php

// Ensure the session is started on pages that use this file
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Include the database connection
require_once "db.php";

/**
 * Logs a security-related event to the database.
 * @param int $user_id The ID of the user performing the action (0 if not logged in).
 * @param string $action The action being performed (e.g., 'login_attempt', 'password_change').
 * @param string $status The result of the action (e.g., 'success', 'failed').
 * @param string $details Optional additional details.
 */
function log_security_event($user_id, $action, $status, $details = null) {
    global $conn; // Use the global connection object

    $ip_address = $_SERVER['REMOTE_ADDR'];
    $user_agent = $_SERVER['HTTP_USER_AGENT'];

    $sql = "INSERT INTO security_logs (user_id, ip_address, user_agent, action, status, details) VALUES (?, ?, ?, ?, ?, ?)";

    if ($stmt = $conn->prepare($sql)) {
        $stmt->bind_param("isssss", $user_id, $ip_address, $user_agent, $action, $status, $details);
        $stmt->execute();
        $stmt->close();
    }
}

/**
 * Checks if the current user is logged in.
 * @return bool True if logged in, false otherwise.
 */
function is_logged_in() {
    return isset($_SESSION["loggedin"]) && $_SESSION["loggedin"] === true;
}

/**
 * Redirects to a given URL if the user is not logged in.
 * @param string $url The URL to redirect to.
 */
function require_login() {
    if (!is_logged_in()) {
        header("location: login.php");
        exit;
    }
}
?>