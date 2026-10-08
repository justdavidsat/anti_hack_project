<?php
// index.php - application entry point
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

if (isset($_SESSION["loggedin"]) && $_SESSION["loggedin"] === true) {
    header("location: dashboard.php");
} else {
    header("location: login.php");
}
exit;
?>
