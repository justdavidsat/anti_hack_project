<?php
// includes/header.php
// Start session if not already started
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo isset($page_title) ? htmlspecialchars($page_title) : 'Secure System'; ?></title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css">
    <link rel="stylesheet" href="assets/css/style.css">
</head>
<body>
    <div class="main-wrapper">
        <header class="main-header">
            <h1><i class="fas fa-shield-alt"></i> <?php echo isset($page_title) ? htmlspecialchars($page_title) : 'Secure System'; ?></h1>
            <?php if (isset($_SESSION["loggedin"]) && $_SESSION["loggedin"] === true): ?>
               <nav class="nav-links">
                <a href="dashboard.php"><i class="fas fa-home"></i> Home</a>
                <a href="profile.php"><i class="fas fa-user"></i> My Profile</a>
                <a href="security_settings.php"><i class="fas fa-cog"></i> Security Settings</a>
                <a href="audit.php"><i class="fas fa-clipboard-check"></i> Security Audit</a> <!-- NEW LINK -->
                <a href="logout.php"><i class="fas fa-sign-out-alt"></i> Logout</a>
            </nav>
            <?php endif; ?>
        </header>
        <main class="content-area">