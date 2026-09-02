<?php
// profile.php

// Include the functions file
require_once "includes/functions.php";
require_once "includes/db.php"; // We need a direct DB connection for this page

// If the user is not logged in, redirect to login page
require_login();

// Get user ID from session
 $user_id = $_SESSION["id"];
 $username = $_SESSION["username"];

// Fetch user details
 $user_sql = "SELECT username, email, created_at, last_login FROM users WHERE id = ?";
 $user = null;
if ($stmt = $conn->prepare($user_sql)) {
    $stmt->bind_param("i", $user_id);
    $stmt->execute();
    $result = $stmt->get_result();
    $user = $result->fetch_assoc();
    $stmt->close();
}

// Fetch recent security logs for this user
 $logs_sql = "SELECT action, status, ip_address, created_at FROM security_logs WHERE user_id = ? ORDER BY created_at DESC LIMIT 10";
 $logs = [];
if ($stmt = $conn->prepare($logs_sql)) {
    $stmt->bind_param("i", $user_id);
    $stmt->execute();
    $result = $stmt->get_result();
    while ($row = $result->fetch_assoc()) {
        $logs[] = $row;
    }
    $stmt->close();
}
 $conn->close();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>My Profile - <?php echo htmlspecialchars($username); ?></title>
    <link rel="stylesheet" href="assets/css/style.css">
    <style>
        .profile-container { max-width: 800px; margin: 20px auto; padding: 20px; background: #fff; border-radius: 5px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        .profile-info, .security-logs { margin-bottom: 30px; }
        .profile-info h2, .security-logs h2 { border-bottom: 2px solid #eee; padding-bottom: 10px; }
        .log-entry { border-bottom: 1px solid #f0f0f0; padding: 10px 0; }
        .log-entry:last-child { border-bottom: none; }
        .log-entry .log-time { font-size: 0.9em; color: #888; }
    </style>
</head>
<body>
    <div class="profile-container">
        <h1>My Profile</h1>
        <div class="nav-links">
            <a href="dashboard.php">Home</a>
            <a href="profile.php">My Profile</a>
            <a href="security_settings.php">Security Settings</a>
            <a href="logout.php">Logout</a>
        </div>

        <div class="profile-info">
            <h2>Account Information</h2>
            <?php if ($user): ?>
                <p><strong>Username:</strong> <?php echo htmlspecialchars($user['username']); ?></p>
                <p><strong>Email:</strong> <?php echo htmlspecialchars($user['email']); ?></p>
                <p><strong>Member Since:</strong> <?php echo date("F j, Y", strtotime($user['created_at'])); ?></p>
                <p><strong>Last Login:</strong> <?php echo $user['last_login'] ? date("F j, Y, g:i a", strtotime($user['last_login'])) : 'Never'; ?></p>
            <?php else: ?>
                <p>Could not retrieve user information.</p>
            <?php endif; ?>
        </div>

        <div class="security-logs">
            <h2>Recent Activity Log</h2>
            <?php if (!empty($logs)): ?>
                <?php foreach ($logs as $log): ?>
                    <div class="log-entry">
                        <strong><?php echo ucfirst(htmlspecialchars($log['action'])); ?></strong> - 
                        <span style="color: <?php echo $log['status'] == 'success' ? 'green' : 'red'; ?>;">
                            <?php echo htmlspecialchars($log['status']); ?>
                        </span>
                        <div class="log-time">
                            IP: <?php echo htmlspecialchars($log['ip_address']); ?> on 
                            <?php echo date("F j, Y, g:i a", strtotime($log['created_at'])); ?>
                        </div>
                    </div>
                <?php endforeach; ?>
            <?php else: ?>
                <p>No recent activity found.</p>
            <?php endif; ?>
        </div>
    </div>
</body>
</html>