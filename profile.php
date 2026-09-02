<?php
// profile.php

require_once "includes/functions.php";
require_once "includes/db.php";

require_login();

$user_id = $_SESSION["id"];
$username = $_SESSION["username"];

$edit_success = $edit_err = "";
$pw_success = $pw_err = "";

// --- HANDLE PROFILE UPDATE ---
if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['update_profile'])) {
    $new_username = trim($_POST["new_username"]);
    $new_email = trim($_POST["new_email"]);

    if (empty($new_username) || empty($new_email)) {
        $edit_err = "Username and email cannot be empty.";
    } elseif (strlen($new_username) < 3) {
        $edit_err = "Username must be at least 3 characters.";
    } elseif (!filter_var($new_email, FILTER_VALIDATE_EMAIL)) {
        $edit_err = "Invalid email format.";
    } else {
        // Check if username is taken by another user
        $check_sql = "SELECT id FROM users WHERE username = ? AND id != ?";
        if ($stmt = $conn->prepare($check_sql)) {
            $stmt->bind_param("si", $new_username, $user_id);
            $stmt->execute();
            $stmt->store_result();
            if ($stmt->num_rows > 0) {
                $edit_err = "Username is already taken.";
            }
            $stmt->close();
        }

        // Check if email is taken by another user
        if (empty($edit_err)) {
            $check_sql = "SELECT id FROM users WHERE email = ? AND id != ?";
            if ($stmt = $conn->prepare($check_sql)) {
                $stmt->bind_param("si", $new_email, $user_id);
                $stmt->execute();
                $stmt->store_result();
                if ($stmt->num_rows > 0) {
                    $edit_err = "Email is already taken.";
                }
                $stmt->close();
            }
        }

        if (empty($edit_err)) {
            $update_sql = "UPDATE users SET username = ?, email = ? WHERE id = ?";
            if ($stmt = $conn->prepare($update_sql)) {
                $stmt->bind_param("ssi", $new_username, $new_email, $user_id);
                if ($stmt->execute()) {
                    $_SESSION["username"] = $new_username;
                    $username = $new_username;
                    $edit_success = "Profile updated successfully!";
                    log_security_event($user_id, 'profile_update', 'success', 'User updated profile information.');
                } else {
                    $edit_err = "Something went wrong. Please try again.";
                }
                $stmt->close();
            }
        }
    }
}

// --- HANDLE PASSWORD CHANGE ---
if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['change_password'])) {
    $current_password = trim($_POST["current_password"]);
    $new_password = trim($_POST["new_password"]);
    $confirm_password = trim($_POST["confirm_password"]);

    if (empty($current_password) || empty($new_password) || empty($confirm_password)) {
        $pw_err = "All password fields are required.";
    } elseif ($new_password !== $confirm_password) {
        $pw_err = "New passwords do not match.";
    } elseif (strlen($new_password) < 6) {
        $pw_err = "New password must be at least 6 characters.";
    } else {
        $sql = "SELECT password FROM users WHERE id = ?";
        if ($stmt = $conn->prepare($sql)) {
            $stmt->bind_param("i", $user_id);
            $stmt->execute();
            $stmt->bind_result($hashed_password);
            $stmt->fetch();
            $stmt->close();

            if (password_verify($current_password, $hashed_password)) {
                $new_hashed = password_hash($new_password, PASSWORD_DEFAULT);
                $update_sql = "UPDATE users SET password = ? WHERE id = ?";
                if ($update_stmt = $conn->prepare($update_sql)) {
                    $update_stmt->bind_param("si", $new_hashed, $user_id);
                    $update_stmt->execute();
                    $update_stmt->close();
                    $pw_success = "Password changed successfully!";
                    log_security_event($user_id, 'password_change', 'success', 'User changed their password from profile page.');
                }
            } else {
                $pw_err = "Current password is incorrect.";
                log_security_event($user_id, 'password_change', 'failed', 'Incorrect current password entered from profile page.');
            }
        }
    }
}

// --- FETCH USER DATA ---
$user_sql = "SELECT username, email, created_at, last_login FROM users WHERE id = ?";
$user = null;
if ($stmt = $conn->prepare($user_sql)) {
    $stmt->bind_param("i", $user_id);
    $stmt->execute();
    $result = $stmt->get_result();
    $user = $result->fetch_assoc();
    $stmt->close();
}

// Fetch recent security logs
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
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>My Profile - <?php echo htmlspecialchars($username); ?></title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css">
    <link rel="stylesheet" href="assets/css/style.css">
    <style>
        .profile-container { max-width: 900px; margin: 20px auto; }
        .profile-section { background: #fff; border-radius: 12px; box-shadow: 0 4px 15px rgba(0,0,0,0.06); padding: 30px; margin-bottom: 25px; }
        .profile-section h2 { color: var(--primary-color); margin-bottom: 20px; border-bottom: 2px solid var(--border-color); padding-bottom: 10px; }
        .profile-info-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 15px; }
        .profile-info-grid p { background: var(--light-accent-color); padding: 12px 15px; border-radius: 8px; }
        .profile-info-grid p strong { color: var(--primary-color); }
        .profile-actions { display: flex; gap: 10px; margin-top: 15px; }
        .btn-edit { width: auto; padding: 10px 25px; background-color: var(--secondary-color); }
        .btn-secondary { width: auto; padding: 10px 25px; background-color: #6c757d; }
        .form-row { display: grid; grid-template-columns: 1fr 1fr; gap: 15px; }
        .log-entry { padding: 12px 0; border-bottom: 1px solid var(--border-color); }
        .log-entry:last-child { border-bottom: none; }
        .log-time { font-size: 0.85em; color: var(--muted-text-color); margin-top: 4px; }
    </style>
</head>
<body>
    <div class="main-wrapper">
        <header class="main-header">
            <h1><i class="fas fa-shield-alt"></i> Secure System</h1>
            <nav class="nav-links">
                <a href="dashboard.php"><i class="fas fa-home"></i> Home</a>
                <a href="profile.php" class="active"><i class="fas fa-user"></i> My Profile</a>
                <a href="security_settings.php"><i class="fas fa-cog"></i> Security Settings</a>
                <a href="audit.php"><i class="fas fa-clipboard-check"></i> Security Audit</a>
                <a href="logout.php"><i class="fas fa-sign-out-alt"></i> Logout</a>
            </nav>
        </header>

        <main class="content-area">
            <div class="profile-container">
                <!-- Account Information -->
                <div class="profile-section">
                    <h2><i class="fas fa-user-circle"></i> Account Information</h2>
                    <?php if ($user): ?>
                        <div class="profile-info-grid">
                            <p><strong>Username:</strong> <?php echo htmlspecialchars($user['username']); ?></p>
                            <p><strong>Email:</strong> <?php echo htmlspecialchars($user['email']); ?></p>
                            <p><strong>Member Since:</strong> <?php echo date("F j, Y", strtotime($user['created_at'])); ?></p>
                            <p><strong>Last Login:</strong> <?php echo $user['last_login'] ? date("F j, Y, g:i a", strtotime($user['last_login'])) : 'Never'; ?></p>
                        </div>
                    <?php else: ?>
                        <p>Could not retrieve user information.</p>
                    <?php endif; ?>
                </div>

                <!-- Edit Profile Section -->
                <div class="profile-section">
                    <h2><i class="fas fa-edit"></i> Edit Profile</h2>
                    <?php if (!empty($edit_err)) { echo '<div class="alert-error">' . $edit_err . '</div>'; } ?>
                    <?php if (!empty($edit_success)) { echo '<div class="alert-success">' . $edit_success . '</div>'; } ?>
                    <form action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post">
                        <div class="form-row">
                            <div class="form-group">
                                <label>Username</label>
                                <input type="text" name="new_username" value="<?php echo htmlspecialchars($user['username']); ?>">
                            </div>
                            <div class="form-group">
                                <label>Email</label>
                                <input type="email" name="new_email" value="<?php echo htmlspecialchars($user['email']); ?>">
                            </div>
                        </div>
                        <div class="form-group">
                            <input type="submit" name="update_profile" class="btn btn-edit" value="Update Profile">
                        </div>
                    </form>
                </div>

                <!-- Change Password Section -->
                <div class="profile-section">
                    <h2><i class="fas fa-lock"></i> Change Password</h2>
                    <?php if (!empty($pw_err)) { echo '<div class="alert-error">' . $pw_err . '</div>'; } ?>
                    <?php if (!empty($pw_success)) { echo '<div class="alert-success">' . $pw_success . '</div>'; } ?>
                    <form action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post">
                        <div class="form-group">
                            <label>Current Password</label>
                            <input type="password" name="current_password">
                        </div>
                        <div class="form-row">
                            <div class="form-group">
                                <label>New Password</label>
                                <input type="password" name="new_password">
                            </div>
                            <div class="form-group">
                                <label>Confirm New Password</label>
                                <input type="password" name="confirm_password">
                            </div>
                        </div>
                        <div class="form-group">
                            <input type="submit" name="change_password" class="btn btn-edit" value="Change Password">
                        </div>
                    </form>
                </div>

                <!-- Recent Activity Log -->
                <div class="profile-section">
                    <h2><i class="fas fa-history"></i> Recent Activity</h2>
                    <?php if (!empty($logs)): ?>
                        <?php foreach ($logs as $log): ?>
                            <div class="log-entry">
                                <strong><?php echo ucfirst(htmlspecialchars(str_replace('_', ' ', $log['action']))); ?></strong> -
                                <span style="color: <?php echo $log['status'] == 'success' ? 'var(--success-color)' : 'var(--error-color)'; ?>;">
                                    <?php echo htmlspecialchars($log['status']); ?>
                                </span>
                                <div class="log-time">
                                    <i class="fas fa-globe"></i> IP: <?php echo htmlspecialchars($log['ip_address']); ?> |
                                    <i class="fas fa-clock"></i> <?php echo date("F j, Y, g:i a", strtotime($log['created_at'])); ?>
                                </div>
                            </div>
                        <?php endforeach; ?>
                    <?php else: ?>
                        <p>No recent activity found.</p>
                    <?php endif; ?>
                </div>
            </div>
        <?php include "includes/footer.php"; ?>
