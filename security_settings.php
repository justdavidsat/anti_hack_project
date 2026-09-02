<?php
// security_settings.php

// Include the functions file
require_once "includes/functions.php";
require_once "includes/db.php";

// If the user is not logged in, redirect to login page
require_login();

// Get user ID from session
 $user_id = $_SESSION["id"];
 $username = $_SESSION["username"];

// Initialize variables and messages
 $current_password = $new_password = $confirm_password = "";
 $password_err = $password_success = $two_fa_success = "";

// --- PROCESS FORM SUBMISSIONS ---
if ($_SERVER["REQUEST_METHOD"] == "POST") {

    // --- Handle Password Change ---
    if (isset($_POST['change_password'])) {
        // Get and validate inputs
        $current_password = trim($_POST["current_password"]);
        $new_password = trim($_POST["new_password"]);
        $confirm_password = trim($_POST["confirm_password"]);

        if (empty($password_err)) {
            // Fetch user's current hashed password
            $sql = "SELECT password FROM users WHERE id = ?";
            if ($stmt = $conn->prepare($sql)) {
                $stmt->bind_param("i", $user_id);
                $stmt->execute();
                $stmt->bind_result($hashed_password);
                $stmt->fetch();
                $stmt->close();

                // Verify current password
                if (password_verify($current_password, $hashed_password)) {
                    // Validate new password
                    if ($new_password !== $confirm_password) {
                        $password_err = "New passwords do not match.";
                    } elseif (strlen($new_password) < 6) {
                        $password_err = "New password must be at least 6 characters.";
                    } else {
                        // Hash the new password and update
                        $new_hashed_password = password_hash($new_password, PASSWORD_DEFAULT);
                        $update_sql = "UPDATE users SET password = ? WHERE id = ?";
                        if ($update_stmt = $conn->prepare($update_sql)) {
                            $update_stmt->bind_param("si", $new_hashed_password, $user_id);
                            $update_stmt->execute();
                            $update_stmt->close();
                            $password_success = "Password changed successfully!";
                            log_security_event($user_id, 'password_change', 'success', 'User changed their password.');
                        }
                    }
                } else {
                    $password_err = "The current password you entered is not valid.";
                    log_security_event($user_id, 'password_change', 'failed', 'User entered incorrect current password.');
                }
            }
        }
    }

       // --- Handle 2FA Toggle ---
    if (isset($_POST['toggle_2fa'])) {
        // An unchecked checkbox is NOT sent in the POST request.
        // We check if it exists (isset) to determine if it was checked.
        $is_checked = isset($_POST['two_factor_enabled']);
        
        // Determine the new status (1 for enabled, 0 for disabled)
        $new_2fa_status = $is_checked ? 1 : 0;
        
        // Create a clear text version for messages and logs
        $status_text = $new_2fa_status ? 'enabled' : 'disabled';

        $update_sql = "UPDATE users SET two_factor_enabled = ? WHERE id = ?";
        if ($stmt = $conn->prepare($update_sql)) {
            $stmt->bind_param("ii", $new_2fa_status, $user_id);
            if ($stmt->execute()) {
                $two_fa_success = "Two-Factor Authentication has been <strong>" . $status_text . "</strong>.";
                
                // Log the action with a very clear message
                $log_details = "User successfully $status_text Two-Factor Authentication.";
                log_security_event($user_id, '2fa_toggle', 'success', $log_details);
            } else {
                // Log a failure if the database update failed
                log_security_event($user_id, '2fa_toggle', 'failed', 'Database update failed for 2FA toggle.');
            }
            $stmt->close();
        }
    }
}

// --- FETCH DATA FOR DISPLAY ---
// Fetch current 2FA status
 $user_sql = "SELECT two_factor_enabled FROM users WHERE id = ?";
 $user_data = ['two_factor_enabled' => 0];
if ($stmt = $conn->prepare($user_sql)) {
    $stmt->bind_param("i", $user_id);
    $stmt->execute();
    $result = $stmt->get_result();
    $user_data = $result->fetch_assoc();
    $stmt->close();
}

// Fetch all security logs for the user (with pagination)
 $page = isset($_GET['page']) && is_numeric($_GET['page']) ? (int)$_GET['page'] : 1;
 $logs_per_page = 20;
 $offset = ($page - 1) * $logs_per_page;

 $logs_sql = "SELECT action, status, ip_address, details, created_at FROM security_logs WHERE user_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?";
 $logs = [];
if ($stmt = $conn->prepare($logs_sql)) {
    $stmt->bind_param("iii", $user_id, $logs_per_page, $offset);
    $stmt->execute();
    $result = $stmt->get_result();
    while ($row = $result->fetch_assoc()) {
        $logs[] = $row;
    }
    $stmt->close();
}

// Get total number of logs for pagination
 $count_sql = "SELECT COUNT(id) as total FROM security_logs WHERE user_id = ?";
 $total_logs = 0;
if ($stmt = $conn->prepare($count_sql)) {
    $stmt->bind_param("i", $user_id);
    $stmt->execute();
    $stmt->bind_result($total_logs);
    $stmt->fetch();
    $stmt->close();
}
 $total_pages = ceil($total_logs / $logs_per_page);

 $conn->close();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Security Settings - <?php echo htmlspecialchars($username); ?></title>
    <link rel="stylesheet" href="assets/css/style.css">
    <style>
        .settings-container { max-width: 900px; margin: 20px auto; padding: 20px; background: #fff; border-radius: 5px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        .settings-section { margin-bottom: 40px; border-bottom: 1px solid #eee; padding-bottom: 20px; }
        .settings-section:last-child { border-bottom: none; }
        .settings-section h2 { margin-bottom: 15px; }
        .log-table { width: 100%; border-collapse: collapse; }
        .log-table th, .log-table td { padding: 10px; border: 1px solid #ddd; text-align: left; }
        .log-table th { background-color: #f2f2f2; }
        .pagination { margin-top: 20px; text-align: center; }
        .pagination a, .pagination span { padding: 8px 16px; text-decoration: none; color: #007bff; border: 1px solid #ddd; margin: 0 4px; }
        .pagination a:hover { background-color: #ddd; }
        .pagination .active { background-color: #007bff; color: white; border-color: #007bff; }
    </style>
</head>
<body>
    <div class="settings-container">
        <h1>Security Settings</h1>
        <div class="nav-links">
            <a href="dashboard.php">Home</a>
            <a href="profile.php">My Profile</a>
            <a href="security_settings.php">Security Settings</a>
            <a href="logout.php">Logout</a>
        </div>

        <!-- Password Change Section -->
        <div class="settings-section">
            <h2>Change Password</h2>
            <?php if(!empty($password_err)) { echo '<div class="alert-error">' . $password_err . '</div>'; } ?>
            <?php if(!empty($password_success)) { echo '<div class="alert-success">' . $password_success . '</div>'; } ?>
            <form action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post">
                <div class="form-group">
                    <label>Current Password</label>
                    <input type="password" name="current_password">
                </div>
                <div class="form-group">
                    <label>New Password</label>
                    <input type="password" name="new_password">
                </div>
                <div class="form-group">
                    <label>Confirm New Password</label>
                    <input type="password" name="confirm_password">
                </div>
                <div class="form-group">
                    <input type="submit" name="change_password" class="btn" value="Change Password">
                </div>
            </form>
        </div>

        <!-- 2FA Section -->
        <div class="settings-section">
            <h2>Two-Factor Authentication (2FA)</h2>
            <p><em>Note: This is a simulated 2FA toggle for demonstration purposes. In a real application, this would integrate with an authenticator app.</em></p>
            <?php if(!empty($two_fa_success)) { echo '<div class="alert-success">' . $two_fa_success . '</div>'; } ?>
            <form action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post">
                <div class="form-group" style="display: flex; align-items: center;">
                    <input type="checkbox" name="two_factor_enabled" value="1" <?php echo ($user_data['two_factor_enabled']) ? 'checked' : ''; ?> onchange="this.form.submit()" style="width: auto; margin-right: 10px;">
                    <label for="two_factor_enabled" style="margin: 0; cursor: pointer; font-weight: 500;">Enable 2FA</label>
                </div>
                <input type="hidden" name="toggle_2fa" value="1">
            </form>
        </div>

        <!-- Full Security Log -->
        <div class="settings-section">
            <h2>Full Security Log</h2>
            <?php if (!empty($logs)): ?>
                <table class="log-table">
                    <thead>
                        <tr>
                            <th>Date/Time</th>
                            <th>Action</th>
                            <th>Status</th>
                            <th>IP Address</th>
                            <th>Details</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($logs as $log): ?>
                            <tr>
                                <td><?php echo date("Y-m-d H:i:s", strtotime($log['created_at'])); ?></td>
                                <td><?php echo htmlspecialchars(ucfirst(str_replace('_', ' ', $log['action']))); ?></td>
                                <td style="color: <?php echo $log['status'] == 'success' ? 'green' : 'red'; ?>;"><?php echo htmlspecialchars($log['status']); ?></td>
                                <td><?php echo htmlspecialchars($log['ip_address']); ?></td>
                                <td><?php echo htmlspecialchars($log['details']); ?></td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
                <?php if ($total_pages > 1): ?>
                    <div class="pagination">
                        <?php for ($i = 1; $i <= $total_pages; $i++): ?>
                            <a href="?page=<?php echo $i; ?>" class="<?php if ($page == $i) echo 'active'; ?>"><?php echo $i; ?></a>
                        <?php endfor; ?>
                    </div>
                <?php endif; ?>
            <?php else: ?>
                <p>No security events found.</p>
            <?php endif; ?>
        </div>
    </div>
</body>
</html>