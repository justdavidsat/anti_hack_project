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
 $password_err = $password_success = "";
 $two_fa_success = $two_fa_err = "";
 $pending_secret = "";

// --- Fetch the account's current 2FA state (needed by the handlers below) ---
 $user_sql = "SELECT two_factor_enabled, two_factor_secret FROM users WHERE id = ?";
 $user_data = ['two_factor_enabled' => 0, 'two_factor_secret' => null];
if ($stmt = $conn->prepare($user_sql)) {
    $stmt->bind_param("i", $user_id);
    $stmt->execute();
    $result = $stmt->get_result();
    $user_data = $result->fetch_assoc();
    $stmt->close();
}

// --- PROCESS FORM SUBMISSIONS ---
if ($_SERVER["REQUEST_METHOD"] == "POST") {

    // --- Handle Password Change ---
    if (isset($_POST['change_password'])) {
        // Get and validate inputs
        $current_password = trim($_POST["current_password"]);
        $new_password = trim($_POST["new_password"]);
        $confirm_password = trim($_POST["confirm_password"]);

        // Validate new password against the strength policy
        if (empty($new_password)) {
            $password_err = "Please enter a new password.";
        } elseif (strlen($new_password) < PASSWORD_MIN_LENGTH) {
            $password_err = "New password must have at least " . PASSWORD_MIN_LENGTH . " characters.";
        } else {
            $strength = assess_password($new_password);
            if ($strength['score'] < PASSWORD_MIN_SCORE) {
                $password_err = "New password is too weak: " . (empty($strength["suggestions"]) ? "add length, letters, numbers and symbols." : implode(" ", $strength["suggestions"]));
            } elseif ($new_password !== $confirm_password) {
                $password_err = "New passwords do not match.";
            } else {
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
                        // Hash the new password and update
                        $new_hashed_password = password_hash($new_password, PASSWORD_DEFAULT);
                        $update_sql = "UPDATE users SET password = ? WHERE id = ?";
                        if ($update_stmt = $conn->prepare($update_sql)) {
                            $update_stmt->bind_param("si", $new_hashed_password, $user_id);
                            $update_stmt->execute();
                            $update_stmt->close();

                            // Invalidate every other live session for this account
                            refresh_session_guard($user_id);

                            $password_success = "Password changed successfully! Other sessions have been signed out.";
                            log_security_event($user_id, 'password_change', 'success', 'User changed their password.');
                        }
                    } else {
                        $password_err = "The current password you entered is not valid.";
                        log_security_event($user_id, 'password_change', 'failed', 'User entered incorrect current password.');
                    }
                }
            }
        }
    }

    // --- Handle 2FA Enrolment: step 1, generate/store a secret ---
    if (isset($_POST['setup_2fa'])) {
        $secret = !empty($user_data['two_factor_secret']) ? $user_data['two_factor_secret'] : totp_generate_secret();
        $update_sql = "UPDATE users SET two_factor_secret = ? WHERE id = ?";
        if ($stmt = $conn->prepare($update_sql)) {
            $stmt->bind_param("si", $secret, $user_id);
            $stmt->execute();
            $stmt->close();
        }
        $pending_secret = $secret;
        log_security_event($user_id, '2fa_toggle', 'setup', 'Authenticator enrolment started; secret generated.');
    }

    // --- Handle 2FA Enrolment: step 2, confirm a code to enable ---
    if (isset($_POST['confirm_2fa'])) {
        $code = isset($_POST['code']) ? trim($_POST['code']) : "";
        $secret = $user_data['two_factor_secret'];
        if (!empty($secret) && totp_verify($secret, $code)) {
            $update_sql = "UPDATE users SET two_factor_enabled = 1 WHERE id = ?";
            if ($stmt = $conn->prepare($update_sql)) {
                $stmt->bind_param("i", $user_id);
                $stmt->execute();
                $stmt->close();
            }
            $two_fa_success = "Two-Factor Authentication has been <strong>enabled</strong>. Your next login will require a verification code.";
            log_security_event($user_id, '2fa_toggle', 'success', 'User enabled Two-Factor Authentication after verifying a code.');
        } else {
            $two_fa_err = "That verification code is not valid. Please try again.";
            $pending_secret = $user_data['two_factor_secret'];
            log_security_event($user_id, '2fa_toggle', 'failed', 'Enrolment rejected: verification code did not match.');
        }
    }

    // --- Handle 2FA Disable: requires a current code ---
    if (isset($_POST['disable_2fa'])) {
        $code = isset($_POST['disable_code']) ? trim($_POST['disable_code']) : "";
        $secret = $user_data['two_factor_secret'];
        if (!empty($secret) && totp_verify($secret, $code)) {
            $update_sql = "UPDATE users SET two_factor_enabled = 0, two_factor_secret = NULL WHERE id = ?";
            if ($stmt = $conn->prepare($update_sql)) {
                $stmt->bind_param("i", $user_id);
                $stmt->execute();
                $stmt->close();
            }
            $two_fa_success = "Two-Factor Authentication has been <strong>disabled</strong>.";
            log_security_event($user_id, '2fa_toggle', 'success', 'User disabled Two-Factor Authentication after verifying a code.');
        } else {
            $two_fa_err = "That verification code is not valid. Two-Factor Authentication was not disabled.";
            log_security_event($user_id, '2fa_toggle', 'failed', 'Disable rejected: verification code did not match.');
        }
    }

    // Refresh 2FA state after any handler above
    if ($stmt = $conn->prepare($user_sql)) {
        $stmt->bind_param("i", $user_id);
        $stmt->execute();
        $result = $stmt->get_result();
        $user_data = $result->fetch_assoc();
        $stmt->close();
    }
}

// --- FETCH DATA FOR DISPLAY ---

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

// Display state for the 2FA panel
 $two_fa_enabled = !empty($user_data['two_factor_enabled']);
 $has_secret = !empty($user_data['two_factor_secret']);
 $show_enrolment = (!$two_fa_enabled && ($pending_secret !== "" || $has_secret));
 $enrolment_secret = ($pending_secret !== "") ? $pending_secret : $user_data['two_factor_secret'];

$page_title = "Security Settings";
require_once "includes/header.php";
?>

<style>
    .settings-container { max-width: 1000px; }
    .settings-section { margin-bottom: 40px; border-bottom: 1px solid var(--border-color); padding-bottom: 20px; }
    .settings-section:last-child { border-bottom: none; }
    .settings-section h2 { color: var(--primary-color); margin-bottom: 15px; }
    .log-table { width: 100%; border-collapse: collapse; margin-top: 10px; }
    .log-table th, .log-table td { padding: 10px; border: 1px solid var(--border-color); text-align: left; }
    .log-table th { background-color: var(--light-accent-color); }
    .pagination { margin-top: 20px; text-align: center; }
    .pagination a, .pagination span { padding: 8px 16px; text-decoration: none; color: var(--primary-color); border: 1px solid var(--border-color); margin: 0 4px; }
    .pagination a:hover { background-color: var(--primary-color); color: #ffffff; }
    .pagination .active { background-color: var(--primary-color); color: white; border-color: var(--primary-color); }
    .strength-meter { background: #eee; border-radius: 4px; height: 8px; margin-top: 8px; overflow: hidden; }
    .strength-bar { height: 100%; width: 0; transition: width 0.2s, background 0.2s; }
    .strength-text { font-size: 0.85em; color: var(--muted-text-color); display: block; margin-top: 4px; }
    .secret-box { background: #f5f5f5; border: 1px dashed var(--border-color); padding: 12px; border-radius: 8px; font-family: monospace; word-break: break-all; margin: 10px 0; }
    .twofa-status { padding: 10px 14px; border-radius: 8px; margin-bottom: 15px; font-weight: 600; }
    .twofa-on { background: #e6f4e6; color: #2e7d32; }
    .twofa-off { background: #fdecea; color: #c62828; }
</style>

<div class="settings-container">
    <h2><i class="fas fa-shield-alt"></i> Security Settings</h2>
    <p style="color: var(--muted-text-color);">Manage your account security below.</p>

        <!-- Password Change Section -->
        <div class="settings-section">
            <h2><i class="fas fa-key"></i> Change Password</h2>
            <?php if(!empty($password_err)) { echo '<div class="alert-error">' . $password_err . '</div>'; } ?>
            <?php if(!empty($password_success)) { echo '<div class="alert-success">' . $password_success . '</div>'; } ?>
            <form action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post">
                <div class="form-group">
                    <label>Current Password</label>
                    <input type="password" name="current_password">
                </div>
                <div class="form-group">
                    <label>New Password</label>
                    <input type="password" name="new_password" id="new_password" oninput="updateStrengthMeter('new_password','pw_strength','pw_strength_text')">
                    <div class="strength-meter"><div class="strength-bar" id="pw_strength"></div></div>
                    <span class="strength-text" id="pw_strength_text">&nbsp;</span>
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
            <h2><i class="fas fa-mobile-alt"></i> Two-Factor Authentication (2FA)</h2>
            <?php if(!empty($two_fa_success)) { echo '<div class="alert-success">' . $two_fa_success . '</div>'; } ?>
            <?php if(!empty($two_fa_err)) { echo '<div class="alert-error">' . $two_fa_err . '</div>'; } ?>

            <?php if ($two_fa_enabled): ?>
                <div class="twofa-status twofa-on"><i class="fas fa-check-circle"></i> Two-Factor Authentication is ON</div>
                <p>Logins now require a 6-digit time-based code from your authenticator app in addition to your password.</p>
                <form action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post">
                    <div class="form-group">
                        <label>Enter current code to disable 2FA</label>
                        <input type="text" name="disable_code" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" placeholder="123456">
                    </div>
                    <div class="form-group">
                        <input type="submit" name="disable_2fa" class="btn" value="Disable 2FA">
                    </div>
                </form>
            <?php elseif ($show_enrolment): ?>
                <div class="twofa-status twofa-off"><i class="fas fa-hourglass-half"></i> Two-Factor Authentication is pending setup</div>
                <p>1. Add this key to your authenticator app (Google Authenticator, Authy, 1Password...) as a <strong>time-based</strong> account, either by typing the key or by opening this link:</p>
                <div class="secret-box"><?php echo htmlspecialchars($enrolment_secret); ?></div>
                <div class="secret-box"><?php echo htmlspecialchars(totp_provisioning_uri($enrolment_secret, $username)); ?></div>
                <form action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post">
                    <div class="form-group">
                        <label>2. Enter the 6-digit code shown in your app to confirm</label>
                        <input type="text" name="code" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" placeholder="123456">
                    </div>
                    <div class="form-group">
                        <input type="submit" name="confirm_2fa" class="btn" value="Confirm and Enable">
                    </div>
                </form>
            <?php else: ?>
                <div class="twofa-status twofa-off"><i class="fas fa-times-circle"></i> Two-Factor Authentication is OFF</div>
                <p>Enabling 2FA adds a time-based one-time code (TOTP) check to every login.</p>
                <form action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post">
                    <div class="form-group">
                        <input type="submit" name="setup_2fa" class="btn" value="Set Up Two-Factor Authentication">
                    </div>
                </form>
            <?php endif; ?>
        </div>

        <!-- Full Security Log -->
        <div class="settings-section">
            <h2><i class="fas fa-list-alt"></i> Full Security Log</h2>
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
                                <td style="color: <?php echo (strpos($log['status'], 'success') === 0 || $log['status'] == 'setup') ? 'green' : 'red'; ?>;"><?php echo htmlspecialchars($log['status']); ?></td>
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

<script>
// Advisory meter; the server enforces the real score (min 40/100, min 8 characters)
function updateStrengthMeter(inputId, barId, textId) {
    var pw = document.getElementById(inputId).value;
    var score = 0;
    if (pw.length >= 8) score += 30;
    if (pw.length >= 12) score += 10;
    if (pw.length >= 16) score += 10;
    if (/[a-z]/.test(pw)) score += 10;
    if (/[A-Z]/.test(pw)) score += 10;
    if (/[0-9]/.test(pw)) score += 10;
    if (/[^A-Za-z0-9]/.test(pw)) score += 15;
    if (/(0123|1234|2345|3456|4567|5678|6789|abcd|bcde|cdef)/i.test(pw)) score -= 15;
    score = Math.max(0, Math.min(100, score));
    var color = '#d9534f';
    var label = 'Weak';
    if (score >= 80) { color = '#2e7d32'; label = 'Very Strong'; }
    else if (score >= 60) { color = '#5cb85c'; label = 'Strong'; }
    else if (score >= 40) { color = '#f0ad4e'; label = 'Moderate'; }
    var bar = document.getElementById(barId);
    bar.style.width = score + '%';
    bar.style.background = color;
    document.getElementById(textId).textContent = pw.length ? (label + ' (' + score + '/100)') : ' ';
    document.getElementById(textId).style.color = color;
}
</script>
</body>
</html>
