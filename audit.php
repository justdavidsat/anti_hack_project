<?php
// audit.php

// Define page title for the header
 $page_title = "Security Audit";

// Include the header
require_once "includes/header.php";

// Include the functions file
require_once "includes/functions.php";
require_once "includes/db.php";

// If the user is not logged in, redirect to login page
require_login();

 $user_id = $_SESSION["id"];
 $username = $_SESSION["username"];

// --- Fetch Data for Analysis ---

// 1. Get user's security settings
 $user_sql = "SELECT two_factor_enabled, last_login FROM users WHERE id = ?";
 $user_data = ['two_factor_enabled' => 0, 'last_login' => null];
if ($stmt = $conn->prepare($user_sql)) {
    $stmt->bind_param("i", $user_id);
    $stmt->execute();
    $result = $stmt->get_result();
    $user_data = $result->fetch_assoc();
    $stmt->close();
}

// 2. Get recent security events
 $logs_sql = "SELECT action, status, created_at FROM security_logs WHERE user_id = ? ORDER BY created_at DESC LIMIT 50";
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

// --- Perform Analysis ---
 $security_score = 100;
 $recommendations = [];

// Check 1: 2FA Status
if (!$user_data['two_factor_enabled']) {
    $security_score -= 25;
    $recommendations[] = "Enable Two-Factor Authentication (2FA) to add an extra layer of security.";
}

// Check 2: Recent Failed Login Attempts
 $failed_attempts = 0;
foreach ($logs as $log) {
    if ($log['action'] == 'login' && $log['status'] == 'failed') {
        $failed_attempts++;
    }
}
if ($failed_attempts > 0) {
    $security_score -= 15;
    $recommendations[] = "We detected " . $failed_attempts . " recent failed login attempt(s). Ensure your password is strong and unique.";
}

// Check 3: Password Change Recency (let's assume older than 90 days is a risk)
// We'll simulate this by checking for a 'password_change' log. If none exists, it's a risk.
 $password_changed_recently = false;
foreach ($logs as $log) {
    if ($log['action'] == 'password_change' && $log['status'] == 'success') {
        $password_changed_recently = true;
        break;
    }
}
if (!$password_changed_recently) {
    $security_score -= 20;
    $recommendations[] = "You have not changed your password in a long time. Consider updating it regularly.";
}

// Determine score color
if ($security_score >= 80) {
    $score_color = 'var(--success-color)';
    $score_status = 'Excellent';
} elseif ($security_score >= 50) {
    $score_color = 'orange';
    $score_status = 'Good';
} else {
    $score_color = 'var(--error-color)';
    $score_status = 'At Risk';
}
?>

<div class="audit-container">
    <h2><i class="fas fa-clipboard-check"></i> Security Audit for <?php echo htmlspecialchars($username); ?></h2>
    <p>This audit analyzes your account's recent activity and settings to provide a security overview.</p>
    
    <div class="audit-score-card">
        <h3>Overall Security Score</h3>
        <div class="score-circle" style="border-color: <?php echo $score_color; ?>;">
            <span class="score-number" style="color: <?php echo $score_color; ?>;"><?php echo $security_score; ?></span>
            <span class="score-status" style="color: <?php echo $score_color; ?>;"><?php echo $score_status; ?></span>
        </div>
    </div>

    <?php if (!empty($recommendations)): ?>
        <div class="audit-recommendations">
            <h3><i class="fas fa-exclamation-triangle"></i> Recommendations</h3>
            <ul>
                <?php foreach ($recommendations as $rec): ?>
                    <li><?php echo htmlspecialchars($rec); ?></li>
                <?php endforeach; ?>
            </ul>
        </div>
    <?php else: ?>
        <div class="audit-recommendations" style="border-color: var(--success-color);">
            <h3><i class="fas fa-check-circle"></i> Great Job!</h3>
            <p>No critical security risks were detected. Keep up the good work.</p>
        </div>
    <?php endif; ?>

    <div class="audit-details">
        <h3><i class="fas fa-info-circle"></i> Audit Details</h3>
        <div class="detail-item">
            <strong>2FA Status:</strong> 
            <span style="color: <?php echo $user_data['two_factor_enabled'] ? 'var(--success-color)' : 'var(--error-color)'; ?>;">
                <?php echo $user_data['two_factor_enabled'] ? 'Enabled' : 'Disabled'; ?>
            </span>
        </div>
        <div class="detail-item">
            <strong>Recent Failed Logins:</strong> 
            <span style="color: <?php echo $failed_attempts > 0 ? 'var(--error-color)' : 'var(--success-color)'; ?>;">
                <?php echo $failed_attempts; ?>
            </span>
        </div>
        <div class="detail-item">
            <strong>Last Login:</strong> 
            <span><?php echo $user_data['last_login'] ? date("F j, Y, g:i a", strtotime($user_data['last_login'])) : 'Never'; ?></span>
        </div>
    </div>
</div>

<style>
.audit-container h2 { margin-bottom: 10px; }
.audit-container p { color: var(--muted-text-color); margin-bottom: 30px; }
.audit-score-card, .audit-recommendations, .audit-details {
    background-color: var(--secondary-color);
    border-radius: 8px;
    padding: 25px;
    margin-bottom: 25px;
    border: 1px solid var(--border-color);
}
.audit-recommendations { border-left: 5px solid var(--accent-color); }
.audit-recommendations h3 { color: var(--accent-color); margin-bottom: 15px; }
.audit-recommendations ul { list-style: none; padding-left: 0; }
.audit-recommendations li { padding: 8px 0; }
.score-circle {
    width: 150px;
    height: 150px;
    border-radius: 50%;
    border: 8px solid;
    display: flex;
    flex-direction: column;
    justify-content: center;
    align-items: center;
    margin: 20px auto;
    text-align: center;
}
.score-number { font-size: 3em; font-weight: 700; }
.score-status { font-size: 1.2em; font-weight: 500; }
.audit-details .detail-item { padding: 10px 0; border-bottom: 1px solid var(--border-color); }
.audit-details .detail-item:last-child { border-bottom: none; }
.audit-details strong { color: var(--text-color); }
</style>

<?php
// Include the footer
require_once "includes/footer.php";
?>