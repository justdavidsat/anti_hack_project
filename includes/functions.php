<?php
// includes/functions.php

// Ensure the session is started on pages that use this file
if (session_status() === PHP_SESSION_NONE) {
    ini_set('session.use_strict_mode', '1');
    ini_set('session.cookie_httponly', '1');
    ini_set('session.cookie_samesite', 'Lax');
    session_start();
}

// Include the database connection
require_once "db.php";

// Include the TOTP helpers (real time-based one-time passwords)
require_once "totp.php";

// Security policy thresholds
define('ACCOUNT_LOCKOUT_THRESHOLD', 5);      // failed attempts before lock
define('ACCOUNT_LOCKOUT_WINDOW_MINUTES', 15); // rolling window in minutes
define('IP_LOCKOUT_THRESHOLD', 10);           // unknown-user attempts from one IP
define('PASSWORD_MIN_LENGTH', 8);
define('PASSWORD_MIN_SCORE', 40);

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
    $user_agent = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '';

    // Events with no account (e.g. logins for unknown usernames) store NULL,
    // because 0 is not a valid users.id for the foreign key.
    $user_id = ($user_id > 0) ? (int)$user_id : null;

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
 * Also re-validates the session guard so a password change invalidates
 * any other session that was stolen before the change.
 */
function require_login() {
    if (!is_logged_in()) {
        header("location: login.php");
        exit;
    }

    global $conn;
    $user_id = $_SESSION["id"];
    $sql = "SELECT session_guard FROM users WHERE id = ?";
    if ($stmt = $conn->prepare($sql)) {
        $stmt->bind_param("i", $user_id);
        $stmt->execute();
        $stmt->bind_result($db_guard);
        $stmt->fetch();
        $stmt->close();

        if (!empty($db_guard) && (!isset($_SESSION["guard"]) || $_SESSION["guard"] !== $db_guard)) {
            $_SESSION = array();
            session_destroy();
            header("location: login.php");
            exit;
        }
    }
}

/**
 * Returns true when the current session belongs to an administrator.
 */
function is_admin() {
    return is_logged_in() && isset($_SESSION["role"]) && $_SESSION["role"] === "admin";
}

/**
 * Restricts a page to administrators.
 */
function require_admin() {
    require_login();
    if (!is_admin()) {
        header("location: dashboard.php");
        exit;
    }
}

/**
 * Counts failed login attempts for one account in the rolling window.
 */
function count_recent_failures($user_id) {
    global $conn;
    $count = 0;
    $sql = "SELECT COUNT(id) FROM security_logs
            WHERE user_id = ? AND action = 'login_attempt' AND status LIKE 'failed%'
              AND created_at >= (NOW() - INTERVAL " . ACCOUNT_LOCKOUT_WINDOW_MINUTES . " MINUTE)";
    if ($stmt = $conn->prepare($sql)) {
        $stmt->bind_param("i", $user_id);
        $stmt->execute();
        $stmt->bind_result($count);
        $stmt->fetch();
        $stmt->close();
    }
    return $count;
}

/**
 * Locks the account when the failure threshold is reached.
 * Logs a single 'account_lockout' event per lock period.
 */
function register_failed_attempt($conn, $user_id) {
    if ($user_id <= 0) {
        return false;
    }
    $count = count_recent_failures($user_id);
    if ($count >= ACCOUNT_LOCKOUT_THRESHOLD) {
        $recent_lockout = 0;
        $sql = "SELECT COUNT(id) FROM security_logs
                WHERE user_id = ? AND action = 'account_lockout'
                  AND created_at >= (NOW() - INTERVAL " . ACCOUNT_LOCKOUT_WINDOW_MINUTES . " MINUTE)";
        if ($stmt = $conn->prepare($sql)) {
            $stmt->bind_param("i", $user_id);
            $stmt->execute();
            $stmt->bind_result($recent_lockout);
            $stmt->fetch();
            $stmt->close();
        }
        if ($recent_lockout == 0) {
            log_security_event($user_id, 'account_lockout', 'triggered',
                'Account locked after ' . $count . ' failed login attempts within ' . ACCOUNT_LOCKOUT_WINDOW_MINUTES . ' minutes.');
        }
        return true;
    }
    return false;
}

/**
 * True when the account is currently inside the lockout window.
 */
function is_account_locked($user_id) {
    return count_recent_failures($user_id) >= ACCOUNT_LOCKOUT_THRESHOLD;
}

/**
 * True when too many unknown-username attempts arrived from this IP.
 */
function is_ip_rate_limited($ip_address) {
    global $conn;
    $count = 0;
    $sql = "SELECT COUNT(id) FROM security_logs
            WHERE ip_address = ? AND status = 'failed_user_not_found'
              AND created_at >= (NOW() - INTERVAL " . ACCOUNT_LOCKOUT_WINDOW_MINUTES . " MINUTE)";
    if ($stmt = $conn->prepare($sql)) {
        $stmt->bind_param("s", $ip_address);
        $stmt->execute();
        $stmt->bind_result($count);
        $stmt->fetch();
        $stmt->close();
    }
    return $count >= IP_LOCKOUT_THRESHOLD;
}

/**
 * Issues a fresh session guard token for an account.
 * Storing it in both the session and the users row lets a password change
 * invalidate every other live session on its next request.
 */
function refresh_session_guard($user_id) {
    global $conn;
    $guard = bin2hex(random_bytes(16));
    $sql = "UPDATE users SET session_guard = ? WHERE id = ?";
    if ($stmt = $conn->prepare($sql)) {
        $stmt->bind_param("si", $guard, $user_id);
        $stmt->execute();
        $stmt->close();
    }
    $_SESSION["guard"] = $guard;
    return $guard;
}

/**
 * Attaches the account's current session guard to this session without rotating it,
 * so logging in from a second device does not sign out the first one.
 * Generates and stores a guard for accounts that do not have one yet.
 */
function adopt_session_guard($user_id) {
    global $conn;
    $guard = null;
    $sql = "SELECT session_guard FROM users WHERE id = ?";
    if ($stmt = $conn->prepare($sql)) {
        $stmt->bind_param("i", $user_id);
        $stmt->execute();
        $stmt->bind_result($guard);
        $stmt->fetch();
        $stmt->close();
    }
    if (empty($guard)) {
        return refresh_session_guard($user_id);
    }
    $_SESSION["guard"] = $guard;
    return $guard;
}

/**
 * Scores a password on a 0-100 scale and returns score, band and suggestions.
 * Weak passwords (below PASSWORD_MIN_SCORE) are rejected by the callers.
 */
function assess_password($password) {
    $score = 0;
    $suggestions = array();

    $length = strlen($password);
    if ($length >= 8) {
        $score += 30;
    } else {
        $suggestions[] = 'Use at least ' . PASSWORD_MIN_LENGTH . ' characters.';
    }
    if ($length >= 12) {
        $score += 10;
    }
    if ($length >= 16) {
        $score += 10;
    }
    if (preg_match('/[a-z]/', $password)) {
        $score += 10;
    } else {
        $suggestions[] = 'Add lowercase letters.';
    }
    if (preg_match('/[A-Z]/', $password)) {
        $score += 10;
    } else {
        $suggestions[] = 'Add uppercase letters.';
    }
    if (preg_match('/[0-9]/', $password)) {
        $score += 10;
    } else {
        $suggestions[] = 'Add numbers.';
    }
    if (preg_match('/[^A-Za-z0-9]/', $password)) {
        $score += 15;
    } else {
        $suggestions[] = 'Add symbols (e.g. ! ? #).';
    }

    // Reject trivial or well-known passwords regardless of length
    $common = array('password', 'password1', 'password123', '12345678', '123456789', '1234567890',
                    'qwertyuiop', 'iloveyou', 'letmein', 'welcome1', 'admin123', 'abc12345',
                    'abcd1234', 'qwerty123', 'football', 'monkey123', 'dragon123', 'sunshine');
    $lower = strtolower($password);
    foreach ($common as $bad) {
        if ($lower === $bad || strpos($lower, $bad) !== false) {
            $score = min($score, 30);
            $suggestions[] = 'This password appears in common-password lists.';
            break;
        }
    }

    // Penalise simple sequences and repeated characters
    if (preg_match('/(0123|1234|2345|3456|4567|5678|6789|abcd|bcde|cdef|defg)/i', $password)) {
        $score -= 15;
        $suggestions[] = 'Avoid simple sequences such as 1234 or abcd.';
    }
    if (preg_match('/(.)\1{3,}/', $password)) {
        $score -= 10;
        $suggestions[] = 'Avoid repeating the same character.';
    }

    $score = max(0, min(100, $score));

    if ($score >= 80) {
        $band = 'Very Strong';
    } elseif ($score >= 60) {
        $band = 'Strong';
    } elseif ($score >= PASSWORD_MIN_SCORE) {
        $band = 'Moderate';
    } else {
        $band = 'Weak';
    }

    return array('score' => $score, 'band' => $band, 'suggestions' => $suggestions);
}
?>
