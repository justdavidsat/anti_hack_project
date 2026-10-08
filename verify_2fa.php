<?php
// verify_2fa.php - second-factor challenge after the password was verified

require_once "includes/db.php";
require_once "includes/functions.php";

// Only reachable as part of a pending login
if(!isset($_SESSION["pending_2fa"]) || $_SESSION["pending_2fa"] !== true){
    header("location: login.php");
    exit;
}

$pending_id = $_SESSION["pending_user_id"];
$pending_username = $_SESSION["pending_username"];
$code_err = "";

if($_SERVER["REQUEST_METHOD"] == "POST"){

    // Five wrong codes drop the attempt back to the login page
    if(!isset($_SESSION["2fa_attempts"])){
        $_SESSION["2fa_attempts"] = 0;
    }

    if(isset($_POST["cancel"])){
        unset($_SESSION["pending_2fa"], $_SESSION["pending_user_id"], $_SESSION["pending_username"],
              $_SESSION["pending_role"], $_SESSION["pending_password_ok"], $_SESSION["2fa_attempts"]);
        session_regenerate_id(true);
        header("location: login.php");
        exit;
    }

    $code = isset($_POST["code"]) ? trim($_POST["code"]) : "";

    // Fetch the account's TOTP secret
    $secret = "";
    $sql = "SELECT two_factor_secret FROM users WHERE id = ?";
    if($stmt = $conn->prepare($sql)){
        $stmt->bind_param("i", $pending_id);
        $stmt->execute();
        $stmt->bind_result($secret);
        $stmt->fetch();
        $stmt->close();
    }

    $_SESSION["2fa_attempts"]++;

    if(!empty($secret) && totp_verify($secret, $code)){
        // Second factor accepted - promote to a full session
        session_regenerate_id(true);
        $_SESSION["loggedin"] = true;
        $_SESSION["id"] = $pending_id;
        $_SESSION["username"] = $pending_username;
        $_SESSION["role"] = $_SESSION["pending_role"];
        adopt_session_guard($pending_id);

        unset($_SESSION["pending_2fa"], $_SESSION["pending_user_id"], $_SESSION["pending_username"],
              $_SESSION["pending_role"], $_SESSION["pending_password_ok"], $_SESSION["2fa_attempts"]);

        $update_sql = "UPDATE users SET last_login = NOW() WHERE id = ?";
        if($update_stmt = $conn->prepare($update_sql)){
            $update_stmt->bind_param("i", $pending_id);
            $update_stmt->execute();
            $update_stmt->close();
        }

        log_security_event($pending_id, 'login', 'success', 'User logged in successfully with two-factor verification.');
        log_security_event($pending_id, '2fa_challenge', 'success', 'Correct verification code entered at login.');

        header("location: dashboard.php");
        exit;
    }

    log_security_event($pending_id, '2fa_challenge', 'failed', 'Incorrect verification code entered at login.');

    if($_SESSION["2fa_attempts"] >= 5){
        unset($_SESSION["pending_2fa"], $_SESSION["pending_user_id"], $_SESSION["pending_username"],
              $_SESSION["pending_role"], $_SESSION["pending_password_ok"], $_SESSION["2fa_attempts"]);
        session_regenerate_id(true);
        log_security_event($pending_id, '2fa_challenge', 'failed', 'Two-factor challenge abandoned after 5 incorrect codes.');
        header("location: login.php");
        exit;
    }

    $code_err = "Incorrect verification code. Please try again.";
}

$page_title = "Two-Factor Verification";
require_once "includes/header.php";
?>

<div class="form-wrapper">
    <div class="auth-card">
        <h2><i class="fas fa-mobile-alt"></i> Two-Factor Verification</h2>
        <p>Enter the 6-digit code from your authenticator app for <strong><?php echo htmlspecialchars($pending_username); ?></strong>.</p>

        <?php if(!empty($code_err)){ echo '<div class="alert-error">' . $code_err . '</div>'; } ?>

        <form action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post">
            <div class="form-group">
                <label><i class="fas fa-key"></i> Verification Code</label>
                <input type="text" name="code" inputmode="numeric" pattern="[0-9]{6}" maxlength="6"
                       autocomplete="one-time-code" placeholder="123456" autofocus required>
                <span class="error"></span>
            </div>
            <div class="form-group">
                <input type="submit" class="btn" value="Verify">
                <button type="submit" name="cancel" value="1" class="btn" style="background:#777; margin-left:8px;">Cancel</button>
            </div>
        </form>
    </div>
</div>

<style>
.auth-card { background: #fff; padding: 30px; border-radius: 12px; box-shadow: 0 8px 25px rgba(0,0,0,0.08); border-top: 4px solid var(--accent-color); }
.auth-card h2 { color: var(--primary-color); text-align: center; margin-bottom: 10px; }
.auth-card > p { text-align: center; color: var(--muted-text-color); margin-bottom: 20px; }
</style>

<?php require_once "includes/footer.php"; ?>
