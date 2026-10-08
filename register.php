<?php
// register.php

// Include config file
require_once "includes/db.php";
require_once "includes/functions.php";

// Define variables and initialize with empty values
 $username = $email = $password = $confirm_password = "";
 $username_err = $email_err = $password_err = $confirm_password_err = "";

// Processing form data when form is submitted
if($_SERVER["REQUEST_METHOD"] == "POST"){

    // Validate username
    if(empty(trim($_POST["username"]))){
        $username_err = "Please enter a username.";
    } else {
        // Prepare a select statement
        $sql = "SELECT id FROM users WHERE username = ?";
        if($stmt = $conn->prepare($sql)){
            $stmt->bind_param("s", $param_username);
            $param_username = trim($_POST["username"]);
            if($stmt->execute()){
                $stmt->store_result();
                if($stmt->num_rows == 1){
                    $username_err = "This username is already taken.";
                } else{
                    $username = trim($_POST["username"]);
                }
            } else{
                echo "Oops! Something went wrong. Please try again later.";
            }
            $stmt->close();
        }
    }

    // Validate email
    if(empty(trim($_POST["email"]))){
        $email_err = "Please enter an email.";
    } else {
        $sql = "SELECT id FROM users WHERE email = ?";
        if($stmt = $conn->prepare($sql)){
            $stmt->bind_param("s", $param_email);
            $param_email = trim($_POST["email"]);
            if($stmt->execute()){
                $stmt->store_result();
                if($stmt->num_rows == 1){
                    $email_err = "This email is already registered.";
                } else{
                    $email = trim($_POST["email"]);
                }
            }
            $stmt->close();
        }
    }

    // Validate password (length + strength policy)
    if(empty(trim($_POST["password"]))){
        $password_err = "Please enter a password.";
    } elseif(strlen(trim($_POST["password"])) < PASSWORD_MIN_LENGTH){
        $password_err = "Password must have at least " . PASSWORD_MIN_LENGTH . " characters.";
    } else{
        $password = trim($_POST["password"]);
        $strength = assess_password($password);
        if($strength['score'] < PASSWORD_MIN_SCORE){
            $password_err = "Password is too weak: " . (empty($strength['suggestions']) ? "add length, letters, numbers and symbols." : implode(" ", $strength['suggestions']));
            $password = "";
        }
    }

    // Validate confirm password
    if(empty(trim($_POST["confirm_password"]))){
        $confirm_password_err = "Please confirm password.";
    } else{
        $confirm_password = trim($_POST["confirm_password"]);
        if(empty($password_err) && ($password != $confirm_password)){
            $confirm_password_err = "Password did not match.";
        }
    }

    // Check input errors before inserting in database
    if(empty($username_err) && empty($email_err) && empty($password_err) && empty($confirm_password_err)){

        // Prepare an insert statement
        $sql = "INSERT INTO users (username, email, password) VALUES (?, ?, ?)";

        if($stmt = $conn->prepare($sql)){
            $stmt->bind_param("sss", $param_username, $param_email, $param_password);
            $param_username = $username;
            $param_email = $email;
            // Creates a password hash - this is a key security feature!
            $param_password = password_hash($password, PASSWORD_DEFAULT);

            if($stmt->execute()){
                $new_user_id = $conn->insert_id;

                // Record the account creation as a security event
                log_security_event($new_user_id, 'account_created', 'success', 'New account created: ' . $username);

                // Redirect to login page
                header("location: login.php");
            } else{
                echo "Something went wrong. Please try again later.";
            }
            $stmt->close();
        }
    }
    $conn->close();
}

$page_title = "Sign Up";
require_once "includes/header.php";
?>

<div class="form-wrapper">
    <div class="auth-card">
        <h2><i class="fas fa-user-plus"></i> Sign Up</h2>
        <p>Please fill this form to create an account.</p>
        <form action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post">
            <div class="form-group">
                <label><i class="fas fa-user"></i> Username</label>
                <input type="text" name="username" value="<?php echo $username; ?>">
                <span class="error"><?php echo $username_err; ?></span>
            </div>
            <div class="form-group">
                <label><i class="fas fa-envelope"></i> Email</label>
                <input type="email" name="email" value="<?php echo $email; ?>">
                <span class="error"><?php echo $email_err; ?></span>
            </div>
            <div class="form-group">
                <label><i class="fas fa-lock"></i> Password</label>
                <input type="password" name="password" id="reg_password" oninput="updateStrengthMeter('reg_password','reg_strength','reg_strength_text')">
                <div class="strength-meter"><div class="strength-bar" id="reg_strength"></div></div>
                <span class="strength-text" id="reg_strength_text">&nbsp;</span>
                <span class="error"><?php echo $password_err; ?></span>
            </div>
            <div class="form-group">
                <label><i class="fas fa-lock"></i> Confirm Password</label>
                <input type="password" name="confirm_password">
                <span class="error"><?php echo $confirm_password_err; ?></span>
            </div>
            <div class="form-group">
                <input type="submit" class="btn" value="Submit">
            </div>
            <p class="auth-switch">Already have an account? <a href="login.php">Login here</a>.</p>
        </form>
    </div>
</div>

<style>
.auth-card { background: #fff; padding: 30px; border-radius: 12px; box-shadow: 0 8px 25px rgba(0,0,0,0.08); border-top: 4px solid var(--accent-color); }
.auth-card h2 { color: var(--primary-color); text-align: center; margin-bottom: 10px; }
.auth-card > p { text-align: center; color: var(--muted-text-color); margin-bottom: 20px; }
.auth-switch { text-align: center; margin-top: 15px; }
.auth-switch a { color: var(--primary-color); font-weight: 600; text-decoration: none; }
.auth-switch a:hover { text-decoration: underline; }
.error { color: var(--error-color); font-size: 0.9em; display: block; margin-top: 5px; }
.strength-meter { background: #eee; border-radius: 4px; height: 8px; margin-top: 8px; overflow: hidden; }
.strength-bar { height: 100%; width: 0; transition: width 0.2s, background 0.2s; }
.strength-text { font-size: 0.85em; color: var(--muted-text-color); display: block; margin-top: 4px; }
</style>

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
    document.getElementById(textId).textContent = pw.length ? (label + ' (' + score + '/100)') : ' ';
    document.getElementById(textId).style.color = color;
}
</script>

<?php require_once "includes/footer.php"; ?>