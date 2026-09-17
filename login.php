<?php
// login.php

// Include config file
require_once "includes/db.php";
require_once "includes/functions.php";

// Define variables and initialize with empty values
 $username = $password = "";
 $username_err = $password_err = $login_err = "";

// Processing form data when form is submitted
if($_SERVER["REQUEST_METHOD"] == "POST"){

    // Check if username is empty
    if(empty(trim($_POST["username"]))){
        $username_err = "Please enter username.";
    } else{
        $username = trim($_POST["username"]);
    }

    // Check if password is empty
    if(empty(trim($_POST["password"]))){
        $password_err = "Please enter your password.";
    } else{
        $password = trim($_POST["password"]);
    }

    // Validate credentials
    if(empty($username_err) && empty($password_err)){
        // Prepare a select statement
        $sql = "SELECT id, username, password, account_status FROM users WHERE username = ? OR email = ?";

        if($stmt = $conn->prepare($sql)){
            $stmt->bind_param("ss", $param_username, $param_username);
            $param_username = $username;

            if($stmt->execute()){
                $stmt->store_result();

                // Check if username exists, if yes then verify password
                if($stmt->num_rows == 1){
                    // Bind result variables
                    $stmt->bind_result($id, $username, $hashed_password, $account_status);
                    if($stmt->fetch()){
                        if($account_status !== 'active'){
                            $login_err = "Your account is locked or suspended. Please contact support.";
                            log_security_event($id, 'login_attempt', 'failed_account_status', 'Account is not active.');
                        } elseif(password_verify($password, $hashed_password)){
                            // Password is correct, so start a new session
                            session_start();

                            // Store data in session variables
                            $_SESSION["loggedin"] = true;
                            $_SESSION["id"] = $id;
                            $_SESSION["username"] = $username;

                            // Update last login timestamp
                            $update_sql = "UPDATE users SET last_login = NOW() WHERE id = ?";
                            if($update_stmt = $conn->prepare($update_sql)){
                                $update_stmt->bind_param("i", $id);
                                $update_stmt->execute();
                                $update_stmt->close();
                            }

                            // Log successful login
                            log_security_event($id, 'login', 'success', 'User logged in successfully.');

                            // Redirect user to dashboard page
                            header("location: dashboard.php");
                        } else{
                            // Password is not valid, display a generic error message
                            $login_err = "Invalid username or password.";
                            // Log failed login attempt
                            log_security_event($id, 'login_attempt', 'failed_password', 'Invalid password entered.');
                        }
                    }
                } else{
                    // Username doesn't exist, display a generic error message
                    $login_err = "Invalid username or password.";
                    // Log failed login attempt for a non-existent user
                    log_security_event(0, 'login_attempt', 'failed_user_not_found', 'Attempt to log in with non-existent user: ' . $username);
                }
            } else{
                echo "Oops! Something went wrong. Please try again later.";
            }

            // Close statement
            $stmt->close();
        }
    }

    // Close connection
    $conn->close();
}

$page_title = "Login";
require_once "includes/header.php";
?>

<div class="form-wrapper">
    <div class="auth-card">
        <h2><i class="fas fa-user-lock"></i> Login</h2>
        <p>Please fill in your credentials to login.</p>

        <?php
        if(!empty($login_err)){
            echo '<div class="alert-error">' . $login_err . '</div>';
        }
        ?>

        <form action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post">
            <div class="form-group">
                <label><i class="fas fa-user"></i> Username or Email</label>
                <input type="text" name="username" value="<?php echo $username; ?>">
                <span class="error"><?php echo $username_err; ?></span>
            </div>
            <div class="form-group">
                <label><i class="fas fa-lock"></i> Password</label>
                <input type="password" name="password">
                <span class="error"><?php echo $password_err; ?></span>
            </div>
            <div class="form-group">
                <input type="submit" class="btn" value="Login">
            </div>
            <p class="auth-switch">Don't have an account? <a href="register.php">Sign up now</a>.</p>
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
</style>

<?php require_once "includes/footer.php"; ?>