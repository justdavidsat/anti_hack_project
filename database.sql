-- satechn1_anti database setup for local WAMP
-- Import via phpMyAdmin (or run with MySQL)

CREATE DATABASE IF NOT EXISTS satechn1_anti;
USE satechn1_anti;

CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    account_status VARCHAR(20) DEFAULT 'active',
    role VARCHAR(20) DEFAULT 'user',
    two_factor_enabled TINYINT(1) DEFAULT 0,
    two_factor_secret VARCHAR(64) NULL,
    session_guard CHAR(32) NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_login DATETIME NULL
);

CREATE TABLE IF NOT EXISTS security_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    action VARCHAR(50),
    status VARCHAR(50),
    details VARCHAR(255),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Sample test account: username = test, password = password123
INSERT INTO users (username, email, password, account_status, role, two_factor_enabled)
VALUES ('test', 'test@example.com', '$2y$10$Afbvl6plhnacUpDwiT4xueG34.rNDD6VpZdJFmsP0UenTYiDbwbsy', 'active', 'user', 0);

-- Administrator account for the cross-user audit view
-- username = admin, password = Admin@2026
INSERT INTO users (username, email, password, account_status, role, two_factor_enabled)
VALUES ('admin', 'admin@example.com', '$2y$10$9HKNlXMJ14dkSCDZ3Jx2XOT1.sqK6i4b93YUrVamym3qj16x7OJ/G', 'active', 'admin', 0);

-- ---------------------------------------------------------------
-- Migration for an existing installation (run once against an
-- already-populated satechn1_anti database):
--
-- ALTER TABLE users
--     ADD COLUMN role VARCHAR(20) DEFAULT 'user' AFTER account_status,
--     ADD COLUMN two_factor_secret VARCHAR(64) NULL AFTER two_factor_enabled,
--     ADD COLUMN session_guard CHAR(32) NULL AFTER two_factor_secret;
--
-- ALTER TABLE security_logs MODIFY user_id INT NULL;
-- ---------------------------------------------------------------
