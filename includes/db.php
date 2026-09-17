<?php
// includes/db.php

// Local WAMP credentials (use these when running locally)
define('DB_SERVER', 'localhost');
define('DB_USERNAME', 'root');
define('DB_PASSWORD', '');
define('DB_NAME', 'satechn1_anti');

// Remote hosting credentials (use these on live server)
// define('DB_SERVER', 'localhost');
// define('DB_USERNAME', 'satechn1_hck');
// define('DB_PASSWORD', 'W^H[ZQ}-_byf');
// define('DB_NAME', 'satechn1_anti');

// Attempt to connect to MySQL database
 $conn = new mysqli(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);

// Check connection
if($conn === false){
    die("ERROR: Could not connect. " . $conn->connect_error);
}
?>