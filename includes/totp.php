<?php
// includes/totp.php
// RFC 6238 Time-Based One-Time Password (TOTP) helpers (SHA-1, 6 digits, 30 s period)

/**
 * Encodes raw bytes as an unpadded RFC 4648 base32 string.
 */
function totp_base32_encode($data) {
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $binary = '';
    foreach (str_split($data) as $char) {
        $binary .= str_pad(decbin(ord($char)), 8, '0', STR_PAD_LEFT);
    }
    $binary = str_split($binary);
    $output = '';
    foreach (array_chunk($binary, 5) as $chunk) {
        if (count($chunk) < 5) {
            $chunk = array_pad($chunk, 5, '0');
        }
        $index = bindec(implode('', $chunk));
        $output .= $alphabet[$index];
    }
    return $output;
}

/**
 * Decodes an RFC 4648 base32 string (padding optional) back to raw bytes.
 */
function totp_base32_decode($string) {
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $string = strtoupper(preg_replace('/[^A-Z2-7]/i', '', (string)$string));
    if ($string === '') {
        return '';
    }
    $binary = '';
    foreach (str_split($string) as $char) {
        $binary .= str_pad(decbin(strpos($alphabet, $char)), 5, '0', STR_PAD_LEFT);
    }
    $binary = str_split($binary);
    $output = '';
    foreach (array_chunk($binary, 8) as $chunk) {
        if (count($chunk) < 8) {
            break;
        }
        $output .= chr(bindec(implode('', $chunk)));
    }
    return $output;
}

/**
 * Generates a random 160-bit (20-byte) base32 secret for enrolment.
 */
function totp_generate_secret() {
    return totp_base32_encode(random_bytes(20));
}

/**
 * Generates the TOTP code for a secret at the given time.
 */
function totp_code($secret, $time = null) {
    $time = ($time === null) ? time() : $time;
    $counter = intdiv($time, 30);
    $key = totp_base32_decode($secret);

    if (strlen($key) < 1) {
        return '';
    }

    $binary_counter = pack('N*', 0) . pack('N*', $counter);
    $hash = hash_hmac('sha1', $binary_counter, $key, true);

    $offset = ord($hash[19]) & 0x0F;
    $truncated = (
        ((ord($hash[$offset]) & 0x7F) << 24) |
        ((ord($hash[$offset + 1]) & 0xFF) << 16) |
        ((ord($hash[$offset + 2]) & 0xFF) << 8) |
        (ord($hash[$offset + 3]) & 0xFF)
    );

    return str_pad((string)($truncated % 1000000), 6, '0', STR_PAD_LEFT);
}

/**
 * Verifies a 6-digit code against the secret, allowing one period of drift either side.
 */
function totp_verify($secret, $code) {
    $code = trim((string)$code);
    if (!preg_match('/^\d{6}$/', $code)) {
        return false;
    }
    $now = time();
    foreach (array(-30, 0, 30) as $drift) {
        if (hash_equals(totp_code($secret, $now + $drift), $code)) {
            return true;
        }
    }
    return false;
}

/**
 * Returns the otpauth:// provisioning URI shown to the user during enrolment.
 */
function totp_provisioning_uri($secret, $account_name, $issuer = 'Anti-Hack Security') {
    $label = rawurlencode($issuer . ':' . $account_name);
    return 'otpauth://totp/' . $label . '?secret=' . rawurlencode($secret)
        . '&issuer=' . rawurlencode($issuer) . '&algorithm=SHA1&digits=6&period=30';
}
?>
