<?php
// admin.php - administrative audit view across all accounts

require_once "includes/db.php";
require_once "includes/functions.php";

// Administrators only
require_admin();

// --- Summary statistics ---
 $stats = ['users' => 0, 'events_24h' => 0, 'failures_24h' => 0, 'twofa_users' => 0, 'lockouts_24h' => 0];
if ($stmt = $conn->prepare("SELECT COUNT(id) FROM users")) {
    $stmt->execute();
    $stmt->bind_result($stats['users']);
    $stmt->fetch();
    $stmt->close();
}
if ($stmt = $conn->prepare("SELECT COUNT(id) FROM security_logs WHERE created_at >= (NOW() - INTERVAL 24 HOUR)")) {
    $stmt->execute();
    $stmt->bind_result($stats['events_24h']);
    $stmt->fetch();
    $stmt->close();
}
if ($stmt = $conn->prepare("SELECT COUNT(id) FROM security_logs WHERE status LIKE 'failed%' AND created_at >= (NOW() - INTERVAL 24 HOUR)")) {
    $stmt->execute();
    $stmt->bind_result($stats['failures_24h']);
    $stmt->fetch();
    $stmt->close();
}
if ($stmt = $conn->prepare("SELECT COUNT(id) FROM security_logs WHERE action = 'account_lockout' AND created_at >= (NOW() - INTERVAL 24 HOUR)")) {
    $stmt->execute();
    $stmt->bind_result($stats['lockouts_24h']);
    $stmt->fetch();
    $stmt->close();
}
if ($stmt = $conn->prepare("SELECT COUNT(id) FROM users WHERE two_factor_enabled = 1")) {
    $stmt->execute();
    $stmt->bind_result($stats['twofa_users']);
    $stmt->fetch();
    $stmt->close();
}

// --- Filters ---
 $filter_action = isset($_GET['action']) ? trim($_GET['action']) : "";
 $filter_user = isset($_GET['user']) ? trim($_GET['user']) : "";
 $filter_status = isset($_GET['status']) ? trim($_GET['status']) : "";
 $page = isset($_GET['page']) && is_numeric($_GET['page']) ? (int)$_GET['page'] : 1;
 if ($page < 1) { $page = 1; }
 $logs_per_page = 25;
 $offset = ($page - 1) * $logs_per_page;

 // Build WHERE clause
 $where = " WHERE 1=1";
 $types = "";
 $params = array();
 if ($filter_action !== "") {
     $where .= " AND sl.action = ?";
     $types .= "s";
     $params[] = $filter_action;
 }
 if ($filter_status !== "") {
     $where .= " AND sl.status LIKE ?";
     $types .= "s";
     $params[] = $filter_status . "%";
 }
 if ($filter_user !== "") {
     $where .= " AND u.username LIKE ?";
     $types .= "s";
     $params[] = "%" . $filter_user . "%";
 }

 $total_logs = 0;
 if ($stmt = $conn->prepare("SELECT COUNT(sl.id) FROM security_logs sl LEFT JOIN users u ON u.id = sl.user_id" . $where)) {
     if ($types !== "") { $stmt->bind_param($types, ...$params); }
     $stmt->execute();
     $stmt->bind_result($total_logs);
     $stmt->fetch();
     $stmt->close();
 }
 $total_pages = max(1, ceil($total_logs / $logs_per_page));

 $logs = array();
 $sql = "SELECT sl.created_at, IFNULL(u.username, '(unknown user)') AS username, sl.ip_address, sl.action, sl.status, sl.details
         FROM security_logs sl
         LEFT JOIN users u ON u.id = sl.user_id" . $where .
        " ORDER BY sl.created_at DESC LIMIT " . $logs_per_page . " OFFSET " . $offset;
 if ($stmt = $conn->prepare($sql)) {
     if ($types !== "") { $stmt->bind_param($types, ...$params); }
     $stmt->execute();
     $result = $stmt->get_result();
     while ($row = $result->fetch_assoc()) {
         $logs[] = $row;
     }
     $stmt->close();
 }

 // Distinct actions present, for the filter dropdown
 $actions = array();
 if ($stmt = $conn->prepare("SELECT DISTINCT action FROM security_logs ORDER BY action")) {
     $stmt->execute();
     $result = $stmt->get_result();
     while ($row = $result->fetch_row()) {
         $actions[] = $row[0];
     }
     $stmt->close();
 }

 $conn->close();

$page_title = "Admin Audit";
require_once "includes/header.php";
?>

<style>
    .admin-container { max-width: 1200px; }
    .stat-grid { display: flex; flex-wrap: wrap; gap: 15px; margin: 20px 0 30px; }
    .stat-card { background: #fff; border-radius: 10px; box-shadow: 0 4px 15px rgba(0,0,0,0.07); padding: 18px; flex: 1; min-width: 170px; border-top: 3px solid var(--accent-color); }
    .stat-card .stat-value { font-size: 1.8em; font-weight: 700; color: var(--primary-color); }
    .stat-card .stat-label { color: var(--muted-text-color); font-size: 0.9em; }
    .filter-bar { display: flex; flex-wrap: wrap; gap: 10px; align-items: flex-end; margin-bottom: 18px; }
    .filter-bar label { display: block; font-size: 0.85em; color: var(--muted-text-color); margin-bottom: 4px; }
    .filter-bar input, .filter-bar select { padding: 8px; border: 1px solid var(--border-color); border-radius: 6px; min-width: 160px; }
    .admin-table { width: 100%; border-collapse: collapse; }
    .admin-table th, .admin-table td { padding: 10px; border: 1px solid var(--border-color); text-align: left; font-size: 0.92em; }
    .admin-table th { background-color: var(--light-accent-color); }
    .status-fail { color: #c62828; font-weight: 600; }
    .status-ok { color: #2e7d32; }
    .pagination { margin-top: 20px; text-align: center; }
    .pagination a, .pagination span { padding: 8px 14px; text-decoration: none; color: var(--primary-color); border: 1px solid var(--border-color); margin: 0 4px; }
    .pagination a:hover { background-color: var(--primary-color); color: #fff; }
    .pagination .active { background-color: var(--primary-color); color: white; border-color: var(--primary-color); }
</style>

<div class="admin-container">
    <h2><i class="fas fa-user-shield"></i> Administrative Audit View</h2>
    <p style="color: var(--muted-text-color);">Cross-account security monitoring for administrators.</p>

    <div class="stat-grid">
        <div class="stat-card"><div class="stat-value"><?php echo $stats['users']; ?></div><div class="stat-label">Registered accounts</div></div>
        <div class="stat-card"><div class="stat-value"><?php echo $stats['twofa_users']; ?></div><div class="stat-label">Accounts with 2FA on</div></div>
        <div class="stat-card"><div class="stat-value"><?php echo $stats['events_24h']; ?></div><div class="stat-label">Events (last 24 h)</div></div>
        <div class="stat-card"><div class="stat-value"><?php echo $stats['failures_24h']; ?></div><div class="stat-label">Failed attempts (24 h)</div></div>
        <div class="stat-card"><div class="stat-value"><?php echo $stats['lockouts_24h']; ?></div><div class="stat-label">Lockouts (24 h)</div></div>
    </div>

    <form method="get" class="filter-bar">
        <div>
            <label>Username</label>
            <input type="text" name="user" value="<?php echo htmlspecialchars($filter_user); ?>" placeholder="contains...">
        </div>
        <div>
            <label>Action</label>
            <select name="action">
                <option value="">All actions</option>
                <?php foreach ($actions as $action): ?>
                    <option value="<?php echo htmlspecialchars($action); ?>" <?php if ($filter_action === $action) echo 'selected'; ?>>
                        <?php echo htmlspecialchars(ucfirst(str_replace('_', ' ', $action))); ?>
                    </option>
                <?php endforeach; ?>
            </select>
        </div>
        <div>
            <label>Status</label>
            <select name="status">
                <option value="">All statuses</option>
                <?php foreach (array('success', 'failed', 'triggered', 'setup', 'throttled') as $status): ?>
                    <option value="<?php echo $status; ?>" <?php if ($filter_status === $status) echo 'selected'; ?>><?php echo $status; ?></option>
                <?php endforeach; ?>
            </select>
        </div>
        <div>
            <input type="submit" class="btn" value="Filter">
            <a href="admin.php" style="margin-left:8px;">Reset</a>
        </div>
    </form>

    <?php if (!empty($logs)): ?>
        <table class="admin-table">
            <thead>
                <tr>
                    <th>Date/Time</th>
                    <th>Account</th>
                    <th>IP Address</th>
                    <th>Action</th>
                    <th>Status</th>
                    <th>Details</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($logs as $log): ?>
                    <tr>
                        <td><?php echo date("Y-m-d H:i:s", strtotime($log['created_at'])); ?></td>
                        <td><?php echo htmlspecialchars($log['username']); ?></td>
                        <td><?php echo htmlspecialchars($log['ip_address']); ?></td>
                        <td><?php echo htmlspecialchars(ucfirst(str_replace('_', ' ', $log['action']))); ?></td>
                        <td class="<?php echo (strpos($log['status'], 'failed') === 0 || $log['status'] === 'triggered') ? 'status-fail' : 'status-ok'; ?>">
                            <?php echo htmlspecialchars($log['status']); ?>
                        </td>
                        <td><?php echo htmlspecialchars($log['details']); ?></td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>

        <?php if ($total_pages > 1): ?>
            <div class="pagination">
                <?php for ($i = 1; $i <= $total_pages; $i++): ?>
                    <?php $qs = http_build_query(array_merge($_GET, array('page' => $i))); ?>
                    <a href="?<?php echo htmlspecialchars($qs); ?>" class="<?php if ($page == $i) echo 'active'; ?>"><?php echo $i; ?></a>
                <?php endfor; ?>
            </div>
        <?php endif; ?>
        <p style="color: var(--muted-text-color); font-size: 0.85em;">Showing <?php echo count($logs); ?> of <?php echo $total_logs; ?> events.</p>
    <?php else: ?>
        <p>No events match the current filters.</p>
    <?php endif; ?>
</div>

<?php require_once "includes/footer.php"; ?>
