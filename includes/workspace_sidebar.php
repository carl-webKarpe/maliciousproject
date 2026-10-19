<?php
$activeWorkspacePage = basename($_SERVER["SCRIPT_NAME"] ?? "");
if ($activeWorkspacePage === "results.php") {
    $activeWorkspacePage = "history.php";
}

$isAdminWorkspace = in_array($_SESSION["user_role"] ?? "", ["admin", "super_admin"], true);
$currentWorkspaceLink = $activeWorkspacePage === "scan.php"
    ? "scanner"
    : ($activeWorkspacePage === "history.php" ? "history" : "");

if ($isAdminWorkspace) {
    $workspaceLinks = [
        ["admin/dashboard.php#dashboard", "fa-chart-line", "Dashboard", ""],
        ["scan.php", "fa-shield-virus", "File Scanner", "scanner"],
        ["admin/dashboard.php#scan-history", "fa-clock-rotate-left", "Scan History", "history"],
        ["admin/dashboard.php#threats", "fa-triangle-exclamation", "Threats", ""],
        ["admin/dashboard.php#quarantine", "fa-box-archive", "Quarantine", ""],
        ["admin/devices.php", "fa-desktop", "Devices", ""],
        ["admin/dashboard.php#settings", "fa-gear", "Settings", ""]
    ];
} else {
    $workspaceLinks = [
        ["dashboard.php", "fa-chart-line", "Dashboard", ""],
        ["scan.php", "fa-shield-virus", "New Scan", "scanner"],
        ["history.php", "fa-clock-rotate-left", "History", "history"]
    ];
}

$sidebarClasses = ["page-sidebar"];
if (!empty($workspaceSidebarFixedHeader)) {
    $sidebarClasses[] = "page-sidebar--fixed-header";
}
if (!empty($workspaceSidebarCompact)) {
    $sidebarClasses[] = "page-sidebar--compact";
}
if ($isAdminWorkspace) {
    $sidebarClasses[] = "page-sidebar--admin";
}
?>
<aside class="<?= implode(" ", $sidebarClasses) ?>" aria-label="Main navigation">
    <div class="sidebar-label">WORKSPACE</div>
    <?php foreach ($workspaceLinks as [$path, $icon, $label, $activeKey]): ?>
        <a href="<?= htmlspecialchars($path, ENT_QUOTES, "UTF-8") ?>"<?= $activeKey !== "" && $currentWorkspaceLink === $activeKey ? ' aria-current="page"' : "" ?>>
            <i class="fa-solid <?= htmlspecialchars($icon, ENT_QUOTES, "UTF-8") ?>" aria-hidden="true"></i>
            <?= htmlspecialchars($label, ENT_QUOTES, "UTF-8") ?>
        </a>
    <?php endforeach; ?>
</aside>