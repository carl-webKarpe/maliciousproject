<?php
// Shared page shell for the admin area (admin/dashboard.php and
// admin/devices.php): one header, one sidebar, one stylesheet.
//
//   mg_admin_page_start($admin, "threats", "Threats", "Scans classified ...");
//   ... page content ...
//   mg_admin_page_end();

require_once __DIR__ . DIRECTORY_SEPARATOR . "bootstrap.php";

// Sidebar: [group label, [[key, url, icon, label], ...]]. URLs are relative
// to admin/.
function mg_admin_nav(array $admin): array
{
    $account = [["settings", "dashboard.php?view=settings", "fa-gear", "Settings"]];
    if ($admin["role"] === "super_admin") {
        $account[] = ["users", "../super_admin/dashboard.php", "fa-users", "User database"];
    }
    return [
        ["OVERVIEW", [
            ["home", "dashboard.php", "fa-house", "Dashboard"],
        ]],
        ["SCANNING", [
            ["scanner", "dashboard.php?view=scanner", "fa-shield-virus", "File Scanner"],
            ["history", "dashboard.php?view=history", "fa-clock-rotate-left", "Scan History"],
            ["threats", "dashboard.php?view=threats", "fa-triangle-exclamation", "Threats"],
            ["quarantine", "dashboard.php?view=quarantine", "fa-box-archive", "Quarantine"],
        ]],
        ["DEVICES", [
            ["computers", "devices.php?view=computers", "fa-desktop", "Computers"],
            ["tokens", "devices.php?view=tokens", "fa-key", "Add a computer"],
            ["events", "devices.php?view=events", "fa-file-arrow-down", "File events"],
            ["scans", "devices.php?view=scans", "fa-magnifying-glass", "Agent scans"],
        ]],
        ["ACCOUNT", $account],
    ];
}

function mg_admin_page_start(array $admin, string $active, string $title, string $intro = "", string $actionsHtml = ""): void
{
    $roleLabel = $admin["role"] === "super_admin" ? "Super admin" : "Admin";
    $initial = strtoupper(mb_substr($admin["name"] !== "" ? $admin["name"] : "A", 0, 1));
    ?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= mg_h($title) ?> | MalwareGuard</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css">
    <link rel="stylesheet" href="../assets/css/admin.css">
</head>
<body>
    <header class="topbar">
        <button class="menu-toggle" type="button" aria-label="Open navigation" aria-controls="adminSidebar" aria-expanded="false">
            <i class="fa-solid fa-bars" aria-hidden="true"></i>
        </button>
        <a class="brand" href="dashboard.php">
            <span class="brand-mark"><i class="fa-solid fa-shield-halved" aria-hidden="true"></i></span>
            <span>Malware<strong>Guard</strong></span>
        </a>
        <div class="topbar-user">
            <span class="avatar" aria-hidden="true"><?= mg_h($initial) ?></span>
            <span class="user-text"><strong><?= mg_h($admin["name"] ?: "Administrator") ?></strong><small><?= $roleLabel ?></small></span>
            <a class="button ghost" href="../logout.php"><i class="fa-solid fa-right-from-bracket" aria-hidden="true"></i><span>Sign out</span></a>
        </div>
    </header>
    <div class="layout">
        <nav class="sidebar" id="adminSidebar" aria-label="Admin navigation">
            <?php foreach (mg_admin_nav($admin) as [$group, $links]): ?>
                <div class="sidebar-label"><?= mg_h($group) ?></div>
                <?php foreach ($links as [$key, $url, $icon, $label]): ?>
                    <a href="<?= mg_h($url) ?>"<?= $key === $active ? ' aria-current="page"' : "" ?>>
                        <i class="fa-solid <?= mg_h($icon) ?>" aria-hidden="true"></i><?= mg_h($label) ?>
                    </a>
                <?php endforeach; ?>
            <?php endforeach; ?>
        </nav>
        <main class="content" id="main">
            <div class="page-head">
                <div>
                    <h1><?= mg_h($title) ?></h1>
                    <?php if ($intro !== ""): ?><p><?= $intro ?></p><?php endif; ?>
                </div>
                <?php if ($actionsHtml !== ""): ?><div class="page-actions"><?= $actionsHtml ?></div><?php endif; ?>
            </div>
    <?php
}

// $notice = [message, isError] or null.
function mg_admin_notice(?array $notice): void
{
    if (!$notice || $notice[0] === "") {
        return;
    }
    $isError = !empty($notice[1]);
    ?>
    <div class="notice<?= $isError ? " error" : "" ?>" role="status">
        <i class="fa-solid <?= $isError ? "fa-circle-exclamation" : "fa-circle-check" ?>" aria-hidden="true"></i>
        <span><?= mg_h($notice[0]) ?></span>
        <button type="button" class="notice-close" aria-label="Dismiss" onclick="this.parentElement.remove()">&times;</button>
    </div>
    <?php
}

function mg_admin_empty(string $icon, string $title, string $text, string $actionHtml = ""): void
{
    ?>
    <div class="empty-state">
        <i class="fa-solid <?= mg_h($icon) ?>" aria-hidden="true"></i>
        <strong><?= mg_h($title) ?></strong>
        <p><?= $text ?></p>
        <?= $actionHtml ?>
    </div>
    <?php
}

function mg_risk_badge(?string $level): string
{
    if ($level === null || $level === "") {
        return '<span class="badge not-scanned">Not scanned</span>';
    }
    return '<span class="badge ' . mg_h($level) . '">' . mg_h(ucfirst($level)) . '</span>';
}

function mg_admin_page_end(string $scripts = ""): void
{
    ?>
        </main>
    </div>
    <script>
        // Mobile navigation toggle.
        (function () {
            const toggle = document.querySelector(".menu-toggle");
            const sidebar = document.getElementById("adminSidebar");
            toggle.addEventListener("click", function () {
                const open = sidebar.classList.toggle("open");
                toggle.setAttribute("aria-expanded", open ? "true" : "false");
            });
        })();

        // Confirmation, rename prompt and "working" state for action buttons.
        document.querySelectorAll("form[method=post]").forEach(function (form) {
            form.addEventListener("submit", function (event) {
                if (form.dataset.custom === "true") return;
                const button = event.submitter || form.querySelector("button[type=submit]");
                if (button && button.dataset.confirm && !window.confirm(button.dataset.confirm)) {
                    event.preventDefault();
                    return;
                }
                if (button && button.dataset.rename !== undefined) {
                    const name = window.prompt(button.dataset.renamePrompt || "New name:", button.dataset.rename);
                    if (name === null || name.trim() === "") {
                        event.preventDefault();
                        return;
                    }
                    form.querySelector("input[data-rename-target]").value = name.trim();
                }
                if (button) {
                    button.disabled = true;
                    button.innerHTML = '<i class="fa-solid fa-spinner fa-spin" aria-hidden="true"></i> Working...';
                }
            });
        });
    </script>
    <?= $scripts ?>
</body>
</html>
    <?php
}
