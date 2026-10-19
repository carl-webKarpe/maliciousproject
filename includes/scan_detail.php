<?php
// Full result of one scan (upload or agent), shared by the admin pages.

require_once __DIR__ . DIRECTORY_SEPARATOR . "admin_layout.php";
require_once __DIR__ . DIRECTORY_SEPARATOR . "devices.php";

// Plain-language VirusTotal status for a scans.vt_status value.
function mg_vt_status_text(?string $status): string
{
    return [
        "not_configured" => "Not set up (no API key)",
        "unavailable" => "Could not connect",
        "rate_limited" => "Quota used up, try later",
        "not_found" => "Unknown to VirusTotal",
        "auth_error" => "API key rejected",
    ][$status ?? ""] ?? "Not checked";
}

// Prints the result panel. Returns false when the scan does not exist.
function mg_render_scan_detail(PDO $pdo, int $scanId, string $closeUrl): bool
{
    $stmt = $pdo->prepare(
        "SELECT s.*, d.display_name, d.hostname, sr.status AS request_status, u.name AS uploader
         FROM scans s
         LEFT JOIN endpoint_devices d ON d.device_id = s.device_id
         LEFT JOIN scan_requests sr ON sr.id = s.scan_request_id
         LEFT JOIN users u ON u.id = s.user_id
         WHERE s.id = ?"
    );
    $stmt->execute([$scanId]);
    $scan = $stmt->fetch();
    if (!$scan) {
        return false;
    }
    $findings = $pdo->prepare("SELECT detection_name, severity, description, evidence FROM detection_results WHERE scan_id = ? ORDER BY score DESC, id");
    $findings->execute([$scanId]);
    $findings = $findings->fetchAll();

    $vtFound = $scan["vt_status"] === "found";
    $fromAgent = $scan["device_id"] !== null;
    $computer = $fromAgent ? (($scan["display_name"] ?: $scan["hostname"]) ?: $scan["device_id"]) : null;
    ?>
    <section class="panel" id="scan-detail" aria-live="polite">
        <div class="panel-head">
            <div>
                <h2><i class="fa-solid fa-file-shield" aria-hidden="true"></i> <?= mg_h($scan["original_file_name"]) ?></h2>
                <p>Scan #<?= (int) $scan["id"] ?> · <?= mg_h($scan["scanned_at"]) ?> · <?= $fromAgent ? "From computer " . mg_h($computer) : "Uploaded by " . mg_h($scan["uploader"] ?? "a user") ?></p>
            </div>
            <div class="actions">
                <?= mg_risk_badge($scan["threat_level"]) ?>
                <a class="button ghost small" href="<?= mg_h($closeUrl) ?>"><i class="fa-solid fa-xmark" aria-hidden="true"></i>Close</a>
            </div>
        </div>

        <div class="finding highlight">
            <h3>What to do</h3>
            <p><?= mg_h($scan["recommended_action"] ?: "Review the findings below.") ?></p>
        </div>

        <div class="detail-grid" style="margin-top:14px;">
            <div><span>Risk</span><strong><?= mg_h(ucfirst($scan["threat_level"])) ?> (<?= mg_h($scan["detection_status"]) ?>)</strong></div>
            <div><span>VirusTotal</span><strong><?= $vtFound ? mg_h($scan["vt_malicious"] . "/" . $scan["vt_engines"]) . " engines flagged it" : mg_h(mg_vt_status_text($scan["vt_status"])) ?></strong></div>
            <div><span>Rule-based score</span><strong><?= (int) $scan["security_score"] ?>/100</strong><br><small>100 minus matched indicator points. Not a probability.</small></div>
            <div><span>Checked by</span><strong><?= mg_h($scan["detection_source"] ?: "MalwareGuard static rules") ?></strong></div>
            <div><span>File path</span><strong><?= mg_h($scan["source_path"] ?: "Uploaded through the browser") ?></strong></div>
            <div><span>Size</span><strong><?= mg_h(mg_format_bytes((int) $scan["file_size"])) ?></strong></div>
            <div><span>Computer</span><strong><?= $computer !== null ? mg_h($computer) . "<br><small>" . mg_h($scan["device_id"]) . "</small>" : "—" ?></strong></div>
            <div><span>Scan status</span><strong><?= mg_h($scan["request_status"] ?? "completed") ?></strong></div>
            <div style="grid-column: 1 / -1;"><span>SHA-256</span><strong><code><?= mg_h($scan["file_hash"]) ?></code></strong></div>
            <?php if (!empty($scan["error_message"])): ?>
                <div style="grid-column: 1 / -1;"><span>Error</span><strong class="muted"><?= mg_h($scan["error_message"]) ?></strong></div>
            <?php endif; ?>
        </div>

        <div class="finding"><h3>Summary</h3><p><?= mg_h($scan["analysis_result"]) ?></p></div>
        <?php foreach ($findings as $finding): ?>
            <div class="finding">
                <h3><?= mg_risk_badge($finding["severity"]) ?> <?= mg_h($finding["detection_name"]) ?></h3>
                <p><?= mg_h($finding["description"]) ?></p>
                <?php if (!empty($finding["evidence"])): ?><p>Evidence: <code><?= mg_h($finding["evidence"]) ?></code></p><?php endif; ?>
            </div>
        <?php endforeach; ?>
        <?php if (!$findings): ?>
            <div class="finding"><p>No warning signs were found by the checks that ran. That is not a guarantee the file is harmless.</p></div>
        <?php endif; ?>
    </section>
    <?php
    return true;
}
