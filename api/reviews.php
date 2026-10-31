<?php
/**
 * Viatrix Tours & Travel — Reviews API
 * Dependency-free PHP backend using a JSON file store.
 *
 * Endpoints (all under api/):
 *   GET  api/reviews.php?action=list        → published reviews + stats (public)
 *   POST api/reviews.php?action=submit      → submit a review (public, pending by default)
 *   GET  api/admin.php?action=login         → admin login (session)
 *   GET  api/admin.php?action=list          → all reviews incl. pending (admin)
 *   POST api/admin.php?action=update        → approve/reject/verify (admin)
 *   POST api/admin.php?action=delete        → delete review (admin)
 *   POST api/admin.php?action=logout        → admin logout
 *
 * Storage: data/reviews.json (created automatically)
 * Admin password: data/admin-config.php — set ADMIN_PASSWORD before deploying.
 */

declare(strict_types=1);

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------
$DATA_DIR   = __DIR__ . '/data';
$STORE_FILE = $DATA_DIR . '/reviews.json';
$UPLOAD_DIR = $DATA_DIR . '/photos';
$RATE_FILE  = $DATA_DIR . '/rate-limits.json';
$MAX_IMAGE  = 4 * 1024 * 1024; // 4 MB
$PAGE_SIZE  = 6;

// Load admin password from outside web-served area if possible.
$adminConfigFile = __DIR__ . '/data/admin-config.php';
$ADMIN_PASSWORD  = 'CHANGE_ME_BEFORE_DEPLOYMENT';
if (is_file($adminConfigFile)) {
    $ADMIN_PASSWORD = (string) include $adminConfigFile;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function jsonOut(array $payload, int $code = 200): void {
    http_response_code($code);
    header('Content-Type: application/json; charset=utf-8');
    header('X-Content-Type-Options: nosniff');
    echo json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
    exit;
}

function fail(string $msg, int $code = 400): void {
    jsonOut(['ok' => false, 'error' => $msg], $code);
}

function ensureDir(string $dir): void {
    if (!is_dir($dir)) @mkdir($dir, 0755, true);
}

function loadStore(string $file): array {
    if (!is_file($file)) return [];
    $raw = @file_get_contents($file);
    if ($raw === false || $raw === '') return [];
    $data = json_decode($raw, true);
    return is_array($data) ? $data : [];
}

function saveStore(string $file, array $data): void {
    ensureDir(dirname($file));
    $tmp = $file . '.tmp';
    file_put_contents($tmp, json_encode($data, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT), LOCK_EX);
    rename($tmp, $file);
}

function lockStore(string $file) {
    ensureDir(dirname($file));
    if (!is_file($file)) @file_put_contents($file, '[]');
    $fp = fopen($file, 'c+');
    if (!$fp) fail('Storage unavailable', 500);
    flock($fp, LOCK_EX);
    $raw = stream_get_contents($fp);
    $data = json_decode((string)$raw, true);
    if (!is_array($data)) $data = [];
    return [$fp, $data];
}

function unlockStore($fp): void {
    flock($fp, LOCK_UN);
    fclose($fp);
}

function sanitizeText(string $raw, int $maxLen): string {
    // Strip tags, collapse whitespace, normalise entities, enforce max length.
    $raw = html_entity_decode($raw, ENT_QUOTES | ENT_HTML5, 'UTF-8');
    $raw = strip_tags($raw);
    $raw = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/u', '', $raw);
    $raw = preg_replace('/\s+/u', ' ', trim($raw));
    if (mb_strlen($raw) > $maxLen) $raw = mb_substr($raw, 0, $maxLen);
    return $raw;
}

function validEmail(string $email): bool {
    return (bool)filter_var(trim($email), FILTER_VALIDATE_EMAIL) && mb_strlen($email) <= 120;
}

function clientIp(): string {
    // Prefer the remote address; only fall back to proxies if present and sane.
    $keys = ['REMOTE_ADDR', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP'];
    foreach ($keys as $k) {
        if (!empty($_SERVER[$k])) {
            $val = explode(',', (string)$_SERVER[$k])[0];
            $val = trim($val);
            if (filter_var($val, FILTER_VALIDATE_IP)) return $val;
        }
    }
    return 'unknown';
}

// ---------------------------------------------------------------------------
// Rate limiting (in-process, file-based)
// ---------------------------------------------------------------------------
function checkRateLimit(string $rateFile, string $ip, int $maxPerHour = 3): void {
    if ($ip === 'unknown') return; // best-effort; honeypot still applies
    $entry = [
        'ip' => $ip,
        'submissions' => [],
    ];
    $limits = is_file($rateFile) ? (json_decode((string)file_get_contents($rateFile), true) ?: []) : [];
    $now = time();
    $limits = array_values(array_filter($limits, function ($e) use ($now) {
        return is_array($e) && isset($e['ip'], $e['submissions']) && ($now - max($e['submissions'] ?: [0])) < 3600;
    }));
    foreach ($limits as $e) {
        if (($e['ip'] ?? '') === $ip) {
            $entry['submissions'] = array_values(array_filter($e['submissions'], function ($t) use ($now) {
                return ($now - $t) < 3600;
            }));
        }
    }
    if (count($entry['submissions']) >= $maxPerHour) {
        fail('You have submitted several reviews recently. Please try again later.', 429);
    }
    $found = false;
    foreach ($limits as &$e) {
        if (($e['ip'] ?? '') === $ip) { $e['submissions'] = $entry['submissions']; $found = true; break; }
    }
    unset($e);
    if (!$found) $limits[] = $entry;
    saveStore($rateFile, $limits);
}

function recordRateLimit(string $rateFile, string $ip): void {
    if ($ip === 'unknown') return;
    $limits = is_file($rateFile) ? (json_decode((string)file_get_contents($rateFile), true) ?: []) : [];
    foreach ($limits as &$e) {
        if (($e['ip'] ?? '') === $ip) { $e['submissions'][] = time(); saveStore($rateFile, $limits); return; }
    }
    unset($e);
    $limits[] = ['ip' => $ip, 'submissions' => [time()]];
    saveStore($rateFile, $limits);
}

// ---------------------------------------------------------------------------
// Image upload validation
// ---------------------------------------------------------------------------
function validateAndSavePhoto(array $files, string $uploadDir, int $maxSize): ?array {
    if (!isset($files['photo']) || $files['photo']['error'] === UPLOAD_ERR_NO_FILE) return null;
    $f = $files['photo'];
    if ($f['error'] !== UPLOAD_ERR_OK) fail('Photo upload failed. Please try again or submit without a photo.');
    if ($f['size'] > $maxSize) fail('Photo is too large — maximum 4 MB.');
    if ($f['size'] === 0) fail('Photo file is empty.');

    // Verify actual file content, not just extension.
    $info = @getimagesize($f['tmp_name']);
    if ($info === false) fail('That file is not a valid image.');
    $allowed = [IMAGETYPE_JPEG => 'jpg', IMAGETYPE_PNG => 'png', IMAGETYPE_WEBP => 'webp'];
    if (!isset($allowed[$info[2]])) fail('Only JPG, PNG and WebP photos are accepted.');

    ensureDir($uploadDir);
    $ext  = $allowed[$info[2]];
    $name = 'photo_' . bin2hex(random_bytes(12)) . '.' . $ext;
    $dest = $uploadDir . '/' . $name;
    if (!@move_uploaded_file($f['tmp_name'], $dest)) fail('Could not save the photo. Please try again.');
    return ['file' => 'data/photos/' . $name];
}

// ---------------------------------------------------------------------------
// Admin session
// ---------------------------------------------------------------------------
function adminSessionStart(): void {
    if (session_status() === PHP_SESSION_NONE) {
        session_set_cookie_params(['httponly' => true, 'samesite' => 'Lax']);
        session_start();
    }
}
function isAdmin(): bool {
    adminSessionStart();
    return !empty($_SESSION['viatrix_admin']) && $_SESSION['viatrix_admin'] === true;
}

// ---------------------------------------------------------------------------
// Main dispatch
// ---------------------------------------------------------------------------
$action = $_GET['action'] ?? 'list';
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';

switch ($action) {

    // -------------------------------------------------------------------
    // PUBLIC: list published reviews + stats
    // -------------------------------------------------------------------
    case 'list': {
        if ($method !== 'GET') fail('Method not allowed', 405);
        [$fp, $all] = lockStore($STORE_FILE);
        unlockStore($fp);
        $published = array_values(array_filter($all, function ($r) {
            return ($r['status'] ?? '') === 'published';
        }));
        usort($published, function ($a, $b) { return strcmp($b['date'] ?? '', $a['date'] ?? ''); });

        $n = count($published);
        $avg = $n ? round(array_sum(array_column($published, 'rating')) / $n, 1) : 0;
        $dist = ['5' => 0, '4' => 0, '3' => 0, '2' => 0, '1' => 0];
        foreach ($published as $r) {
            $k = (string)($r['rating'] ?? 0);
            if (isset($dist[$k])) $dist[$k]++;
        }

        // Public view never exposes email.
        $public = array_map(function ($r) {
            return [
                'name'     => $r['name'],
                'rating'   => (int)$r['rating'],
                'date'     => $r['date'],
                'tour'     => $r['tour'],
                'title'    => $r['title'],
                'body'     => $r['body'],
                'country'  => $r['country'] ?? '',
                'photo'    => $r['photo'] ?? '',
                'verified' => !empty($r['verified']),
            ];
        }, $published);

        jsonOut([
            'ok'       => true,
            'reviews'  => $public,
            'stats'    => ['total' => $n, 'average' => $avg, 'distribution' => $dist],
            'pageSize' => $PAGE_SIZE,
        ]);
    }

    // -------------------------------------------------------------------
    // PUBLIC: submit a review
    // -------------------------------------------------------------------
    case 'submit': {
        if ($method !== 'POST') fail('Method not allowed', 405);
        $ip = clientIp();
        checkRateLimit($RATE_FILE, $ip);

        $name    = sanitizeText((string)($_POST['name'] ?? ''), 80);
        $email   = sanitizeText((string)($_POST['email'] ?? ''), 120);
        $tour    = sanitizeText((string)($_POST['tour'] ?? ''), 120);
        $title   = sanitizeText((string)($_POST['title'] ?? ''), 100);
        $body    = sanitizeText((string)($_POST['body'] ?? ''), 2500);
        $country = sanitizeText((string)($_POST['country'] ?? ''), 80);
        $rating  = (int)($_POST['rating'] ?? 0);
        $consent = !empty($_POST['consent']) || $_POST['consent'] === 'on' || $_POST['consent'] === '1';
        $website = trim((string)($_POST['website'] ?? '')); // honeypot

        // Honeypot — bots fill hidden fields; humans never see it.
        if ($website !== '') {
            // Pretend success so bots don't learn.
            jsonOut(['ok' => true, 'message' => 'Thank you — your review will appear after moderation.']);
        }

        $errors = [];
        if (mb_strlen($name) < 2)        $errors[] = 'Full name is required.';
        if (!validEmail($email))         $errors[] = 'A valid email address is required.';
        if (mb_strlen($tour) < 3)        $errors[] = 'Destination or tour is required.';
        if ($rating < 1 || $rating > 5)  $errors[] = 'A rating between 1 and 5 stars is required.';
        if (mb_strlen($title) < 3)       $errors[] = 'A review title is required.';
        if (mb_strlen($body) < 20)       $errors[] = 'The written review must be at least 20 characters.';
        if (!$consent)                   $errors[] = 'You must confirm the review is genuine and agree to publication.';
        if ($errors) fail(implode(' ', $errors), 422);

        // Basic keyword spam filter.
        $spamWords = ['http://', 'https://', 'www.', 'viagra', 'casino', 'loan offer', 'bitcoin', 'seo service', 'backlink'];
        $hay = strtolower($name . ' ' . $title . ' ' . $body);
        foreach ($spamWords as $w) {
            if (strpos($hay, $w) !== false) fail('Your review appears to contain promotional content. Please remove links and resubmit.', 422);
        }

        $photo = validateAndSavePhoto($_FILES, $UPLOAD_DIR, $MAX_IMAGE);

        [$fp, $all] = lockStore($STORE_FILE);
        $id = bin2hex(random_bytes(8));
        $all[] = [
            'id'       => $id,
            'name'     => $name,
            'email'    => $email,        // stored privately, never exposed publicly
            'country'  => $country,
            'rating'   => $rating,
            'tour'     => $tour,
            'title'    => $title,
            'body'     => $body,
            'photo'    => $photo['file'] ?? '',
            'consent'  => true,
            'verified' => false,
            'status'   => 'pending',
            'ip'       => $ip,           // stored privately for moderation only
            'date'     => date('Y-m-d H:i:s'),
        ];
        saveStore($STORE_FILE, $all);
        unlockStore($fp);
        recordRateLimit($RATE_FILE, $ip);

        jsonOut([
            'ok'      => true,
            'message' => 'Thank you for sharing your experience! Your review has been received and will be reviewed before publication.',
        ]);
    }

    // -------------------------------------------------------------------
    // ADMIN: login / logout
    // -------------------------------------------------------------------
    case 'login': {
        if ($method !== 'POST') fail('Method not allowed', 405);
        $pw = (string)($_POST['password'] ?? '');
        if ($pw === $ADMIN_PASSWORD) {
            adminSessionStart();
            $_SESSION['viatrix_admin'] = true;
            jsonOut(['ok' => true]);
        }
        fail('Incorrect password.', 401);
    }
    case 'logout': {
        adminSessionStart();
        unset($_SESSION['viatrix_admin']);
        jsonOut(['ok' => true]);
    }

    // -------------------------------------------------------------------
    // ADMIN: list all reviews (incl. pending/rejected)
    // -------------------------------------------------------------------
    case 'admin_list': {
        if (!isAdmin()) fail('Authorisation required', 401);
        [$fp, $all] = lockStore($STORE_FILE);
        unlockStore($fp);
        usort($all, function ($a, $b) { return strcmp($b['date'] ?? '', $a['date'] ?? ''); });
        jsonOut(['ok' => true, 'reviews' => $all]);
    }

    // -------------------------------------------------------------------
    // ADMIN: update status / verified flag
    // -------------------------------------------------------------------
    case 'admin_update': {
        if (!isAdmin()) fail('Authorisation required', 401);
        if ($method !== 'POST') fail('Method not allowed', 405);
        $id     = sanitizeText((string)($_POST['id'] ?? ''), 32);
        $status = sanitizeText((string)($_POST['status'] ?? ''), 20);
        $verify = $_POST['verified'] ?? null;

        if (!in_array($status, ['pending', 'published', 'rejected'], true) && $status !== '') {
            fail('Invalid status.');
        }
        [$fp, $all] = lockStore($STORE_FILE);
        $found = false;
        foreach ($all as &$r) {
            if (($r['id'] ?? '') === $id) {
                $found = true;
                if ($status !== '') $r['status'] = $status;
                if ($verify !== null) $r['verified'] = (in_array($verify, ['1', 'true', 'on', 'yes'], true));
                break;
            }
        }
        unset($r);
        saveStore($STORE_FILE, $all);
        unlockStore($fp);
        if (!$found) fail('Review not found.', 404);
        jsonOut(['ok' => true]);
    }

    // -------------------------------------------------------------------
    // ADMIN: delete review
    // -------------------------------------------------------------------
    case 'admin_delete': {
        if (!isAdmin()) fail('Authorisation required', 401);
        if ($method !== 'POST') fail('Method not allowed', 405);
        $id = sanitizeText((string)($_POST['id'] ?? ''), 32);
        [$fp, $all] = lockStore($STORE_FILE);
        $kept = [];
        $deleted = null;
        foreach ($all as $r) {
            if (($r['id'] ?? '') === $id) { $deleted = $r; continue; }
            $kept[] = $r;
        }
        saveStore($STORE_FILE, $kept);
        unlockStore($fp);
        if ($deleted && !empty($deleted['photo'])) {
            $p = __DIR__ . '/../' . $deleted['photo'];
            if (is_file($p)) @unlink($p);
        }
        if (!$deleted) fail('Review not found.', 404);
        jsonOut(['ok' => true]);
    }

    default:
        fail('Unknown action.', 404);
}
