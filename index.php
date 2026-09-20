<?php
ob_start();
ini_set('display_errors', '0');
ini_set('log_errors', '1');
ini_set('zlib.output_compression', '0');
date_default_timezone_set('Asia/Kolkata');
error_reporting(E_ALL);
set_time_limit(0);

const USERS_FILE = '.netvault_users.json';
const META_FILE = '.netvault_meta.json';
const SHARES_FILE = '.netvault_shares.json';
const SYSTEM_UPLOAD_DIR = '.netvault_uploads';
const CHUNK_SIZE = 16 * 1024 * 1024;
const MAX_LOGIN_ATTEMPTS = 5;
const LOGIN_LOCK_SECONDS = 30;
const MAX_STORAGE_BYTES = 30 * 1024 * 1024 * 1024; // 30 GB

$base = realpath(__DIR__);
if ($base === false) {
    http_response_code(500);
    exit('Unable to resolve server directory.');
}

// Session Setup & Configuration
$sessionDir = $base . '/.netvault_sessions';
if (!is_dir($sessionDir)) @mkdir($sessionDir, 0700);
session_save_path($sessionDir);
session_name('NETVAULTSESSID');
session_set_cookie_params(['lifetime' => 0, 'path' => '/', 'secure' => false, 'httponly' => true, 'samesite' => 'Lax']);
session_start();

if (empty($_SESSION['csrf'])) $_SESSION['csrf'] = bin2hex(random_bytes(32));

// User Database Verification
$usersFile = $base . '/' . USERS_FILE;
$sysUsers = file_exists($usersFile) ? json_decode(file_get_contents($usersFile), true) ?: [] : [];
if (empty($sysUsers)) {
    $sysUsers = ['admin' => ['hash' => password_hash('password', PASSWORD_DEFAULT), 'role' => 'admin']];
    file_put_contents($usersFile, json_encode($sysUsers));
}

// Helper Functions
function h($value) { return htmlspecialchars((string)$value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }
function clearBuffers() { while (ob_get_level() > 0) { @ob_end_clean(); } }
function noCache() { header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0'); header('Pragma: no-cache'); }
function redirectTo($url) { clearBuffers(); header('Location: ' . $url, true, 303); exit; }
function validCsrf($received, $expected) { return is_string($received) && $received !== '' && hash_equals($expected, $received); }
function requireCsrf($csrfToken) { if (!validCsrf($_POST['csrf'] ?? null, $csrfToken)) throw new RuntimeException('Invalid security token.'); }
function jsonResponse($data, $status = 200) {
    clearBuffers(); http_response_code($status);
    header('Content-Type: application/json; charset=UTF-8'); header('Cache-Control: no-store');
    echo json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE); exit;
}
function formatBytes($bytes, $precision = 2) {
    $bytes = max(0, (int)$bytes);
    if ($bytes === 0) return '0 B';
    $units = ['B', 'KB', 'MB', 'GB', 'TB'];
    $power = min((int)floor(log($bytes, 1024)), count($units) - 1);
    return number_format($bytes / (1024 ** $power), $precision) . ' ' . $units[$power];
}
function getDirectorySize($path) {
    $bytesTotal = 0; $path = realpath($path);
    if ($path !== false && $path != '' && file_exists($path)) {
        foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($path, FilesystemIterator::SKIP_DOTS)) as $object) {
            $bytesTotal += $object->getSize();
        }
    }
    return $bytesTotal;
}

function getIconSvg($isDir, $ext) {
    if ($isDir) return '<svg viewBox="0 0 24 24" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" fill="none" style="width: 100%; height: 100%; flex-shrink: 0; color: #60a5fa; fill: #60a5fa;"><path d="M11 5L13 7H20C21.1 7 22 7.9 22 9V19C22 20.1 21.1 21 20 21H4C2.9 21 2 20.1 2 19V7C2 5.9 2.9 5 4 5H11Z"></path></svg>';
    
    $video = ['mp4', 'm4v', 'webm', 'ogv', 'mkv', 'mov', 'avi', 'flv', 'wmv', 'mpg', 'mpeg', 'ts', 'm2ts', '3gp'];
    $audio = ['mp3', 'm4a', 'aac', 'wav', 'ogg', 'flac', 'wma', 'opus', 'oga', 'amr'];
    $image = ['jpg', 'jpeg', 'png', 'gif', 'webp', 'svg', 'ico'];
    $code  = ['php', 'js', 'css', 'html', 'json', 'py', 'c', 'cpp', 'java', 'xml', 'sh', 'yml', 'yaml', 'ini', 'conf'];
    
    if (in_array($ext, $video)) return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width: 100%; height: 100%; flex-shrink: 0; color:#f87171;"><path d="M15 10l4.553-2.276A1 1 0 0121 8.618v6.764a1 1 0 01-1.447.894L15 14v-4z"></path><rect x="3" y="6" width="12" height="12" rx="2" ry="2"></rect></svg>';
    if (in_array($ext, $audio)) return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width: 100%; height: 100%; flex-shrink: 0; color:#a78bfa;"><path d="M9 19V6l12-3v13M9 19c0 1.105-1.343 2-3 2s-3-.895-3-2 1.343-2 3-2 3 .895 3 2zm12-3c0 1.105-1.343 2-3 2s-3-.895-3-2 1.343-2 3-2 3 .895 3 2zM9 10l12-3"></path></svg>';
    if (in_array($ext, $image)) return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width: 100%; height: 100%; flex-shrink: 0; color:#34d399;"><rect x="3" y="3" width="18" height="18" rx="2" ry="2"></rect><circle cx="8.5" cy="8.5" r="1.5"></circle><polyline points="21 15 16 10 5 21"></polyline></svg>';
    if (in_array($ext, $code)) return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width: 100%; height: 100%; flex-shrink: 0; color:#fbbf24;"><polyline points="16 18 22 12 16 6"></polyline><polyline points="8 6 2 12 8 18"></polyline></svg>';
    if (in_array($ext, ['zip', 'rar', '7z'])) return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="width: 100%; height: 100%; flex-shrink: 0; color:#fb923c;"><path d="M4 4v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8.342a2 2 0 0 0-.602-1.43l-4.44-4.342A2 2 0 0 0 13.56 2H6a2 2 0 0 0-2 2z"></path><path d="M9 2v2"></path><path d="M9 6v2"></path><path d="M9 10v2"></path><path d="M11 4v2"></path><path d="M11 8v2"></path><path d="M11 12v2"></path></svg>';
    if ($ext === 'pdf') return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width: 100%; height: 100%; flex-shrink: 0; color:#f43f5e;"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line><polyline points="10 9 9 9 8 9"></polyline></svg>';
    
    return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width: 100%; height: 100%; flex-shrink: 0; color:#94a3b8;"><path stroke-linecap="round" stroke-linejoin="round" d="M7 21h10a2 2 0 002-2V9.414a1 1 0 00-.293-.707l-5.414-5.414A1 1 0 0012.586 3H7a2 2 0 00-2 2v14a2 2 0 002 2z"></path></svg>';
}

function mimeFor($file) {
    $ext = strtolower(pathinfo($file, PATHINFO_EXTENSION));
    $known = [
        'mp4' => 'video/mp4', 'm4v' => 'video/mp4', 'webm' => 'video/webm', 'ogv' => 'video/ogg', 'mkv' => 'video/webm',
        'mov' => 'video/quicktime', 'avi' => 'video/x-msvideo', 'mp3' => 'audio/mpeg', 'm4a' => 'audio/mp4', 'aac' => 'audio/aac',
        'wav' => 'audio/wav', 'ogg' => 'audio/ogg', 'flac' => 'audio/flac', 'opus' => 'audio/ogg', 'jpg' => 'image/jpeg',
        'jpeg' => 'image/jpeg', 'png' => 'image/png', 'gif' => 'image/gif', 'webp' => 'image/webp', 'svg' => 'image/svg+xml',
        'pdf' => 'application/pdf', 'txt' => 'text/plain; charset=UTF-8', 'log' => 'text/plain; charset=UTF-8',
        'md' => 'text/plain; charset=UTF-8', 'json' => 'application/json; charset=UTF-8', 'csv' => 'text/csv; charset=UTF-8',
        'vtt' => 'text/vtt; charset=UTF-8', 'srt' => 'text/plain; charset=UTF-8',
        'php' => 'text/plain; charset=UTF-8', 'py' => 'text/plain; charset=UTF-8', 'js' => 'text/plain; charset=UTF-8',
        'css' => 'text/css; charset=UTF-8', 'html' => 'text/html; charset=UTF-8', 'sh' => 'text/plain; charset=UTF-8',
        'c' => 'text/plain; charset=UTF-8', 'cpp' => 'text/plain; charset=UTF-8', 'java' => 'text/plain; charset=UTF-8',
        'xml' => 'application/xml; charset=UTF-8', 'yml' => 'text/plain; charset=UTF-8', 'yaml' => 'text/plain; charset=UTF-8',
        'ini' => 'text/plain; charset=UTF-8', 'conf' => 'text/plain; charset=UTF-8'
    ];
    return $known[$ext] ?? 'application/octet-stream';
}

function getMeta() {
    global $base; $f = $base . '/' . META_FILE;
    return file_exists($f) ? json_decode(file_get_contents($f), true) ?: [] : [];
}
function saveMeta($data) {
    global $base; file_put_contents($base . '/' . META_FILE, json_encode($data, JSON_UNESCAPED_SLASHES));
}
function setOwner($relPath, $user) {
    $meta = getMeta(); $meta[$relPath] = $user; saveMeta($meta);
}
function removeOwner($relPath) {
    $meta = getMeta();
    foreach ($meta as $k => $v) { if ($k === $relPath || str_starts_with($k, $relPath . '/')) unset($meta[$k]); }
    saveMeta($meta);
}
function renameOwner($oldRel, $newRel) {
    $meta = getMeta(); $updated = false;
    foreach ($meta as $k => $v) {
        if ($k === $oldRel) { $meta[$newRel] = $v; unset($meta[$k]); $updated = true; }
        elseif (str_starts_with($k, $oldRel . '/')) {
            $meta[$newRel . substr($k, strlen($oldRel))] = $v; unset($meta[$k]); $updated = true;
        }
    }
    if ($updated) saveMeta($meta);
}

function normalizeRel($value) {
    $value = str_replace("\0", '', (string)$value); $value = str_replace('\\', '/', $value);
    $parts = [];
    foreach (explode('/', $value) as $part) {
        if ($part === '' || $part === '.') continue;
        if ($part === '..') { array_pop($parts); continue; }
        $parts[] = $part;
    }
    return implode('/', $parts);
}
function insideBase($path, $base) {
    $path = rtrim(str_replace('\\', '/', $path), '/');
    $base = rtrim(str_replace('\\', '/', $base), '/');
    return $path === $base || str_starts_with($path . '/', $base . '/');
}
function resolveExisting($base, $relative) {
    $relative = normalizeRel($relative);
    $candidate = realpath($base . ($relative !== '' ? '/' . $relative : ''));
    if ($candidate === false || !insideBase($candidate, $base)) return null;
    return $candidate;
}
function relativeFromBase($absolute, $base) {
    $absolute = str_replace('\\', '/', $absolute);
    $base = rtrim(str_replace('\\', '/', $base), '/');
    return ltrim(substr($absolute, strlen($base)), '/');
}
function safeName($name) {
    $name = basename(str_replace("\0", '', (string)$name));
    $name = preg_replace('/[\x00-\x1F\x7F]/u', '', $name) ?? '';
    return trim($name);
}
function reservedName($name) {
    $lower = strtolower($name);
    return $lower === 'index.php' || str_starts_with($lower, '.netvault') || $lower === '.htaccess' || $lower === '.user.ini';
}
function blockedUpload($name) {
    if (reservedName($name)) return true;
    $ext = strtolower(pathinfo($name, PATHINFO_EXTENSION));
    return in_array($ext, ['php', 'php3', 'php4', 'php5', 'phtml', 'phar', 'cgi'], true);
}
function removeTree($path) {
    if (is_file($path) || is_link($path)) { @unlink($path); return; }
    if (!is_dir($path)) return;
    $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($path, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
    foreach ($iterator as $item) {
        if ($item->isDir() && !$item->isLink()) @rmdir($item->getPathname());
        else @unlink($item->getPathname());
    }
    @rmdir($path);
}
function uniqueDestination($directory, $fileName) {
    $candidate = $directory . '/' . $fileName;
    if (!file_exists($candidate)) return $candidate;
    $info = pathinfo($fileName);
    $stem = $info['filename'] ?? $fileName;
    $extension = isset($info['extension']) && $info['extension'] !== '' ? '.' . $info['extension'] : '';
    for ($i = 1; $i < 10000; $i++) {
        $candidate = $directory . '/' . $stem . ' (' . $i . ')' . $extension;
        if (!file_exists($candidate)) return $candidate;
    }
    throw new RuntimeException('Could not create a unique filename.');
}
function urlWith($params) {
    $query = $_GET;
    foreach ($params as $k => $v) { if ($v === null) unset($query[$k]); else $query[$k] = $v; }
    return '?' . http_build_query($query, '', '&', PHP_QUERY_RFC3986);
}
function srtToVtt($text) {
    $text = str_replace(["\r\n", "\r"], "\n", $text);
    $text = preg_replace('/(\d{2}:\d{2}:\d{2}),(\d{3})/', '$1.$2', $text) ?? $text;
    return "WEBVTT\n\n" . ltrim($text);
}

// ---------------------------------------------------------
// THUMBNAIL GENERATOR ENDPOINT
// ---------------------------------------------------------
if (isset($_GET['thumb'])) {
    session_write_close();
    $rel = normalizeRel($_GET['thumb']);
    $file = resolveExisting($base, $rel);
    if (!$file || !is_file($file)) { http_response_code(404); exit; }
    
    $thumbDir = $base . '/.netvault_thumbs';
    if (!is_dir($thumbDir)) @mkdir($thumbDir, 0700);
    
    $hash = md5($rel . filemtime($file));
    $thumbPath = $thumbDir . '/' . $hash . '.jpg';
    
    if (file_exists($thumbPath)) {
        header('Content-Type: image/jpeg');
        header('Cache-Control: public, max-age=86400');
        readfile($thumbPath);
        exit;
    }
    
    $ext = strtolower(pathinfo($file, PATHINFO_EXTENSION));
    $generated = false;
    
    if (in_array($ext, ['jpg', 'jpeg', 'png', 'gif', 'webp']) && extension_loaded('gd')) {
        $img = null;
        if ($ext === 'jpg' || $ext === 'jpeg') $img = @imagecreatefromjpeg($file);
        elseif ($ext === 'png') $img = @imagecreatefrompng($file);
        elseif ($ext === 'gif') $img = @imagecreatefromgif($file);
        elseif ($ext === 'webp') $img = @imagecreatefromwebp($file);
        
        if ($img) {
            $w = imagesx($img); $h = imagesy($img);
            $dim = 150;
            $thumb = imagecreatetruecolor($dim, $dim);
            $bg = imagecolorallocate($thumb, 15, 23, 42);
            imagefill($thumb, 0, 0, $bg);
            
            $min = min($w, $h);
            $x = ($w - $min) / 2; $y = ($h - $min) / 2;
            imagecopyresampled($thumb, $img, 0, 0, $x, $y, $dim, $dim, $min, $min);
            imagejpeg($thumb, $thumbPath, 75);
            imagedestroy($img); imagedestroy($thumb);
            $generated = true;
        }
    } elseif (in_array($ext, ['mp4', 'webm', 'mkv', 'avi', 'mov', 'ts'])) {
        $cmd = "ffmpeg -y -i " . escapeshellarg($file) . " -ss 00:00:05.000 -vframes 1 -vf \"scale=150:150:force_original_aspect_ratio=increase,crop=150:150\" " . escapeshellarg($thumbPath) . " 2>&1";
        @exec($cmd, $out, $ret);
        if ($ret === 0 && file_exists($thumbPath)) $generated = true;
    }
    
    if ($generated) {
        header('Content-Type: image/jpeg');
        header('Cache-Control: public, max-age=86400');
        readfile($thumbPath);
        exit;
    }
    
    http_response_code(404);
    exit;
}

function streamLocalFile($file, $download = false) {
    session_write_close(); clearBuffers();
    $size = filesize($file);
    if ($size === false) { http_response_code(500); exit('Unable to determine file size.'); }
    
    $name = basename($file);
    $fallback = preg_replace('/[^A-Za-z0-9._ -]/', '_', $name) ?: 'download';
    
    header('Content-Type: ' . mimeFor($file));
    header('Accept-Ranges: bytes');
    header('X-Content-Type-Options: nosniff');
    header($download ? 'Cache-Control: private, no-store, max-age=0' : 'Cache-Control: private, max-age=0, must-revalidate');
    header('Content-Disposition: ' . ($download ? 'attachment' : 'inline') . '; filename="' . addcslashes($fallback, "\\\"") . '"' . "; filename*=UTF-8''" . rawurlencode($name));
    
    if ($size === 0) { header('Content-Length: 0'); exit; }
    
    $start = 0; $end = $size - 1;
    $range = trim((string)($_SERVER['HTTP_RANGE'] ?? ''));
    if ($range !== '') {
        if (str_contains($range, ',') || !preg_match('/^bytes=(\d*)-(\d*)$/', $range, $matches)) {
            header("Content-Range: bytes */{$size}");
            http_response_code(416); exit;
        }
        $rangeStart = $matches[1]; $rangeEnd = $matches[2];
        if ($rangeStart === '' && $rangeEnd === '') { header("Content-Range: bytes */{$size}"); http_response_code(416); exit; }
        if ($rangeStart === '') {
            $suffix = (int)$rangeEnd;
            if ($suffix <= 0) { header("Content-Range: bytes */{$size}"); http_response_code(416); exit; }
            $start = max(0, $size - $suffix);
        } else {
            $start = (int)$rangeStart;
            if ($rangeEnd !== '') $end = min((int)$rangeEnd, $size - 1);
        }
        if ($start > $end || $start >= $size) { header("Content-Range: bytes */{$size}"); http_response_code(416); exit; }
        http_response_code(206);
        header("Content-Range: bytes {$start}-{$end}/{$size}");
    }
    
    $length = $end - $start + 1;
    header('Content-Length: ' . $length);
    if ($_SERVER['REQUEST_METHOD'] === 'HEAD') exit;
    
    $handle = fopen($file, 'rb');
    if ($handle === false) { http_response_code(500); exit('Unable to open file.'); }
    
    fseek($handle, $start);
    $remaining = $length;
    while ($remaining > 0 && !feof($handle)) {
        $buffer = fread($handle, min(1024 * 1024, $remaining));
        if ($buffer === false || $buffer === '') break;
        echo $buffer;
        $remaining -= strlen($buffer);
        flush();
        if (connection_aborted()) break;
    }
    fclose($handle);
    exit;
}

// ---------------------------------------------------------
// PUBLIC SHARE STREAMING (Bypasses Auth) & TRACKING
// ---------------------------------------------------------
if (isset($_GET['share'])) {
    $sharesFile = $base . '/' . SHARES_FILE;
    $shares = file_exists($sharesFile) ? json_decode(file_get_contents($sharesFile), true) : [];
    $token = preg_replace('/[^a-zA-Z0-9]/', '', $_GET['share']);
    
    if (!isset($shares[$token])) { http_response_code(404); exit('Share link invalid or expired.'); }
    
    $file = resolveExisting($base, $shares[$token]['path']);
    if (!$file || !is_file($file)) { http_response_code(404); exit('File no longer exists.'); }
    
    $range = trim((string)($_SERVER['HTTP_RANGE'] ?? ''));
    if ($range === '' || str_starts_with($range, 'bytes=0-')) {
        $shares[$token]['access_count'] = ($shares[$token]['access_count'] ?? 0) + 1;
        $shares[$token]['last_accessed'] = time();
        $shares[$token]['last_ip'] = $_SERVER['REMOTE_ADDR'] ?? 'Unknown';
        @file_put_contents($sharesFile, json_encode($shares, JSON_UNESCAPED_SLASHES));
    }
    
    $action = (string)($_GET['action'] ?? 'stream');
    streamLocalFile($file, $action === 'download');
}

// ---------------------------------------------------------
// BULK ZIP DOWNLOAD STREAMER
// ---------------------------------------------------------
if (isset($_GET['download_zip'])) {
    session_write_close(); clearBuffers();
    $zipId = preg_replace('/[^a-zA-Z0-9_]/', '', $_GET['download_zip']);
    $zipTemp = sys_get_temp_dir() . '/' . $zipId . '.zip';
    
    if (file_exists($zipTemp)) {
        header('Content-Type: application/zip');
        header('Content-Disposition: attachment; filename="NetVault_Archive.zip"');
        header('Content-Length: ' . filesize($zipTemp));
        header('Cache-Control: private, no-store, max-age=0');
        readfile($zipTemp);
        @unlink($zipTemp);
        exit;
    } else {
        http_response_code(404); exit('ZIP file not found or expired.');
    }
}

// ---------------------------------------------------------
// AUTHENTICATION
// ---------------------------------------------------------
$authError = '';
$authSuccess = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['auth_action'])) {
    $action = $_POST['auth_action'];
    $now = time();
    $lockUntil = (int)($_SESSION['login_lock_until'] ?? 0);
    
    if ($lockUntil > $now) {
        $authError = 'Too many failed attempts. Try again in ' . ($lockUntil - $now) . ' seconds.';
    } elseif (!validCsrf($_POST['csrf'] ?? null, (string)$_SESSION['csrf'])) {
        $authError = 'Invalid session token. Refresh and try again.';
    } else {
        $username = trim((string)($_POST['username'] ?? ''));
        $password = (string)($_POST['password'] ?? '');

        if ($action === 'login') {
            if (isset($sysUsers[$username]) && password_verify($password, $sysUsers[$username]['hash'])) {
                session_regenerate_id(true);
                $_SESSION['authenticated'] = true;
                $_SESSION['username'] = $username;
                $_SESSION['login_attempts'] = 0;
                $_SESSION['login_lock_until'] = 0;
                $_SESSION['csrf'] = bin2hex(random_bytes(32));
                redirectTo('./');
            } else {
                $attempts = (int)($_SESSION['login_attempts'] ?? 0) + 1;
                $_SESSION['login_attempts'] = $attempts;
                if ($attempts >= MAX_LOGIN_ATTEMPTS) {
                    $_SESSION['login_attempts'] = 0;
                    $_SESSION['login_lock_until'] = $now + LOGIN_LOCK_SECONDS;
                    $authError = 'Too many failed attempts. Login is temporarily locked.';
                } else {
                    $authError = 'Invalid username or password.';
                }
            }
        } elseif ($action === 'register') {
            if (isset($sysUsers[$username])) {
                $authError = 'Username already exists.';
            } elseif (strlen($username) < 3 || strlen($password) < 6) {
                $authError = 'Username (min 3 chars) and Password (min 6 chars) required.';
            } else {
                $sysUsers[$username] = ['hash' => password_hash($password, PASSWORD_DEFAULT), 'role' => 'user'];
                file_put_contents($usersFile, json_encode($sysUsers));
                $authSuccess = 'Account created successfully. You can now log in.';
            }
        }
    }
}

if (empty($_SESSION['authenticated'])) {
    noCache();
    $csrf = (string)$_SESSION['csrf'];
    $isRegister = isset($_GET['register']);
    ?>
    <!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
    <title>NetVault · <?= $isRegister ? 'Register' : 'Login' ?></title>
    <style>
        * { box-sizing: border-box; font-family: 'Segoe UI', system-ui, sans-serif; } 
        body { margin: 0; min-height: 100vh; display: grid; place-items: center; background: #0f172a; color: #f8fafc; }
        .card { width: min(400px, 90%); background: #1e293b; padding: 32px; border-radius: 16px; box-shadow: 0 20px 25px -5px rgba(0,0,0,0.3); border: 1px solid #334155; }
        .header { display: flex; align-items: center; gap: 16px; margin-bottom: 28px; }
        .logo { width: 50px; height: 50px; background: linear-gradient(135deg, #10b981, #059669); border-radius: 12px; display: grid; place-items: center; color: white; box-shadow: 0 4px 10px rgba(16, 185, 129, 0.3); }
        h1 { font-size: 22px; margin: 0; color: #f1f5f9; font-weight: 600; } p { margin: 4px 0 0; color: #94a3b8; font-size: 14px; }
        label { display: block; margin: 16px 0 8px; font-size: 13px; font-weight: 600; color: #cbd5e1; }
        input { width: 100%; padding: 12px 16px; border-radius: 8px; border: 1px solid #475569; background: #0f172a; color: white; outline: none; transition: 0.2s; }
        input:focus { border-color: #10b981; box-shadow: 0 0 0 3px rgba(16, 185, 129, 0.2); }
        button { width: 100%; padding: 14px; margin-top: 24px; border: none; border-radius: 8px; background: #10b981; color: white; font-weight: 700; font-size: 15px; cursor: pointer; transition: 0.2s; }
        button:hover { background: #059669; }
        .alert { padding: 12px; border-radius: 8px; margin-top: 16px; font-size: 14px; }
        .alert-error { background: rgba(220, 38, 38, 0.1); border: 1px solid #b91c1c; color: #fca5a5; }
        .alert-success { background: rgba(16, 185, 129, 0.1); border: 1px solid #047857; color: #6ee7b7; }
        .toggle-link { display: block; text-align: center; margin-top: 20px; color: #10b981; text-decoration: none; font-size: 14px; font-weight: 500; }
        .toggle-link:hover { text-decoration: underline; }
    </style></head><body>
    <div class="card">
        <div class="header">
            <div class="logo">
                <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path><rect x="9" y="9" width="6" height="6" rx="1"></rect></svg>
            </div>
            <div><h1>NetVault</h1><p><?= $isRegister ? 'Create a new account' : 'Access your secure storage' ?></p></div>
        </div>
        <form method="post">
            <input type="hidden" name="auth_action" value="<?= $isRegister ? 'register' : 'login' ?>">
            <input type="hidden" name="csrf" value="<?= h($csrf) ?>">
            <label>Username</label><input type="text" name="username" required autofocus>
            <label>Password</label><input type="password" name="password" required>
            <button type="submit"><?= $isRegister ? 'Create Account' : 'Sign In' ?></button>
        </form>
        <?php if ($authError): ?><div class="alert alert-error"><?= h($authError) ?></div><?php endif; ?>
        <?php if ($authSuccess): ?><div class="alert alert-success"><?= h($authSuccess) ?></div><?php endif; ?>
        <a href="?<?= $isRegister ? '' : 'register=1' ?>" class="toggle-link">
            <?= $isRegister ? 'Already have an account? Sign In' : 'Need an account? Register' ?>
        </a>
    </div></body></html>
    <?php exit;
}

$csrfToken = (string)$_SESSION['csrf'];
$currentUser = $_SESSION['username'];
$isAdmin = ($sysUsers[$currentUser]['role'] === 'admin');

if (isset($_GET['toggle_hidden']) && $isAdmin) {
    $_SESSION['show_hidden'] = empty($_SESSION['show_hidden']);
    redirectTo(urlWith(['toggle_hidden' => null]));
}

$requestedDir = normalizeRel($_GET['dir'] ?? '');
$currentAbs = resolveExisting($base, $requestedDir);
if ($currentAbs === null || !is_dir($currentAbs)) { $requestedDir = ''; $currentAbs = $base; }
$currentDir = relativeFromBase($currentAbs, $base);

if (isset($_GET['subtitle'])) {
    clearBuffers();
    $subtitleRel = normalizeRel($_GET['subtitle']);
    $subtitleFile = resolveExisting($base, $subtitleRel);
    if ($subtitleFile === null || !is_file($subtitleFile)) { http_response_code(404); exit('Subtitle not found.'); }
    $ext = strtolower(pathinfo($subtitleFile, PATHINFO_EXTENSION));
    if (!in_array($ext, ['vtt', 'srt'], true)) { http_response_code(415); exit('Unsupported subtitle format.'); }
    $text = @file_get_contents($subtitleFile);
    if ($text === false) { http_response_code(500); exit('Unable to read subtitle.'); }
    header('Content-Type: text/vtt; charset=UTF-8');
    header('Cache-Control: private, max-age=60');
    echo $ext === 'srt' ? srtToVtt($text) : $text;
    exit;
}

if (isset($_GET['file'])) {
    session_write_close(); 
    clearBuffers();
    $relative = normalizeRel($_GET['file']);
    $file = resolveExisting($base, $relative);
    $isReservedViewable = $isAdmin && strtolower(pathinfo($file, PATHINFO_EXTENSION)) === 'json';
    if ($file === null || !is_file($file) || (reservedName(basename($file)) && !$isReservedViewable) || str_contains('/' . relativeFromBase($file, $base) . '/', '/' . SYSTEM_UPLOAD_DIR . '/')) {
        http_response_code(404); exit('File not found.');
    }
    $action = (string)($_GET['action'] ?? 'stream');
    streamLocalFile($file, $action === 'download');
}

// ---------------------------------------------------------
// AJAX UPLOADS & ZIP BUILDER
// ---------------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['ajax_action'] ?? '') === 'upload_chunk') {
    try {
        requireCsrf($csrfToken);
        if (!isset($_FILES['chunk']) || $_FILES['chunk']['error'] !== UPLOAD_ERR_OK) throw new RuntimeException('Chunk was not received correctly.');
        if ((int)$_FILES['chunk']['size'] > CHUNK_SIZE + 1024) throw new RuntimeException('Chunk is too large.');
        
        $fileName = safeName($_POST['file_name'] ?? '');
        $filePathRaw = $_POST['file_path'] ?? '';
        $filePath = normalizeRel($filePathRaw);
        if ($filePath === '') $filePath = $fileName;
        
        if (blockedUpload($fileName)) throw new RuntimeException('This file type or filename is blocked for safety.');
        
        $uploadId = preg_replace('/[^a-zA-Z0-9_-]/', '', (string)($_POST['upload_id'] ?? '')) ?? '';
        $chunkIndex = filter_var($_POST['chunk_index'] ?? null, FILTER_VALIDATE_INT);
        $totalChunks = filter_var($_POST['total_chunks'] ?? null, FILTER_VALIDATE_INT);
        
        if ($uploadId === '' || strlen($uploadId) > 128 || $chunkIndex === false || $totalChunks === false || $chunkIndex < 0 || $totalChunks < 1 || $chunkIndex >= $totalChunks || $totalChunks > 1000000) throw new RuntimeException('Invalid upload metadata.');
        
        $uploadRoot = $base . '/' . SYSTEM_UPLOAD_DIR;
        if (!is_dir($uploadRoot) && !mkdir($uploadRoot, 0700, true) && !is_dir($uploadRoot)) throw new RuntimeException('Unable to create upload workspace.');
        $uploadDirectory = $uploadRoot . '/' . $uploadId;
        if (!is_dir($uploadDirectory) && !mkdir($uploadDirectory, 0700, true) && !is_dir($uploadDirectory)) throw new RuntimeException('Unable to create upload session.');
        
        $metadata = ['file_name' => $fileName, 'file_path' => $filePath, 'destination' => $currentDir, 'total_chunks' => (int)$totalChunks];
        $metadataFile = $uploadDirectory . '/meta.json';
        $lockFile = $uploadDirectory . '/meta.lock';
        $lockHandle = fopen($lockFile, 'c+');
        if ($lockHandle === false) throw new RuntimeException('Unable to lock upload session.');
        
        try {
            if (!flock($lockHandle, LOCK_EX)) throw new RuntimeException('Unable to lock upload session.');
            if (is_file($metadataFile)) {
                $rawMetadata = file_get_contents($metadataFile);
                $existing = json_decode((string)$rawMetadata, true);
                if (!is_array($existing)) {
                    $existing = $metadata;
                    $json = json_encode($metadata, JSON_UNESCAPED_SLASHES);
                    if ($json === false || file_put_contents($metadataFile, $json, LOCK_EX) === false) throw new RuntimeException('Unable to repair upload metadata.');
                }
            } else {
                $temporaryMetadata = $metadataFile . '.tmp';
                $json = json_encode($metadata, JSON_UNESCAPED_SLASHES);
                if ($json === false) throw new RuntimeException('Unable to encode upload metadata.');
                if (file_put_contents($temporaryMetadata, $json, LOCK_EX) === false) throw new RuntimeException('Unable to save upload metadata.');
                if (!rename($temporaryMetadata, $metadataFile)) { @unlink($temporaryMetadata); throw new RuntimeException('Unable to finalize upload metadata.'); }
            }
        } finally {
            @flock($lockHandle, LOCK_UN);
            fclose($lockHandle);
        }
        
        $partFile = $uploadDirectory . '/' . sprintf('%08d.part', $chunkIndex);
        if (!move_uploaded_file($_FILES['chunk']['tmp_name'], $partFile)) throw new RuntimeException('Unable to store uploaded chunk.');
        jsonResponse(['ok' => true, 'chunk' => $chunkIndex]);
    } catch (Throwable $e) {
        jsonResponse(['ok' => false, 'message' => $e->getMessage()], 400);
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['ajax_action'] ?? '') === 'finalize_upload') {
    try {
        requireCsrf($csrfToken);
        $uploadId = preg_replace('/[^a-zA-Z0-9_-]/', '', (string)($_POST['upload_id'] ?? '')) ?? '';
        if ($uploadId === '' || strlen($uploadId) > 128) throw new RuntimeException('Invalid upload session.');
        
        $uploadDirectory = $base . '/' . SYSTEM_UPLOAD_DIR . '/' . $uploadId;
        $metadataFile = $uploadDirectory . '/meta.json';
        if (!is_file($metadataFile)) throw new RuntimeException('Upload session not found.');
        
        $metadata = json_decode((string)file_get_contents($metadataFile), true);
        if (!is_array($metadata)) throw new RuntimeException('Upload metadata is damaged.');
        
        $fileName = safeName($metadata['file_name'] ?? '');
        $filePath = $metadata['file_path'] ?? $fileName;
        $subDirs = dirname($filePath);
        if ($subDirs === '.' || $subDirs === '\\') $subDirs = '';
        
        if (blockedUpload($fileName)) throw new RuntimeException('This file is blocked for safety.');
        
        $destination = resolveExisting($base, normalizeRel($metadata['destination'] ?? ''));
        if ($destination === null || !is_dir($destination)) throw new RuntimeException('Destination directory no longer exists.');
        
        $totalChunks = (int)($metadata['total_chunks'] ?? 0);
        for ($i = 0; $i < $totalChunks; $i++) {
            $part = $uploadDirectory . '/' . sprintf('%08d.part', $i);
            if (!is_file($part)) throw new RuntimeException('Upload incomplete. Missing chunk ' . ($i + 1) . '.');
        }
        
        $assembled = $uploadDirectory . '/assembled.tmp';
        $output = fopen($assembled, 'wb');
        if ($output === false) throw new RuntimeException('Unable to assemble uploaded file.');
        try {
            for ($i = 0; $i < $totalChunks; $i++) {
                $part = $uploadDirectory . '/' . sprintf('%08d.part', $i);
                $input = fopen($part, 'rb');
                if ($input === false) throw new RuntimeException('Unable to read upload chunk.');
                try { if (stream_copy_to_stream($input, $output) === false) throw new RuntimeException('Unable to assemble uploaded file.'); } 
                finally { fclose($input); }
            }
        } finally { fclose($output); }

        $usedStorage = getDirectorySize($base);
        if ($usedStorage + filesize($assembled) > MAX_STORAGE_BYTES) {
            @unlink($assembled);
            throw new RuntimeException('Storage quota exceeded.');
        }
        
        $finalDestDir = $destination;
        if ($subDirs !== '') {
            $finalDestDir = $destination . '/' . $subDirs;
            if (!is_dir($finalDestDir)) mkdir($finalDestDir, 0755, true);
        }
        
        $target = uniqueDestination($finalDestDir, $fileName);
        if (!@rename($assembled, $target)) {
            @unlink($assembled);
            throw new RuntimeException('Unable to move completed upload into place.');
        }
        removeTree($uploadDirectory);
        setOwner(relativeFromBase($target, $base), $currentUser);

        jsonResponse(['ok' => true, 'file_name' => basename($target)]);
    } catch (Throwable $e) {
        jsonResponse(['ok' => false, 'message' => $e->getMessage()], 400);
    }
}

// Background ZIP Builder
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['ajax_action'] ?? '') === 'build_zip') {
    try {
        requireCsrf($csrfToken);
        session_write_close(); 
        
        if (!isset($_POST['items']) || !is_array($_POST['items'])) throw new RuntimeException("No items selected.");
        if (!class_exists('ZipArchive')) throw new RuntimeException("ZIP extension not installed on server.");

        $zipId = 'nv_zip_' . bin2hex(random_bytes(8));
        $zipTemp = sys_get_temp_dir() . '/' . $zipId . '.zip';
        
        $zip = new ZipArchive();
        if ($zip->open($zipTemp, ZipArchive::CREATE | ZipArchive::OVERWRITE)) {
            foreach ($_POST['items'] as $rel) {
                $abs = resolveExisting($base, normalizeRel($rel));
                if (!$abs || reservedName(basename($abs))) continue;
                
                if (is_file($abs)) {
                    $zip->addFile($abs, basename($abs));
                    $zip->setCompressionName(basename($abs), ZipArchive::CM_STORE);
                } elseif (is_dir($abs)) {
                    $baseFolder = basename($abs);
                    $zip->addEmptyDir($baseFolder);
                    $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($abs, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::SELF_FIRST);
                    foreach ($iterator as $item) {
                        $localPath = $baseFolder . '/' . str_replace('\\', '/', $iterator->getSubPathname());
                        if ($item->isDir()) {
                            $zip->addEmptyDir($localPath);
                        } else {
                            $zip->addFile($item->getPathname(), $localPath);
                            $zip->setCompressionName($localPath, ZipArchive::CM_STORE);
                        }
                    }
                }
            }
            $zip->close();
            jsonResponse(['ok' => true, 'zip_id' => $zipId]);
        } else {
            throw new RuntimeException("Failed to create temporary ZIP file.");
        }
    } catch (Throwable $e) {
        jsonResponse(['ok' => false, 'message' => $e->getMessage()], 400);
    }
}

// Share Link Generator
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['ajax_action'] ?? '') === 'create_share') {
    try {
        requireCsrf($csrfToken);
        $relPath = normalizeRel($_POST['share_target'] ?? '');
        $file = resolveExisting($base, $relPath);
        if (!$file || !is_file($file) || reservedName(basename($file))) throw new RuntimeException("Invalid file for sharing.");
        
        $sharesFile = $base . '/' . SHARES_FILE;
        $shares = file_exists($sharesFile) ? json_decode(file_get_contents($sharesFile), true) : [];
        $token = substr(str_shuffle("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"), 0, 8);
        $shares[$token] = [
            'path' => $relPath, 
            'created_by' => $currentUser, 
            'time' => time(),
            'access_count' => 0,
            'last_accessed' => null
        ];
        file_put_contents($sharesFile, json_encode($shares, JSON_UNESCAPED_SLASHES));
        
        $protocol = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off' || $_SERVER['SERVER_PORT'] == 443) ? "https://" : "http://";
        $host = $_SERVER['HTTP_HOST'];
        $path = explode('?', $_SERVER['REQUEST_URI'], 2)[0];
        $link = $protocol . $host . $path . '?share=' . $token;
        
        jsonResponse(['ok' => true, 'link' => $link]);
    } catch (Throwable $e) {
        jsonResponse(['ok' => false, 'message' => $e->getMessage()]);
    }
}

// ---------------------------------------------------------
// STANDARD POST ACTIONS
// ---------------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST' && !isset($_POST['ajax_action'])) {
    try {
        requireCsrf($csrfToken);

        if (isset($_POST['logout_action'])) {
            session_destroy();
            redirectTo('./');
        }

        if (isset($_POST['revoke_share'])) {
            $tokenToRevoke = preg_replace('/[^a-zA-Z0-9]/', '', $_POST['revoke_share']);
            $sharesFile = $base . '/' . SHARES_FILE;
            $shares = file_exists($sharesFile) ? json_decode(file_get_contents($sharesFile), true) : [];
            
            if (isset($shares[$tokenToRevoke])) {
                if ($isAdmin || ($shares[$tokenToRevoke]['created_by'] ?? '') === $currentUser) {
                    unset($shares[$tokenToRevoke]);
                    file_put_contents($sharesFile, json_encode($shares, JSON_UNESCAPED_SLASHES));
                }
            }
            redirectTo(urlWith(['dir' => $currentDir]));
        }

        if (isset($_POST['manage_system_action']) && $isAdmin) {
            if ($_POST['manage_system_action'] === 'clear_temp') {
                $uploadRoot = $base . '/' . SYSTEM_UPLOAD_DIR;
                if (is_dir($uploadRoot)) {
                    $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($uploadRoot, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
                    foreach ($iterator as $item) {
                        if ($item->isDir() && !$item->isLink()) @rmdir($item->getPathname());
                        else @unlink($item->getPathname());
                    }
                }
                
                $thumbRoot = $base . '/.netvault_thumbs';
                if (is_dir($thumbRoot)) {
                    $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($thumbRoot, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
                    foreach ($iterator as $item) {
                        if ($item->isDir() && !$item->isLink()) @rmdir($item->getPathname());
                        else @unlink($item->getPathname());
                    }
                }
                
                $sysTemp = sys_get_temp_dir();
                if (is_dir($sysTemp)) {
                    $zipFiles = glob($sysTemp . '/*.zip');
                    if ($zipFiles) {
                        foreach ($zipFiles as $zf) {
                            @unlink($zf);
                        }
                    }
                }
            }
            redirectTo(urlWith(['dir' => $currentDir]));
        }

        if (isset($_POST['manage_user_action']) && $isAdmin) {
            $action = $_POST['manage_user_action'];
            $targetUser = trim($_POST['target_user']);
            
            if ($targetUser !== 'admin' && isset($sysUsers[$targetUser])) {
                if ($action === 'delete') {
                    unset($sysUsers[$targetUser]);
                } elseif ($action === 'toggle_admin') {
                    $sysUsers[$targetUser]['role'] = ($sysUsers[$targetUser]['role'] === 'admin') ? 'user' : 'admin';
                } elseif ($action === 'reset_pass' && !empty($_POST['new_pass'])) {
                    $sysUsers[$targetUser]['hash'] = password_hash($_POST['new_pass'], PASSWORD_DEFAULT);
                }
                file_put_contents($usersFile, json_encode($sysUsers));
            }
            redirectTo(urlWith(['dir' => $currentDir]));
        }
        
        if (isset($_POST['move_items']) && isset($_POST['move_dest']) && is_array($_POST['move_items'])) {
            $destRel = normalizeRel($_POST['move_dest']);
            $destDir = resolveExisting($base, $destRel);
            
            if ($destDir && is_dir($destDir)) {
                foreach ($_POST['move_items'] as $sourceRel) {
                    $sourceRel = normalizeRel($sourceRel);
                    $source = resolveExisting($base, $sourceRel);
                    
                    if ($source && !reservedName(basename($source))) {
                        if ($source !== $destDir && !str_starts_with($destDir . '/', $source . '/')) {
                            $newPath = $destDir . '/' . basename($source);
                            if (!file_exists($newPath) && rename($source, $newPath)) {
                                $newRel = relativeFromBase($newPath, $base);
                                renameOwner($sourceRel, $newRel);
                            }
                        }
                    }
                }
            }
            redirectTo(urlWith(['dir' => $currentDir]));
        }

        if (isset($_POST['new_folder'])) {
            $name = safeName($_POST['new_folder']);
            if (reservedName($name)) throw new RuntimeException('Reserved folder name.');
            $newDir = $currentAbs . '/' . $name;
            if (file_exists($newDir) || !mkdir($newDir, 0755)) throw new RuntimeException('Cannot create folder.');
            setOwner(ltrim($currentDir . '/' . $name, '/'), $currentUser);
            redirectTo(urlWith(['dir' => $currentDir]));
        }

        if (isset($_POST['new_file'])) {
            $name = safeName($_POST['new_file']);
            if (blockedUpload($name)) throw new RuntimeException('File extension is blocked.');
            $newPath = $currentAbs . '/' . $name;
            if (file_exists($newPath) || file_put_contents($newPath, '') === false) throw new RuntimeException('Cannot create file.');
            $relPath = ltrim($currentDir . '/' . $name, '/');
            setOwner($relPath, $currentUser);
            redirectTo(urlWith(['dir' => $currentDir, 'edit' => $relPath]));
        }

        if (isset($_POST['delete_item'])) {
            $items = is_array($_POST['delete_item']) ? $_POST['delete_item'] : [$_POST['delete_item']];
            foreach ($items as $relative) {
                $relative = normalizeRel($relative);
                $target = resolveExisting($base, $relative);
                if ($target && !reservedName(basename($target))) {
                    removeTree($target);
                    removeOwner($relative);
                }
            }
            redirectTo(urlWith(['dir' => $currentDir]));
        }

        if (isset($_POST['rename_target']) && isset($_POST['rename_new'])) {
            $oldRel = normalizeRel($_POST['rename_target']);
            $target = resolveExisting($base, $oldRel);
            $newName = safeName($_POST['rename_new']);
            if ($target && !reservedName($newName) && !reservedName(basename($target))) {
                $newPath = dirname($target) . '/' . $newName;
                if (!file_exists($newPath) && rename($target, $newPath)) {
                    $newRel = relativeFromBase($newPath, $base);
                    renameOwner($oldRel, $newRel);
                }
            }
            redirectTo(urlWith(['dir' => $currentDir]));
        }

        if (isset($_POST['save_file']) && isset($_POST['file_content'])) {
            $target = resolveExisting($base, normalizeRel($_POST['save_file']));
            if ($target && is_file($target) && !reservedName(basename($target))) {
                file_put_contents($target, $_POST['file_content']);
            }
            redirectTo(urlWith(['dir' => $currentDir]));
        }
        
        if (isset($_POST['extract_zip'])) {
            $target = resolveExisting($base, normalizeRel($_POST['extract_zip']));
            if ($target && is_file($target) && class_exists('ZipArchive')) {
                $zip = new ZipArchive;
                if ($zip->open($target) === TRUE) {
                    $extractPath = dirname($target) . '/' . pathinfo($target, PATHINFO_FILENAME);
                    if (!is_dir($extractPath)) mkdir($extractPath);
                    $zip->extractTo($extractPath);
                    $zip->close();
                    setOwner(relativeFromBase($extractPath, $base), $currentUser);
                }
            }
            redirectTo(urlWith(['dir' => $currentDir]));
        }

    } catch (Throwable $e) {
        $errorMsg = $e->getMessage();
    }
}

// Prepare file system view
$usedStorage = getDirectorySize($base);
$storagePercentage = min(100, ($usedStorage / MAX_STORAGE_BYTES) * 100);
$storageColor = $storagePercentage > 90 ? '#ef4444' : ($storagePercentage > 75 ? '#eab308' : '#10b981');

$fileMeta = getMeta();
$items = scandir($currentAbs);
$folders = [];
$files = [];

$showHidden = !empty($_SESSION['show_hidden']);

$videoExts = ['mp4', 'm4v', 'webm', 'ogv', 'mkv', 'mov', 'avi', 'flv', 'wmv', 'mpg', 'mpeg', 'ts', 'm2ts', '3gp'];
$audioExts = ['mp3', 'm4a', 'aac', 'wav', 'ogg', 'flac', 'wma', 'opus', 'oga', 'amr'];
$imageExts = ['jpg', 'jpeg', 'png', 'gif', 'webp', 'svg', 'ico'];
$textExts = ['txt', 'log', 'md', 'json', 'csv', 'vtt', 'srt', 'php', 'py', 'js', 'css', 'html', 'sh', 'c', 'cpp', 'java', 'xml', 'yml', 'yaml', 'ini', 'conf'];

foreach ($items as $item) {
    if ($item === '.' || $item === '..') continue;
    $isSystemReserved = reservedName($item);
    if ((!$showHidden || !$isAdmin) && ($isSystemReserved || str_starts_with($item, '.'))) continue;
    
    $path = $currentAbs . '/' . $item;
    $rel = relativeFromBase($path, $base);
    $stat = stat($path);
    $isDir = is_dir($path);
    
    $entry = [
        'name' => $item, 'path' => $rel, 'size' => $isDir ? getDirectorySize($path) : $stat['size'],
        'mtime' => $stat['mtime'], 'is_dir' => $isDir, 'ext' => $isDir ? '' : strtolower(pathinfo($item, PATHINFO_EXTENSION)),
        'owner' => $fileMeta[$rel] ?? '--', 'is_reserved' => $isSystemReserved,
        'is_reserved_viewable' => $isAdmin && $isSystemReserved && strtolower(pathinfo($item, PATHINFO_EXTENSION)) === 'json'
    ];
    if ($isDir) $folders[] = $entry; else $files[] = $entry;
}

usort($folders, fn($a, $b) => strcasecmp($a['name'], $b['name']));
usort($files, fn($a, $b) => strcasecmp($a['name'], $b['name']));

$breadcrumbs = explode('/', $currentDir);

// Detect Preview mode
$previewRelative = isset($_GET['preview']) ? normalizeRel($_GET['preview']) : '';
$previewFile = $previewRelative !== '' ? resolveExisting($base, $previewRelative) : null;
if ($previewFile !== null && (!is_file($previewFile) || (reservedName(basename($previewFile)) && !($isAdmin && strtolower(pathinfo($previewFile, PATHINFO_EXTENSION)) === 'json')))) $previewFile = null;

$tracks = [];
if ($previewFile !== null && in_array(strtolower(pathinfo($previewFile, PATHINFO_EXTENSION)), $videoExts, true)) {
    $videoDirectory = dirname($previewFile);
    $videoBase = pathinfo($previewFile, PATHINFO_FILENAME);
    $relativeDirectory = dirname($previewRelative);
    if ($relativeDirectory === '.') $relativeDirectory = '';
    foreach (scandir($videoDirectory) ?: [] as $subtitleName) {
        if ($subtitleName === '.' || $subtitleName === '..') continue;
        $subtitleExtension = strtolower(pathinfo($subtitleName, PATHINFO_EXTENSION));
        if (!in_array($subtitleExtension, ['vtt', 'srt'], true)) continue;
        $subtitleStem = pathinfo($subtitleName, PATHINFO_FILENAME);
        if ($subtitleStem !== $videoBase && !str_starts_with($subtitleStem, $videoBase . '.')) continue;
        $suffix = $subtitleStem === $videoBase ? '' : substr($subtitleStem, strlen($videoBase) + 1);
        $language = $suffix !== '' ? strtolower(preg_replace('/[^a-zA-Z0-9_-]/', '', $suffix) ?: 'und') : 'en';
        $label = $suffix !== '' ? strtoupper($suffix) : 'Subtitles';
        $subtitleRelative = ltrim(($relativeDirectory !== '' ? $relativeDirectory . '/' : '') . $subtitleName, '/');
        $tracks[] = ['src' => urlWith(['subtitle' => $subtitleRelative]), 'lang' => $language, 'label' => $label];
    }
}
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>NetVault</title>
    
    <?php if (isset($_GET['edit'])): ?>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.13/codemirror.min.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.13/theme/dracula.min.css">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.13/codemirror.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.13/mode/javascript/javascript.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.13/mode/xml/xml.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.13/mode/css/css.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.13/mode/htmlmixed/htmlmixed.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.13/mode/clike/clike.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.13/mode/php/php.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.13/mode/python/python.min.js"></script>
    <?php endif; ?>
    
    <?php if ($previewFile !== null && in_array(strtolower(pathinfo($previewFile, PATHINFO_EXTENSION)), $videoExts, true)): ?>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/artplayer/5.1.7/artplayer.js"></script>
    <?php endif; ?>

    <style>
        :root { 
            --bg: #0f172a; --panel: #1e293b; --text: #f8fafc; --muted: #94a3b8; 
            --border: #334155; --accent: #10b981; --accent-hover: #059669; --danger: #ef4444; 
        }
        * { box-sizing: border-box; font-family: 'Segoe UI', system-ui, sans-serif; }
        body { margin: 0; background: var(--bg); color: var(--text); }
        
        .navbar { display: flex; justify-content: space-between; align-items: center; padding: 16px 24px; background: var(--panel); border-bottom: 1px solid var(--border); position: sticky; top: 0; z-index: 50; }
        .brand { display: flex; align-items: center; gap: 12px; font-weight: 700; font-size: 20px; color: white; text-decoration: none;}
        .logo { width: 36px; height: 36px; background: linear-gradient(135deg, var(--accent), var(--accent-hover)); border-radius: 8px; display: flex; align-items: center; justify-content: center; color: white; }
        
        .search-box { display: flex; align-items: center; background: var(--bg); border: 1px solid var(--border); border-radius: 20px; padding: 0 16px; width: 100%; max-width: 400px; margin: 0 20px; transition: 0.2s; height: 42px; }
        .search-box:focus-within { border-color: var(--accent); box-shadow: 0 0 0 2px rgba(16,185,129,0.2); }
        .search-box svg { width: 18px; height: 18px; color: var(--muted); flex-shrink: 0; display: block; margin: 0; padding: 0; }
        #searchInput { flex: 1 !important; border: none !important; background: transparent !important; color: white !important; outline: none !important; font-size: 14px !important; margin: 0 !important; padding: 0 0 0 10px !important; box-shadow: none !important; border-radius: 0 !important; height: 100% !important; }

        .nav-right { display: flex; align-items: center; gap: 16px; }
        .storage-container { display: flex; flex-direction: column; align-items: flex-end; gap: 4px; }
        .quota-text { font-size: 12px; color: var(--muted); font-weight: 500; }
        .progress-bar { width: 120px; height: 6px; background: var(--bg); border-radius: 4px; overflow: hidden; border: 1px solid var(--border); }
        .progress-fill { height: 100%; background: <?= $storageColor ?>; border-radius: 4px; transition: width 0.3s; }
        
        .btn { padding: 8px 16px; border: none; border-radius: 8px; background: var(--accent); color: white; font-weight: 600; cursor: pointer; text-decoration: none; display: inline-flex; align-items: center; gap: 6px; transition: 0.2s; font-size: 14px; }
        .btn:hover:not(:disabled) { background: var(--accent-hover); transform: translateY(-1px); }
        .btn:disabled { opacity: 0.6; cursor: not-allowed; }
        .btn-danger { background: rgba(239, 68, 68, 0.1); color: #fca5a5; border: 1px solid rgba(239, 68, 68, 0.2); }
        .btn-danger:hover { background: var(--danger); color: white; }
        .btn-sm { padding: 6px 10px; font-size: 13px; border-radius: 6px; background: transparent; border: 1px solid var(--border); color: var(--text); }
        .btn-sm:hover { background: var(--border); }
        
        .btn-icon { padding: 6px; display: inline-flex; align-items: center; justify-content: center; border-radius: 6px; background: transparent; border: 1px solid transparent; color: var(--muted); transition: 0.2s; cursor: pointer; text-decoration: none; position: relative; }
        .btn-icon:hover { color: var(--text); background: rgba(255,255,255,0.05); border-color: var(--border); }
        .btn-icon svg { width: 18px; height: 18px; }
        .btn-icon-danger:hover { color: #fca5a5; background: rgba(239, 68, 68, 0.15); border-color: rgba(239, 68, 68, 0.3); }

        .checkbox-container { display: inline-flex; align-items: center; justify-content: center; position: relative; cursor: pointer; user-select: none; width: 18px; height: 18px; }
        .checkbox-container input { position: absolute; opacity: 0; cursor: pointer; height: 0; width: 0; }
        .checkmark { position: absolute; top: 0; left: 0; height: 18px; width: 18px; background: var(--bg); border: 2px solid var(--muted); border-radius: 4px; transition: 0.2s; }
        .checkbox-container:hover input ~ .checkmark { border-color: var(--accent); }
        .checkbox-container input:checked ~ .checkmark { background-color: var(--accent); border-color: var(--accent); }
        .checkmark:after { content: ""; position: absolute; display: none; }
        .checkbox-container input:checked ~ .checkmark:after { display: block; }
        .checkbox-container .checkmark:after { left: 4px; top: 1px; width: 4px; height: 9px; border: solid white; border-width: 0 2px 2px 0; transform: rotate(45deg); }

        .main { padding: 32px 24px; max-width: 1400px; margin: 0 auto; }
        .toolbar { display: flex; justify-content: space-between; flex-wrap: wrap; gap: 16px; margin-bottom: 24px; align-items: center; }
        .breadcrumbs { display: flex; gap: 8px; font-size: 18px; font-weight: 500; align-items: center; }
        .breadcrumbs a { color: var(--text); text-decoration: none; transition: 0.2s; padding: 4px 8px; border-radius: 6px; }
        .breadcrumbs a:hover { background: var(--border); }
        .breadcrumbs span { color: var(--muted); }
        
        #selection-toolbar { display: none; background: var(--panel); border: 1px solid var(--border); padding: 12px 20px; border-radius: 12px; margin-bottom: 20px; align-items: center; justify-content: space-between; box-shadow: 0 4px 15px rgba(0,0,0,0.2); }
        
        .table-container { background: var(--panel); border-radius: 12px; border: 1px solid var(--border); overflow: hidden; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1); }
        table { width: 100%; border-collapse: collapse; text-align: left; }
        th { background: rgba(0,0,0,0.2); padding: 14px 20px; font-size: 12px; text-transform: uppercase; color: var(--muted); letter-spacing: 0.5px; font-weight: 600; cursor: pointer; user-select: none; transition: 0.2s; }
        th:hover { background: rgba(0,0,0,0.4); color: white; }
        td { padding: 14px 20px; border-bottom: 1px solid var(--border); color: var(--text); font-size: 14px; }
        tr:last-child td { border-bottom: none; }
        tr:hover td { background: rgba(255,255,255,0.03); }
        tr.focused { outline: 2px solid var(--accent); outline-offset: -2px; background: rgba(255,255,255,0.05) !important; border-radius: 4px; }
        
        .sort-icon { display: inline-block; width: 12px; margin-left: 4px; color: var(--accent); }
        .item-name { display: flex; align-items: center; gap: 12px; color: var(--text); text-decoration: none; font-weight: 500; }
        .actions-cell { display: flex; justify-content: flex-end; align-items: center; gap: 4px; flex-wrap: wrap; }
        .actions-cell form { margin: 0; }
        
        .grid-only { display: none !important; }
        .list-only { display: block !important; }
        .icon-wrapper { width: 22px; height: 22px; flex-shrink: 0; }

        .grid-view table { display: block; border: none; width: 100%; }
        .grid-view thead { display: none; }
        .grid-view tbody { display: grid; grid-template-columns: repeat(auto-fill, minmax(160px, 1fr)); gap: 16px; padding: 16px; width: 100%; }
        .grid-view tr.file-row { display: flex; flex-direction: column; align-items: center; border: 1px solid var(--border); border-radius: 12px; background: var(--bg); padding: 16px; position: relative; transition: 0.2s; cursor: pointer; text-align: center; }
        .grid-view tr.file-row:hover { transform: translateY(-2px); box-shadow: 0 10px 15px -3px rgba(0,0,0,0.3); border-color: var(--accent); }
        .grid-view tr.file-row.focused { outline: 2px solid var(--accent); outline-offset: 2px; }
        .grid-view td { display: none; border: none; padding: 0; }
        .grid-view td:nth-child(1) { display: block; position: absolute; top: 12px; left: 12px; z-index: 2; }
        .grid-view td:nth-child(2) { display: flex; flex-direction: column; align-items: center; width: 100%; }
        
        .grid-view .item-name { flex-direction: column; gap: 12px; font-size: 13px; font-weight: 600; width: 100%; word-break: break-word; text-decoration: none; color: var(--text); display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; overflow: hidden; align-items: center; }
        .grid-view .icon-wrapper { width: 64px; height: 64px; }
        .grid-view .file-thumb { width: 100px; height: 100px; object-fit: cover; border-radius: 8px; box-shadow: 0 4px 10px rgba(0,0,0,0.3); }
        
        .grid-view .actions-cell { position: absolute; top: 8px; right: 8px; background: rgba(15,23,42,0.9); border-radius: 8px; padding: 4px; display: none; flex-direction: column; gap: 2px; border: 1px solid var(--border); z-index: 5; }
        .grid-view tr:hover .actions-cell { display: flex; }
        
        .grid-view tr.ignore-search { grid-column: 1 / -1; display: flex; flex-direction: row; padding: 12px 16px; background: transparent; border: 1px dashed var(--border); }
        .grid-view tr.ignore-search td:nth-child(2) { display: block; text-align: left; }
        .grid-view tr.ignore-search .item-name { flex-direction: row; display: flex; font-size: 14px; }
        .grid-view tr.ignore-search .icon-wrapper { width: 22px; height: 22px; }

        .grid-view .grid-only { display: block !important; }
        .grid-view .list-only { display: none !important; }
        
        .modal { display: none; position: fixed; inset: 0; background: rgba(0,0,0,0.6); backdrop-filter: blur(4px); place-items: center; padding: 20px; z-index: 100; opacity: 0; transition: opacity 0.2s; }
        .modal.active { display: grid; opacity: 1; }
        .modal-content { background: var(--panel); padding: 28px; border-radius: 16px; width: 100%; max-width: 450px; border: 1px solid var(--border); box-shadow: 0 25px 50px -12px rgba(0,0,0,0.5); transform: scale(0.95); transition: transform 0.2s; max-height: 90vh; overflow-y: auto;}
        .modal.active .modal-content { transform: scale(1); }
        .modal-content.large { max-width: 900px; }
        #modal-upload .modal-content { max-width: 600px; } 

        .modal h2 { margin: 0 0 20px 0; font-size: 20px; font-weight: 600; display:flex; justify-content: space-between; align-items: center;}
        input[type="text"], input[type="file"], textarea { width: 100%; padding: 12px; margin-bottom: 20px; background: var(--bg); border: 1px solid var(--border); color: white; border-radius: 8px; font-size: 14px; }
        
        .CodeMirror { height: 500px !important; border-radius: 8px; font-family: 'Consolas', monospace; font-size: 14px; border: 1px solid var(--border); margin-bottom: 20px; }
        textarea { height: 500px; font-family: 'Consolas', monospace; resize: vertical; line-height: 1.5; }
        
        .uploads { display: grid; gap: 10px; margin-top: 20px; }
        .ucard { padding: 14px; border: 1px solid var(--border); border-radius: 12px; background: var(--bg); }
        .uhead { display: flex; justify-content: space-between; gap: 10px; margin-bottom: 10px; }
        .uname { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-size: 13px; font-weight: 600; }
        .upercent { font-size: 13px; font-weight: 700; color: var(--accent); }
        .utrack { height: 6px; overflow: hidden; border-radius: 999px; background: var(--panel); border: 1px solid var(--border); } 
        .ufill { width: 0; height: 100%; background: var(--accent); transition: width .1s linear; }
        .umeta { display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 8px; margin-top: 12px; }
        .ustat { padding: 8px; border-radius: 8px; background: var(--panel); border: 1px solid var(--border); text-align: center; }
        .ulabel { color: var(--muted); font-size: 10px; text-transform: uppercase; font-weight: 600; }
        .uvalue { margin-top: 4px; color: var(--text); font-size: 12px; font-weight: 600; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

        .preview-container { background: var(--panel); border: 1px solid var(--border); border-radius: 12px; padding: 24px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1); }
        .ptop { display: flex; align-items: center; justify-content: space-between; gap: 16px; flex-wrap: wrap; margin-bottom: 24px; padding-bottom: 16px; border-bottom: 1px solid var(--border); }
        .ptop h1 { margin: 4px 0 0; font-size: 22px; word-break: break-all; }
        .pmeta { color: var(--muted); font-size: 13px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; }
        .media { width: 100%; max-width: 1000px; margin: 0 auto; display: flex; flex-direction: column; align-items: center; }
        .videoshell { background: #000; border-radius: 12px; overflow: hidden; width: 100%; height: 75vh; box-shadow: 0 10px 25px rgba(0,0,0,0.5); }
        .artplayer-app { width: 100%; height: 100%; }
        .img-preview { max-width: 100%; max-height: 75vh; object-fit: contain; border-radius: 8px; box-shadow: 0 4px 15px rgba(0,0,0,0.3); }
        .text-preview { width: 100%; max-height: 70vh; overflow: auto; margin: 0; padding: 20px; border: 1px solid var(--border); border-radius: 8px; background: var(--bg); white-space: pre-wrap; font-family: 'Consolas', monospace; font-size: 14px; line-height: 1.6; color: #e2e8f0; }
        .captionnote { margin-top: 12px; color: var(--muted); font-size: 13px; text-align: center; }
        .empty-preview { padding: 40px; text-align: center; color: var(--muted); background: var(--bg); border-radius: 8px; border: 1px dashed var(--border); width: 100%; }
        
        .zip-table { width: 100%; border-collapse: collapse; text-align: left; border-radius: 8px; overflow: hidden; border: 1px solid var(--border); }
        .zip-table th { background: var(--bg); color: var(--muted); font-size: 12px; text-transform: uppercase; padding: 12px 16px; font-weight: 600; }
        .zip-table td { padding: 12px 16px; border-top: 1px solid var(--border); color: var(--text); font-size: 13px; }

        #dropOverlay { position: fixed; inset: 0; background: rgba(16, 185, 129, 0.9); z-index: 9999; display: flex; align-items: center; justify-content: center; flex-direction: column; color: white; font-size: 28px; font-weight: 700; opacity: 0; pointer-events: none; transition: 0.2s; backdrop-filter: blur(4px); }
        #dropOverlay.active { opacity: 1; pointer-events: all; }
        #dropOverlay svg { width: 72px; height: 72px; margin-bottom: 20px; }
        
        #zipOverlay { position: fixed; inset: 0; background: rgba(15, 23, 42, 0.9); z-index: 9999; display: flex; align-items: center; justify-content: center; flex-direction: column; color: white; font-size: 20px; font-weight: 600; opacity: 0; pointer-events: none; transition: 0.2s; backdrop-filter: blur(4px); }
        #zipOverlay.active { opacity: 1; pointer-events: all; }
        .spinner { border: 4px solid rgba(255,255,255,0.1); border-left-color: var(--accent); border-radius: 50%; width: 40px; height: 40px; animation: spin 1s linear infinite; margin-bottom: 16px; }
        @keyframes spin { 100% { transform: rotate(360deg); } }

        @media (max-width: 768px) {
            .navbar { flex-wrap: wrap; gap: 16px; }
            .search-box { order: 3; max-width: 100%; margin: 0; }
            .hide-mobile { display: none; }
        }
    </style>
</head>
<body>

<div id="dropOverlay">
    <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12"></path></svg>
    Drop Files or Folders Here to Upload
</div>

<div id="zipOverlay">
    <div class="spinner"></div>
    <div>Compressing Files...</div>
    <div style="font-size: 13px; color: var(--muted); margin-top: 8px; font-weight: 400;">This may take a few minutes for large files. Feel free to browse in another tab.</div>
</div>

<nav class="navbar">
    <a href="./" class="brand">
        <div class="logo">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path><rect x="9" y="9" width="6" height="6" rx="1"></rect></svg>
        </div>
        NetVault
    </a>
    
    <div class="search-box">
        <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"></path></svg>
        <input type="text" id="searchInput" placeholder="Search files and folders...">
    </div>

    <div class="nav-right">
        <button id="viewToggleBtn" class="btn-icon hide-mobile" title="Toggle Grid View">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7"></rect><rect x="14" y="3" width="7" height="7"></rect><rect x="14" y="14" width="7" height="7"></rect><rect x="3" y="14" width="7" height="7"></rect></svg>
        </button>

        <button class="btn btn-sm hide-mobile" onclick="document.getElementById('modal-shares').classList.add('active')">
            <svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24" style="vertical-align:text-bottom; margin-right:4px;"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1"></path></svg>
            Shared Links
        </button>

        <?php if ($isAdmin): ?>
            <a href="?toggle_hidden=1" class="btn btn-sm hide-mobile" title="Toggle Hidden Files">
                <svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"></path><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"></path></svg>
                <?= $showHidden ? 'Hide' : 'Show' ?> Hidden
            </a>

            <button class="btn btn-sm hide-mobile" onclick="document.getElementById('modal-users').classList.add('active')">
                <svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z"></path></svg>
                Admin Panel
            </button>
        <?php endif; ?>

        <div class="storage-container hide-mobile">
            <div class="quota-text"><?= formatBytes($usedStorage) ?> / <?= formatBytes(MAX_STORAGE_BYTES) ?> Used</div>
            <div class="progress-bar"><div class="progress-fill" style="width: <?= $storagePercentage ?>%"></div></div>
        </div>
        <form method="post" style="margin:0;">
            <input type="hidden" name="logout_action" value="1">
            <input type="hidden" name="csrf" value="<?= h($csrfToken) ?>">
            <button class="btn btn-danger" style="padding: 8px 12px;">Logout</button>
        </form>
    </div>
</nav>

<main class="main">
    <?php if (isset($errorMsg)): ?>
        <div style="background: rgba(239, 68, 68, 0.1); color: #fca5a5; padding: 12px 16px; border-radius: 8px; border: 1px solid #b91c1c; margin-bottom: 20px;">
            <?= h($errorMsg) ?>
        </div>
    <?php endif; ?>

    <?php if ($previewFile !== null): ?>
        <!-- ======================= PREVIEW UI ======================= -->
        <?php
        $previewName = basename($previewFile);
        $previewExt = strtolower(pathinfo($previewFile, PATHINFO_EXTENSION));
        $streamUrl = urlWith(['file' => $previewRelative, 'action' => 'stream']);
        $downloadUrl = urlWith(['file' => $previewRelative, 'action' => 'download']);
        ?>
        <div class="preview-container">
            <div class="ptop">
                <div>
                    <div class="pmeta">Preview Viewer</div>
                    <h1><?= h($previewName) ?></h1>
                </div>
                <div style="display: flex; gap: 8px; flex-wrap: wrap;">
                    <a href="?dir=<?= urlencode($currentDir) ?>" class="btn btn-sm">
                        <svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 19l-7-7m0 0l7-7m-7 7h18"></path></svg> 
                        Back
                    </a>
                    
                    <?php if (in_array($previewExt, $videoExts, true)): ?>
                        <label for="localSubInput" class="btn btn-sm" style="cursor: pointer;">
                            <svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 8h10M7 12h4m1 8l-4-4H5a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v8a2 2 0 01-2 2h-3l-4 4z"></path></svg>
                            Load Subtitles
                        </label>
                        <input type="file" id="localSubInput" accept=".srt,.vtt" style="display: none;">
                    <?php endif; ?>
                    
                    <a href="<?= h($downloadUrl) ?>" class="btn btn-sm btn-danger" style="color: white;">
                        <svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"></path></svg>
                        Download
                    </a>
                </div>
            </div>
            
            <div class="media">
                <?php if (in_array($previewExt, ['mkv', 'avi', 'ts'])): ?>
                    <div style="background: rgba(239, 68, 68, 0.1); color: #fca5a5; padding: 12px; border-radius: 8px; border: 1px solid #b91c1c; margin-bottom: 16px; font-size: 13px; width: 100%;">
                        ⚠️ <b>Codec Warning:</b> You are previewing an MKV/AVI file. Most web browsers cannot natively play these containers or x265/HEVC codecs. If the player gets stuck loading, please use the Download button.
                    </div>
                <?php endif; ?>

                <?php if (in_array($previewExt, $videoExts, true)): ?>
                    <div class="videoshell" id="videoShell">
                        <div id="artplayer-app" class="artplayer-app"></div>
                    </div>
                    <?php if (count($tracks) > 0): ?><div class="captionnote">Subtitles found. Use the gear icon or press <b>G</b> / <b>H</b> to sync delay.</div><?php endif; ?>
                
                <?php elseif (in_array($previewExt, $audioExts, true)): ?>
                    <audio controls preload="metadata" style="width: 100%; max-width: 600px; margin-top: 20px;"><source src="<?= h($streamUrl) ?>" type="<?= h(mimeFor($previewFile)) ?>"></audio>
                
                <?php elseif (in_array($previewExt, $imageExts, true)): ?>
                    <img class="img-preview" src="<?= h($streamUrl) ?>" alt="<?= h($previewName) ?>">
                
                <?php elseif ($previewExt === 'pdf'): ?>
                    <iframe src="<?= h($streamUrl) ?>" style="width: 100%; height: 75vh; border: none; border-radius: 8px; background: white;"></iframe>
                
                <?php elseif (in_array($previewExt, ['zip', 'rar', '7z'])): ?>
                    <?php 
                    if (class_exists('ZipArchive') && $previewExt === 'zip') {
                        $zip = new ZipArchive();
                        if ($zip->open($previewFile) === TRUE) {
                            echo '<table class="zip-table"><thead><tr><th>File Path</th><th>Original Size</th><th>Compressed</th></tr></thead><tbody>';
                            for ($i = 0; $i < $zip->numFiles; $i++) {
                                $stat = $zip->statIndex($i);
                                if ($stat['size'] == 0 && str_ends_with($stat['name'], '/')) continue;
                                echo '<tr><td>' . h($stat['name']) . '</td><td>' . formatBytes($stat['size']) . '</td><td>' . formatBytes($stat['comp_size']) . '</td></tr>';
                            }
                            echo '</tbody></table>';
                            $zip->close();
                        } else {
                            echo '<div class="empty-preview">Failed to read ZIP archive.</div>';
                        }
                    } else {
                        echo '<div class="empty-preview">ZIP preview currently only supports .zip extension. Please download to extract.</div>';
                    }
                    ?>

                <?php elseif (in_array($previewExt, $textExts, true) || (reservedName($previewName) && $previewExt === 'json')): ?>
                    <?php $text = file_get_contents($previewFile, false, null, 0, 2 * 1024 * 1024); if ($text === false) $text = 'Unable to read text file.'; ?>
                    <pre class="text-preview"><?= h($text) ?></pre>
                
                <?php else: ?>
                    <div class="empty-preview">
                        No inline preview available for this file type.<br>Please download to view.
                    </div>
                <?php endif; ?>
            </div>
        </div>

    <?php else: ?>
        <!-- ======================= STANDARD FILE MANAGER UI ======================= -->
        <div class="toolbar">
            <div class="breadcrumbs">
                <a href="?dir=">
                    <svg width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24" style="vertical-align: sub;"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6"></path></svg>
                </a>
                <?php 
                $buildPath = '';
                foreach ($breadcrumbs as $crumb) {
                    if ($crumb === '') continue;
                    $buildPath .= ($buildPath === '' ? '' : '/') . $crumb;
                    echo ' <span>/</span> <a href="?dir=' . urlencode($buildPath) . '">' . h($crumb) . '</a>';
                }
                ?>
            </div>
            <div style="display: flex; gap: 12px; flex-wrap: wrap;">
                <button class="btn btn-sm" onclick="document.getElementById('modal-newfile').classList.add('active')">
                    <svg width="18" height="18" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 13h6m-3-3v6m-9 1V7a2 2 0 012-2h4l2 2h4a2 2 0 012 2v10a2 2 0 01-2 2H5a2 2 0 01-2-2z"></path></svg>
                    New File
                </button>
                <button class="btn btn-sm" onclick="document.getElementById('modal-folder').classList.add('active')">
                    <svg width="18" height="18" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 13h6m-3-3v6m-9 1V7a2 2 0 012-2h4l2 2h4a2 2 0 012 2v10a2 2 0 01-2 2H5a2 2 0 01-2-2z"></path></svg>
                    New Folder
                </button>
                <button class="btn" onclick="document.getElementById('modal-upload').classList.add('active')">
                    <svg width="18" height="18" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12"></path></svg>
                    Upload
                </button>
            </div>
        </div>

        <div id="selection-toolbar">
            <div style="font-weight: 600;"><span id="sel-count" style="color: var(--accent);">0</span> item(s) selected <span style="color: var(--muted); font-weight: normal; font-size: 13px; margin-left: 8px;">(Drag rows to move them)</span></div>
            <div style="display: flex; gap: 8px;">
                <form method="post" id="bulkZipForm" style="margin: 0;">
                    <input type="hidden" name="csrf" value="<?= h($csrfToken) ?>">
                    <input type="hidden" name="bulk_action" value="zip">
                    <button type="button" class="btn btn-sm" onclick="submitBulkZip()">Download ZIP</button>
                </form>
                <form method="post" id="bulkDeleteForm" onsubmit="return confirm('Delete selected items completely?');" style="margin: 0;">
                    <input type="hidden" name="csrf" value="<?= h($csrfToken) ?>">
                    <button type="button" class="btn btn-sm btn-danger" onclick="submitBulkDelete()">Delete Selected</button>
                </form>
            </div>
        </div>

        <div class="table-container">
            <table id="fileTable">
                <thead>
                    <tr>
                        <th style="width: 40px; text-align: center; padding-right: 0;">
                            <label class="checkbox-container">
                                <input type="checkbox" id="selectAll" title="Select All">
                                <span class="checkmark"></span>
                            </label>
                        </th>
                        <th onclick="sortTable('name', 'string', this)">Name <span class="sort-icon"></span></th>
                        <th class="hide-mobile" onclick="sortTable('size', 'number', this)">Size <span class="sort-icon"></span></th>
                        <th class="hide-mobile" onclick="sortTable('owner', 'string', this)">Owner <span class="sort-icon"></span></th>
                        <th class="hide-mobile" onclick="sortTable('time', 'number', this)">Modified <span class="sort-icon"></span></th>
                        <th style="text-align: right; cursor: default;">Actions</th>
                    </tr>
                </thead>
                <tbody>
                    <?php if ($currentDir !== ''): ?>
                    <?php $parentRel = dirname($currentDir) === '.' ? '' : dirname($currentDir); ?>
                    <tr class="ignore-search" ondragover="dragOverMove(event)" ondrop="dropMove(event, '<?= h(addslashes($parentRel)) ?>')" ondragenter="dragEnterMove(event)" ondragleave="dragLeaveMove(event)">
                        <td></td>
                        <td colspan="5">
                            <a href="?dir=<?= urlencode($parentRel) ?>" class="item-name">
                                <div class="icon-wrapper"><?= getIconSvg(true, '') ?></div>
                                <span style="font-weight: 600;">.. (Go Up)</span> <span style="color: var(--muted); font-size: 12px; margin-left: 10px;">Drop files here to move up</span>
                            </a>
                        </td>
                    </tr>
                    <?php endif; ?>
                    
                    <?php foreach (array_merge($folders, $files) as $item): ?>
                    <tr class="file-row" 
                        draggable="true" 
                        data-name="<?= h(strtolower($item['name'])) ?>"
                        data-size="<?= $item['size'] ?>"
                        data-owner="<?= h(strtolower($item['owner'])) ?>"
                        data-time="<?= $item['mtime'] ?>"
                        data-isdir="<?= $item['is_dir'] ? 1 : 0 ?>"
                        <?= $item['is_dir'] ? 'ondragover="dragOverMove(event)" ondrop="dropMove(event, \''.h(addslashes($item['path'])).'\')" ondragenter="dragEnterMove(event)" ondragleave="dragLeaveMove(event)"' : '' ?>
                        ondragstart="dragStart(event, '<?= h(addslashes($item['path'])) ?>')"
                    >
                        <td style="text-align: center; padding-right: 0;">
                            <?php if (!$item['is_reserved']): ?>
                                <label class="checkbox-container">
                                    <input type="checkbox" class="item-checkbox" value="<?= h($item['path']) ?>" onclick="updateSelection(event)">
                                    <span class="checkmark"></span>
                                </label>
                            <?php endif; ?>
                        </td>

                        <td>
                            <?php if ($item['is_dir']): ?>
                                <a href="?dir=<?= urlencode($item['path']) ?>" class="item-name folder-name">
                                    <div class="icon-wrapper"><?= getIconSvg(true, '') ?></div>
                                    <span class="item-text"><?= h($item['name']) ?></span>
                                </a>
                            <?php else: ?>
                                <?php 
                                $previewable = in_array($item['ext'], array_merge($videoExts, $audioExts, $imageExts, $textExts, ['pdf', 'zip']), true) || $item['is_reserved_viewable'];
                                $viewUrl = $previewable && (!$item['is_reserved'] || $item['is_reserved_viewable']) ? "?dir=" . urlencode($currentDir) . "&preview=" . urlencode($item['path']) : "?file=" . urlencode($item['path']) . "&action=download";
                                $hasThumb = in_array($item['ext'], array_merge($imageExts, $videoExts));
                                ?>
                                <a href="<?= h($viewUrl) ?>" class="item-name file-name">
                                    <?php if ($hasThumb): ?>
                                        <img src="?thumb=<?= urlencode($item['path']) ?>" class="file-thumb grid-only" onerror="this.style.display='none'; this.nextElementSibling.style.display='block';" loading="lazy" alt="<?= h($item['name']) ?>">
                                        <div class="icon-wrapper grid-only thumb-fallback" style="display: none;"><?= getIconSvg(false, $item['ext']) ?></div>
                                        <div class="icon-wrapper list-only"><?= getIconSvg(false, $item['ext']) ?></div>
                                    <?php else: ?>
                                        <div class="icon-wrapper"><?= getIconSvg(false, $item['ext']) ?></div>
                                    <?php endif; ?>
                                    <span class="item-text"><?= h($item['name']) ?></span>
                                </a>
                            <?php endif; ?>
                        </td>
                        <td class="hide-mobile" style="color: var(--muted)"><?= formatBytes($item['size']) ?></td>
                        <td class="hide-mobile" style="color: var(--accent); font-weight: 500; font-size: 13px;"><?= h($item['owner']) ?></td>
                        <td class="hide-mobile" style="color: var(--muted)"><?= date('M j, Y H:i', $item['mtime']) ?></td>
                        <td>
                            <div class="actions-cell">
                            <?php if ($item['is_reserved']): ?>
                                <?php if ($item['is_reserved_viewable']): ?>
                                    <a href="?dir=<?= urlencode($currentDir) ?>&preview=<?= urlencode($item['path']) ?>" class="btn-icon" title="Preview JSON">
                                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>
                                    </a>
                                <?php endif; ?>
                                <span style="color: var(--muted); font-size: 12px; font-weight: 600; padding: 6px; margin-left: 8px;">System Locked</span>
                            <?php else: ?>
                                <?php if (!$item['is_dir']): ?>
                                    <button class="btn-icon" title="Share Link" onclick="generateShareLink('<?= h(addslashes($item['path'])) ?>')">
                                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"></path><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"></path></svg>
                                    </button>

                                    <?php if ($previewable): ?>
                                    <a href="?dir=<?= urlencode($currentDir) ?>&preview=<?= urlencode($item['path']) ?>" class="btn-icon" title="Preview">
                                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>
                                    </a>
                                    <?php endif; ?>
                                    
                                    <a href="?file=<?= urlencode($item['path']) ?>&action=download" class="btn-icon" title="Download">
                                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg>
                                    </a>
                                    
                                    <?php if (in_array($item['ext'], $textExts)): ?>
                                        <a href="?dir=<?= urlencode($currentDir) ?>&edit=<?= urlencode($item['path']) ?>" class="btn-icon" title="Edit Code">
                                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"></path><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"></path></svg>
                                        </a>
                                    <?php endif; ?>
                                    
                                    <?php if (in_array($item['ext'], ['zip', 'rar', '7z']) && class_exists('ZipArchive')): ?>
                                        <form method="post"><input type="hidden" name="csrf" value="<?= h($csrfToken) ?>"><input type="hidden" name="extract_zip" value="<?= h($item['path']) ?>">
                                            <button class="btn-icon" title="Extract Here"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="21 8 21 21 3 21 3 8"></polyline><rect x="1" y="3" width="22" height="5"></rect><line x1="10" y1="12" x2="14" y2="12"></line></svg></button>
                                        </form>
                                    <?php endif; ?>
                                <?php endif; ?>
                                
                                <button class="btn-icon" title="Rename" onclick="openRename('<?= h(addslashes($item['path'])) ?>', '<?= h(addslashes($item['name'])) ?>')">
                                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20.59 13.41l-7.17 7.17a2 2 0 0 1-2.83 0L2 12V2h10l8.59 8.59a2 2 0 0 1 0 2.82z"></path><line x1="7" y1="7" x2="7.01" y2="7"></line></svg>
                                </button>
                                
                                <form method="post" class="del-form" onsubmit="return confirm('Are you sure you want to delete \'<?= h(addslashes($item['name'])) ?>\'?');">
                                    <input type="hidden" name="csrf" value="<?= h($csrfToken) ?>">
                                    <input type="hidden" name="delete_item[]" value="<?= h($item['path']) ?>">
                                    <button class="btn-icon btn-icon-danger" title="Delete">
                                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path><line x1="10" y1="11" x2="10" y2="17"></line><line x1="14" y1="11" x2="14" y2="17"></line></svg>
                                    </button>
                                </form>
                            <?php endif; ?>
                            </div>
                        </td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    <?php endif; ?>
</main>

<div id="modal-shares" class="modal">
    <div class="modal-content large">
        <h2>Active Shared Links <button class="btn-sm" onclick="closeModal(this)" style="border:none;">✕</button></h2>
        <div style="overflow-x: auto;">
            <table style="margin-bottom: 20px; width: 100%;">
                <thead>
                    <tr>
                        <th>File</th>
                        <th>Created By</th>
                        <th>Hits</th>
                        <th>Last Access</th>
                        <th style="text-align: right;">Action</th>
                    </tr>
                </thead>
                <tbody>
                    <?php 
                    $sharesFile = $base . '/' . SHARES_FILE;
                    $shares = file_exists($sharesFile) ? json_decode(file_get_contents($sharesFile), true) : [];
                    $hasShares = false;
                    foreach ($shares as $token => $data): 
                        if (!$isAdmin && ($data['created_by'] ?? '') !== $currentUser) continue;
                        $hasShares = true;
                    ?>
                    <tr>
                        <td style="max-width: 150px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
                            <strong><a href="?share=<?= h($token) ?>" target="_blank" style="color: var(--accent); text-decoration: none;" title="<?= h(basename($data['path'])) ?>"><?= h(basename($data['path'])) ?></a></strong>
                        </td>
                        <td><?= h($data['created_by']) ?></td>
                        <td style="color: var(--accent); font-weight: 600;"><?= (int)($data['access_count'] ?? 0) ?></td>
                        <td style="color: var(--muted);"><?= !empty($data['last_accessed']) ? date('M j, H:i', $data['last_accessed']) : 'Never' ?></td>
                        <td style="text-align: right;">
                            <form method="post" style="display:inline;" onsubmit="return confirm('Revoke this share link?');">
                                <input type="hidden" name="csrf" value="<?= h($csrfToken) ?>">
                                <input type="hidden" name="revoke_share" value="<?= h($token) ?>">
                                <button class="btn-sm btn-danger" style="color:#fca5a5; padding: 4px 8px;">Revoke</button>
                            </form>
                        </td>
                    </tr>
                    <?php endforeach; ?>
                    <?php if (!$hasShares): ?>
                        <tr><td colspan="5" style="text-align: center; color: var(--muted); padding: 20px;">No active share links.</td></tr>
                    <?php endif; ?>
                </tbody>
            </table>
        </div>
    </div>
</div>

<?php if ($isAdmin): ?>
    <?php
    $tempUploadsSize = 0;
    $uploadRoot = $base . '/' . SYSTEM_UPLOAD_DIR;
    if (is_dir($uploadRoot)) $tempUploadsSize += getDirectorySize($uploadRoot);
    
    $thumbRoot = $base . '/.netvault_thumbs';
    if (is_dir($thumbRoot)) $tempUploadsSize += getDirectorySize($thumbRoot);
    
    $sysTemp = sys_get_temp_dir();
    $zipFiles = glob($sysTemp . '/*.zip');
    if ($zipFiles) {
        foreach ($zipFiles as $zf) {
            $tempUploadsSize += filesize($zf);
        }
    }
    ?>
<div id="modal-users" class="modal">
    <div class="modal-content large">
        <h2>Admin Panel <button class="btn-sm" onclick="closeModal(this)" style="border:none;">✕</button></h2>
        <div class="captionnote" style="text-align: left; margin-bottom: 20px;">
            * Passwords are mathematically encrypted using <code>bcrypt</code> and cannot be viewed, only reset.
        </div>
        <table style="margin-bottom: 20px;">
            <thead><tr><th>Username</th><th>Role</th><th style="text-align: right">Actions</th></tr></thead>
            <tbody>
                <?php foreach ($sysUsers as $u => $data): ?>
                <tr>
                    <td style="font-weight: 600;"><?= h($u) ?></td>
                    <td style="color: <?= $data['role'] === 'admin' ? 'var(--accent)' : 'var(--muted)' ?>"><?= ucfirst(h($data['role'])) ?></td>
                    <td style="text-align: right">
                        <div style="display:flex; justify-content:flex-end; gap:6px;">
                            <button class="btn-sm" onclick="resetPassword('<?= h(addslashes($u)) ?>')">Reset Pass</button>
                            
                            <?php if ($u !== 'admin'): ?>
                                <form method="post" style="margin:0;">
                                    <input type="hidden" name="csrf" value="<?= h($csrfToken) ?>">
                                    <input type="hidden" name="manage_user_action" value="toggle_admin">
                                    <input type="hidden" name="target_user" value="<?= h($u) ?>">
                                    <button class="btn-sm"><?= $data['role'] === 'admin' ? 'Revoke Admin' : 'Make Admin' ?></button>
                                </form>
                                <form method="post" onsubmit="return confirm('Delete this user permanently?');" style="margin:0;">
                                    <input type="hidden" name="csrf" value="<?= h($csrfToken) ?>">
                                    <input type="hidden" name="manage_user_action" value="delete">
                                    <input type="hidden" name="target_user" value="<?= h($u) ?>">
                                    <button class="btn-sm" style="color: #fca5a5; border-color: rgba(239, 68, 68, 0.3);">Remove</button>
                                </form>
                            <?php endif; ?>
                        </div>
                    </td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
        
        <hr style="border-color: var(--border); margin: 24px 0;">
        <h3 style="font-size: 16px; margin-bottom: 12px; margin-top: 0;">System Maintenance</h3>
        <div style="display: flex; justify-content: space-between; align-items: center; background: var(--bg); padding: 12px 16px; border-radius: 8px; border: 1px solid var(--border);">
            <div>
                <div style="font-weight: 600; font-size: 14px; color: var(--text);">Clear Temporary Files</div>
                <div style="font-size: 12px; color: var(--muted); margin-top: 4px;">Wasted space: <strong style="color: var(--accent);"><?= formatBytes($tempUploadsSize) ?></strong></div>
            </div>
            <form method="post" onsubmit="return confirm('Delete all pending uploads, thumbnail caches, and temporary ZIPs?');" style="margin:0;">
                <input type="hidden" name="csrf" value="<?= h($csrfToken) ?>">
                <input type="hidden" name="manage_system_action" value="clear_temp">
                <button class="btn btn-sm btn-danger" style="color: white;" <?= $tempUploadsSize === 0 ? 'disabled' : '' ?>>Clean Up</button>
            </form>
        </div>
        
        <form id="manageForm" method="post" style="display:none;">
            <input type="hidden" name="csrf" value="<?= h($csrfToken) ?>">
            <input type="hidden" name="manage_user_action" id="m_action">
            <input type="hidden" name="target_user" id="m_user">
            <input type="hidden" name="new_pass" id="m_val">
        </form>
    </div>
</div>
<?php endif; ?>

<div id="modal-folder" class="modal">
    <div class="modal-content">
        <h2>Create New Folder</h2>
        <form method="post">
            <input type="hidden" name="csrf" value="<?= h($csrfToken) ?>">
            <input type="text" name="new_folder" placeholder="Folder Name e.g. 'Projects'" required autofocus>
            <div style="display:flex;gap:12px;">
                <button type="submit" class="btn" style="flex: 1; justify-content: center;">Create</button>
                <button type="button" class="btn btn-danger" onclick="closeModal(this)" style="flex: 1; justify-content: center;">Cancel</button>
            </div>
        </form>
    </div>
</div>

<div id="modal-newfile" class="modal">
    <div class="modal-content">
        <h2>Create New Text File</h2>
        <form method="post">
            <input type="hidden" name="csrf" value="<?= h($csrfToken) ?>">
            <input type="text" name="new_file" placeholder="File Name e.g. 'script.php'" required autofocus>
            <div style="display:flex;gap:12px;">
                <button type="submit" class="btn" style="flex: 1; justify-content: center;">Create & Edit</button>
                <button type="button" class="btn btn-danger" onclick="closeModal(this)" style="flex: 1; justify-content: center;">Cancel</button>
            </div>
        </form>
    </div>
</div>

<div id="modal-upload" class="modal">
    <div class="modal-content">
        <h2>Upload Files</h2>
        <div>
            <input type="file" id="fileInput" multiple style="margin-bottom: 10px;">
            <div style="display:flex;gap:12px;">
                <button class="btn" id="uploadButton" type="button" style="flex: 1; justify-content: center;">Start Upload</button>
                <button type="button" class="btn btn-danger" onclick="closeModal(this)" style="flex: 1; justify-content: center;">Close</button>
            </div>
        </div>
        <div class="uploads" id="uploadList"></div>
    </div>
</div>

<div id="modal-rename" class="modal">
    <div class="modal-content">
        <h2>Rename Item</h2>
        <form method="post">
            <input type="hidden" name="csrf" value="<?= h($csrfToken) ?>">
            <input type="hidden" name="rename_target" id="rename_target">
            <input type="text" name="rename_new" id="rename_new" required>
            <div style="display:flex;gap:12px;">
                <button type="submit" class="btn" style="flex: 1; justify-content: center;">Save</button>
                <button type="button" class="btn btn-danger" onclick="closeModal(this)" style="flex: 1; justify-content: center;">Cancel</button>
            </div>
        </form>
    </div>
</div>

<?php if (isset($_GET['edit'])): 
    $editPath = resolveExisting($base, $_GET['edit']);
    if ($editPath && is_file($editPath)):
        $content = file_get_contents($editPath);
        $editExt = strtolower(pathinfo($editPath, PATHINFO_EXTENSION));
        $mode = 'text/plain';
        if ($editExt === 'js' || $editExt === 'json') $mode = 'javascript';
        if ($editExt === 'css') $mode = 'css';
        if ($editExt === 'php') $mode = 'application/x-httpd-php';
        if ($editExt === 'html') $mode = 'htmlmixed';
        if ($editExt === 'py') $mode = 'python';
        if ($editExt === 'xml') $mode = 'xml';
        if ($editExt === 'c' || $editExt === 'cpp' || $editExt === 'java') $mode = 'clike';
?>
<div id="modal-edit" class="modal active">
    <div class="modal-content large">
        <h2>Editing: <?= h(basename($editPath)) ?></h2>
        <form method="post">
            <input type="hidden" name="csrf" value="<?= h($csrfToken) ?>">
            <input type="hidden" name="save_file" value="<?= h($_GET['edit']) ?>">
            <textarea id="file_content_ta" name="file_content" spellcheck="false"><?= h($content) ?></textarea>
            <div style="display:flex;gap:12px; margin-top: 20px;">
                <button type="submit" class="btn" style="width: auto;">Save Changes</button>
                <a href="?dir=<?= urlencode($currentDir) ?>" class="btn btn-danger" style="text-decoration:none;">Discard & Close</a>
            </div>
        </form>
    </div>
</div>
<script>
    if (typeof CodeMirror !== 'undefined') {
        var editor = CodeMirror.fromTextArea(document.getElementById("file_content_ta"), {
            lineNumbers: true,
            theme: "dracula",
            mode: "<?= $mode ?>",
            indentUnit: 4,
            matchBrackets: true,
            viewportMargin: Infinity
        });
    }
</script>
<?php endif; endif; ?>

<script>
(() => {
    // Grid vs List View Toggling
    const toggleBtn = document.getElementById('viewToggleBtn');
    const tableContainer = document.querySelector('.table-container');
    
    function setView(view) {
        if (!tableContainer) return; // Fix: Only run if file table exists
        if (view === 'grid') {
            tableContainer.classList.add('grid-view');
            localStorage.setItem('netvault_view', 'grid');
            if (toggleBtn) {
                toggleBtn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="8" y1="6" x2="21" y2="6"></line><line x1="8" y1="12" x2="21" y2="12"></line><line x1="8" y1="18" x2="21" y2="18"></line><line x1="3" y1="6" x2="3.01" y2="6"></line><line x1="3" y1="12" x2="3.01" y2="12"></line><line x1="3" y1="18" x2="3.01" y2="18"></line></svg>';
                toggleBtn.title = "Switch to List View";
            }
        } else {
            tableContainer.classList.remove('grid-view');
            localStorage.setItem('netvault_view', 'list');
            if (toggleBtn) {
                toggleBtn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7"></rect><rect x="14" y="3" width="7" height="7"></rect><rect x="14" y="14" width="7" height="7"></rect><rect x="3" y="14" width="7" height="7"></rect></svg>';
                toggleBtn.title = "Switch to Grid View";
            }
        }
    }
    if (toggleBtn && tableContainer) {
        toggleBtn.addEventListener('click', () => {
            if (tableContainer.classList.contains('grid-view')) setView('list');
            else setView('grid');
        });
    }
    if (tableContainer) {
        setView(localStorage.getItem('netvault_view') || 'list');
    }

    // Keyboard Navigation
    let focusedIndex = -1;
    function getVisibleRows() {
        return Array.from(document.querySelectorAll('.file-row')).filter(row => row.style.display !== 'none');
    }
    function updateFocus() {
        document.querySelectorAll('.file-row').forEach(row => row.classList.remove('focused'));
        const rows = getVisibleRows();
        if (focusedIndex >= 0 && focusedIndex < rows.length) {
            const row = rows[focusedIndex];
            row.classList.add('focused');
            row.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
        }
    }
    document.addEventListener('keydown', (e) => {
        if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA' || document.querySelector('.modal.active')) return;
        
        const rows = getVisibleRows();
        if (rows.length === 0) return;
        
        if (e.key === 'ArrowDown' || e.key === 'ArrowRight') {
            e.preventDefault();
            focusedIndex = Math.min(focusedIndex + 1, rows.length - 1);
            updateFocus();
        } else if (e.key === 'ArrowUp' || e.key === 'ArrowLeft') {
            e.preventDefault();
            focusedIndex = Math.max(focusedIndex - 1, 0);
            updateFocus();
        } else if (e.key === 'Enter') {
            if (focusedIndex >= 0) {
                e.preventDefault();
                const link = rows[focusedIndex].querySelector('.item-name');
                if (link) link.click();
            }
        } else if (e.key === 'Delete') {
            if (focusedIndex >= 0) {
                e.preventDefault();
                const delForm = rows[focusedIndex].querySelector('.del-form');
                if (delForm) delForm.querySelector('.btn-icon-danger').click();
            }
        }
    });

    // Share Link Generator
    window.generateShareLink = async function(path) {
        try {
            let data = new FormData();
            data.append('ajax_action', 'create_share');
            data.append('csrf', '<?= h($csrfToken) ?>');
            data.append('share_target', path);
            
            let res = await fetch(window.location.pathname + window.location.search, { method: 'POST', body: data });
            let json = await res.json();
            
            if (json.ok) {
                if (navigator.clipboard && window.isSecureContext) {
                    navigator.clipboard.writeText(json.link);
                }
                prompt("Shareable Link Generated! (Copied to clipboard)", json.link);
            } else {
                alert("Failed to generate link: " + json.message);
            }
        } catch (e) {
            alert("Error connecting to server.");
        }
    }

    // Dynamic Sorting
    let currentSort = { key: 'name', dir: 1 };
    window.sortTable = function(key, type, headerEl) {
        if (currentSort.key === key) {
            currentSort.dir *= -1;
        } else {
            currentSort.key = key;
            currentSort.dir = 1; 
        }
        
        document.querySelectorAll('.sort-icon').forEach(el => el.innerHTML = '');
        headerEl.querySelector('.sort-icon').innerHTML = currentSort.dir === 1 ? '↑' : '↓';
        
        const tbody = document.querySelector('#fileTable tbody');
        if (!tbody) return;
        const rows = Array.from(tbody.querySelectorAll('.file-row'));
        
        rows.sort((a, b) => {
            let isDirA = parseInt(a.dataset.isdir);
            let isDirB = parseInt(b.dataset.isdir);
            if (isDirA !== isDirB) return isDirB - isDirA;
            
            let valA = a.dataset[key];
            let valB = b.dataset[key];
            
            if (type === 'number') return currentSort.dir * (parseFloat(valA) - parseFloat(valB));
            else return currentSort.dir * valA.localeCompare(valB);
        });
        
        rows.forEach(row => tbody.appendChild(row));
    };

    // Selection Toolbar
    const selectAllCb = document.getElementById('selectAll');
    const itemCbs = document.querySelectorAll('.item-checkbox');
    const selToolbar = document.getElementById('selection-toolbar');
    const selCount = document.getElementById('sel-count');

    if (selectAllCb) {
        selectAllCb.addEventListener('change', (e) => {
            itemCbs.forEach(cb => {
                if (cb.closest('tr').style.display !== 'none') {
                    cb.checked = e.target.checked;
                }
            });
            window.updateSelection();
        });
    }

    window.updateSelection = function(e) {
        if (e) e.stopPropagation();
        const checked = document.querySelectorAll('.item-checkbox:checked');
        if (selToolbar) {
            if (checked.length > 0) {
                selToolbar.style.display = 'flex';
                if (selCount) selCount.textContent = checked.length;
            } else {
                selToolbar.style.display = 'none';
            }
        }
        if (selectAllCb) selectAllCb.checked = (checked.length === itemCbs.length && itemCbs.length > 0);
    }

    window.submitBulkDelete = function() {
        const checked = document.querySelectorAll('.item-checkbox:checked');
        if (checked.length === 0) return;
        
        const form = document.getElementById('bulkDeleteForm');
        form.querySelectorAll('.dyn-input').forEach(el => el.remove());
        
        checked.forEach(cb => {
            const input = document.createElement('input');
            input.type = 'hidden'; input.name = 'delete_item[]'; input.value = cb.value; input.className = 'dyn-input';
            form.appendChild(input);
        });
        form.submit();
    }
    
    window.submitBulkZip = async function() {
        const checked = document.querySelectorAll('.item-checkbox:checked');
        if (checked.length === 0) return;
        
        const overlay = document.getElementById('zipOverlay');
        overlay.classList.add('active');
        
        let formData = new FormData();
        formData.append('ajax_action', 'build_zip');
        formData.append('csrf', '<?= h($csrfToken) ?>');
        checked.forEach(cb => formData.append('items[]', cb.value));

        try {
            let res = await fetch(window.location.pathname + window.location.search, { method: 'POST', body: formData });
            let json = await res.json();
            if (json.ok) {
                window.location.href = "?download_zip=" + json.zip_id;
                checked.forEach(cb => cb.checked = false);
                window.updateSelection();
            } else {
                alert("ZIP failed: " + json.message);
            }
        } catch(e) {
            alert("Network error while building ZIP.");
        } finally {
            overlay.classList.remove('active');
        }
    }

    const searchInput = document.getElementById('searchInput');
    if (searchInput) {
        searchInput.addEventListener('keyup', function() {
            let filter = this.value.toLowerCase();
            let rows = document.querySelectorAll('.file-row');
            rows.forEach(row => {
                let nameElement = row.querySelector('.item-name');
                if (nameElement) {
                    let text = nameElement.textContent.toLowerCase();
                    row.style.display = text.includes(filter) ? '' : 'none';
                }
            });
            window.updateSelection();
            focusedIndex = -1;
            updateFocus();
        });
    }

    window.openRename = function(path, currentName) {
        document.getElementById('rename_target').value = path;
        document.getElementById('rename_new').value = currentName;
        document.getElementById('modal-rename').classList.add('active');
    }
    window.closeModal = function(btn) { btn.closest('.modal').classList.remove('active'); }
    window.onclick = function(event) { if (event.target.classList.contains('modal')) event.target.classList.remove('active'); }

    window.resetPassword = function(username) {
        let newPass = prompt("Enter a new password for user: " + username);
        if (newPass && newPass.length >= 6) {
            document.getElementById('m_action').value = 'reset_pass';
            document.getElementById('m_user').value = username;
            document.getElementById('m_val').value = newPass;
            document.getElementById('manageForm').submit();
        } else if (newPass) {
            alert("Password must be at least 6 characters.");
        }
    }

    // Internal Drag and Drop
    let dragSourcePaths = [];
    window.dragStart = function(e, path) {
        let selectedCbs = document.querySelectorAll('.item-checkbox:checked');
        let paths = Array.from(selectedCbs).map(cb => cb.value);
        if (!paths.includes(path)) paths = [path];
        dragSourcePaths = paths;
        e.dataTransfer.setData('application/json', JSON.stringify(paths));
        e.dataTransfer.effectAllowed = 'move';
        
        if (paths.length > 1) {
            let badge = document.createElement('div');
            badge.textContent = `Moving ${paths.length} items`;
            badge.style.position = 'absolute'; badge.style.top = '-1000px'; badge.style.background = '#10b981';
            badge.style.color = '#fff'; badge.style.padding = '4px 10px'; badge.style.borderRadius = '6px'; badge.style.fontWeight = 'bold';
            document.body.appendChild(badge);
            e.dataTransfer.setDragImage(badge, 0, 0);
            setTimeout(() => document.body.removeChild(badge), 0);
        }
    };
    window.dragOverMove = function(e) {
        if (dragSourcePaths.length > 0) {
            e.preventDefault();
            e.dataTransfer.dropEffect = 'move';
        }
    };
    window.dragEnterMove = function(e) {
        if (dragSourcePaths.length > 0) e.currentTarget.style.backgroundColor = 'rgba(16, 185, 129, 0.2)';
    };
    window.dragLeaveMove = function(e) {
        if (dragSourcePaths.length > 0) e.currentTarget.style.backgroundColor = '';
    };
    window.dropMove = function(e, destPath) {
        if (dragSourcePaths.length === 0) return;
        e.preventDefault(); e.stopPropagation();
        e.currentTarget.style.backgroundColor = '';
        
        let paths = dragSourcePaths;
        dragSourcePaths = [];
        
        paths = paths.filter(p => p !== destPath && !destPath.startsWith(p + '/'));
        if (paths.length === 0) return; 
        
        const form = document.createElement('form');
        form.method = 'POST';
        form.innerHTML = `<input type="hidden" name="csrf" value="${CSRF_TOKEN}"><input type="hidden" name="move_dest" value="${destPath}">`;
        paths.forEach(p => { form.innerHTML += `<input type="hidden" name="move_items[]" value="${p}">`; });
        document.body.appendChild(form);
        form.submit();
    };
    document.addEventListener('dragstart', () => { window.isInternalDrag = true; });
    document.addEventListener('dragend', () => { window.isInternalDrag = false; dragSourcePaths = []; });

    // Desktop Upload Drag and Drop
    const dropOverlay = document.getElementById('dropOverlay');
    window.addEventListener('dragover', (e) => {
        if (window.isInternalDrag) return;
        if (e.dataTransfer.types.includes('Files')) {
            e.preventDefault();
            dropOverlay.classList.add('active');
        }
    });
    dropOverlay.addEventListener('dragleave', (e) => {
        e.preventDefault();
        dropOverlay.classList.remove('active');
    });
    dropOverlay.addEventListener('drop', async (e) => {
        e.preventDefault();
        dropOverlay.classList.remove('active');
        if (window.isInternalDrag) return;
        
        const files = await getFilesFromDataTransfer(e.dataTransfer);
        if (files.length > 0) startUploads(files);
    });

    async function getFilesFromDataTransfer(dataTransfer) {
        const files = [];
        const entries = [];
        if (dataTransfer.items) {
            for (let i = 0; i < dataTransfer.items.length; i++) {
                const item = dataTransfer.items[i];
                if (item.kind === 'file') {
                    const entry = item.webkitGetAsEntry ? item.webkitGetAsEntry() : null;
                    if (entry) entries.push(entry);
                    else {
                        const file = item.getAsFile();
                        if (file) { file.fullPath = file.name; files.push(file); }
                    }
                }
            }
        } else if (dataTransfer.files) {
            for (let i = 0; i < dataTransfer.files.length; i++) {
                const file = dataTransfer.files[i];
                file.fullPath = file.name;
                files.push(file);
            }
        }

        async function readEntry(entry, path = '') {
            if (entry.isFile) {
                const file = await new Promise(resolve => entry.file(resolve));
                file.fullPath = path + file.name;
                files.push(file);
            } else if (entry.isDirectory) {
                const dirReader = entry.createReader();
                const allEntries = [];
                const readBatch = async () => {
                    const batch = await new Promise(resolve => dirReader.readEntries(resolve));
                    if (batch.length > 0) {
                        allEntries.push(...batch);
                        await readBatch();
                    }
                };
                await readBatch();
                for (let i = 0; i < allEntries.length; i++) {
                    await readEntry(allEntries[i], path + entry.name + '/');
                }
            }
        }

        for (let i = 0; i < entries.length; i++) {
            await readEntry(entries[i]);
        }
        return files;
    }

    // Artplayer Setup
    const videoShell = document.getElementById('videoShell');
    if (videoShell && typeof Artplayer !== 'undefined') {
        let subOffset = 0;

        function toggleSubtitles() {
            const tracks = art.video.textTracks;
            if (!tracks || tracks.length === 0) {
                art.notice.show = 'No subtitles available';
                return;
            }
            let turnedOff = false;
            for (let i = 0; i < tracks.length; i++) {
                if (tracks[i].mode === 'showing') {
                    tracks[i].mode = 'hidden';
                    turnedOff = true;
                }
            }
            if (turnedOff) {
                art.notice.show = 'Subtitles Off';
            } else {
                let targetTrack = tracks[tracks.length - 1];
                targetTrack.mode = 'showing';
                art.notice.show = 'Subtitles On: ' + targetTrack.label;
            }
        }
        
        const art = new Artplayer({
            container: '.artplayer-app',
            url: <?= isset($streamUrl) ? json_encode($streamUrl) : '""' ?>,
            title: <?= isset($previewName) ? json_encode($previewName) : '""' ?>,
            theme: '#10b981',
            volume: 1,
            setting: true,
            playbackRate: true,
            fullscreen: true,
            fullscreenWeb: true,
            autoSize: true,
            controls: [
                {
                    position: 'right',
                    html: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width: 22px; height: 22px; margin-top: 5px;"><rect x="3" y="5" width="18" height="14" rx="2" ry="2"></rect><path d="M10 10H8a1 1 0 0 0-1 1v2a1 1 0 0 0 1 1h2M16 10h-2a1 1 0 0 0-1 1v2a1 1 0 0 0 1 1h2"></path></svg>',
                    tooltip: 'Toggle Subtitles (C)',
                    click: function () {
                        toggleSubtitles();
                    }
                }
            ],
        });

        <?php if (isset($tracks)): foreach ($tracks as $index => $track): ?>
        art.video.insertAdjacentHTML('beforeend', '<track kind="subtitles" src="<?= h($track['src']) ?>" srclang="<?= h($track['lang']) ?>" label="<?= h($track['label']) ?>" <?= $index === 0 ? 'default' : '' ?>>');
        <?php endforeach; endif; ?>
        
        setTimeout(() => {
            const tracks = art.video.textTracks;
            if (tracks && tracks.length > 0) tracks[0].mode = 'showing';
        }, 500);

        const localSubInput = document.getElementById('localSubInput');
        if (localSubInput) {
            localSubInput.addEventListener('change', async (e) => {
                const file = e.target.files[0];
                if (!file) return;
                let content = await file.text();
                if (file.name.toLowerCase().endsWith('.srt')) {
                    content = content.replace(/\r\n|\r/g, '\n').replace(/(\d{2}:\d{2}:\d{2}),(\d{3})/g, '$1.$2');
                    content = "WEBVTT\n\n" + content;
                }
                const blob = new Blob([content], { type: 'text/vtt' });
                art.video.insertAdjacentHTML('beforeend', '<track kind="subtitles" src="' + URL.createObjectURL(blob) + '" label="' + file.name + '">');
                
                setTimeout(() => {
                    Array.from(art.video.textTracks).forEach(t => t.mode = 'hidden');
                    const newTrack = Array.from(art.video.textTracks).find(t => t.label === file.name);
                    if (newTrack) newTrack.mode = 'showing';
                }, 100);
            });
        }

        art.setting.add({
            html: 'Subtitle Sync',
            tooltip: '0.0s',
            selector: [
                { html: '-0.5s', offset: -0.5 },
                { html: '-0.1s', offset: -0.1 },
                { html: '+0.1s', offset: 0.1 },
                { html: '+0.5s', offset: 0.5 },
            ],
            onSelect: function (item) {
                shiftSubtitles(item.offset);
                subOffset = (subOffset + item.offset);
                return subOffset.toFixed(1) + 's';
            },
        });

        function shiftSubtitles(seconds) {
            const tracks = art.video.textTracks;
            for(let i=0; i<tracks.length; i++) {
                if(tracks[i].mode === 'showing' || tracks[i].mode === 'hidden') {
                    const cues = tracks[i].cues;
                    if(cues) {
                        for(let j=0; j<cues.length; j++) {
                            cues[j].startTime += seconds;
                            cues[j].endTime += seconds;
                        }
                    }
                }
            }
        }

        document.addEventListener('keydown', (e) => {
            if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') return;
            if (e.key.toLowerCase() === 'c') toggleSubtitles();
            if (e.key.toLowerCase() === 'g') {
                shiftSubtitles(-0.1);
                subOffset -= 0.1;
                art.notice.show = 'Subtitle: ' + subOffset.toFixed(1) + 's';
            }
            if (e.key.toLowerCase() === 'h') {
                shiftSubtitles(0.1);
                subOffset += 0.1;
                art.notice.show = 'Subtitle: ' + subOffset.toFixed(1) + 's';
            }
        });
    }

    // Chunked Upload Engine
    const CSRF_TOKEN = <?= json_encode($csrfToken) ?>;
    const CHUNK_SIZE = <?= CHUNK_SIZE ?>;
    const MAX_SIMULTANEOUS_UPLOADS = 1;
    const MAX_PARALLEL_CHUNKS = 3;
    const MAX_CHUNK_ATTEMPTS = 6;

    const uploadButton = document.getElementById('uploadButton');
    const fileInput = document.getElementById('fileInput');
    const uploadList = document.getElementById('uploadList');

    function formatBytes(bytes) {
        if (!Number.isFinite(bytes) || bytes <= 0) return '0 B';
        const units = ['B', 'KB', 'MB', 'GB', 'TB'];
        const index = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
        return (bytes / Math.pow(1024, index)).toFixed(1) + ' ' + units[index];
    }
    function formatSpeed(bytesPerSecond) {
        if (!Number.isFinite(bytesPerSecond) || bytesPerSecond <= 0) return '0 MB/s';
        if (bytesPerSecond >= 1024 * 1024) return (bytesPerSecond / 1024 / 1024).toFixed(2) + ' MB/s';
        return (bytesPerSecond / 1024).toFixed(1) + ' KB/s';
    }
    function formatEta(seconds) {
        if (!Number.isFinite(seconds) || seconds < 0) return 'Calculating…';
        const total = Math.ceil(seconds);
        if (total < 1) return '< 1 sec';
        const hours = Math.floor(total / 3600); const minutes = Math.floor((total % 3600) / 60); const secs = total % 60;
        if (hours > 0) return `${hours}h ${minutes}m ${secs}s`;
        if (minutes > 0) return `${minutes}m ${secs}s`;
        return `${secs}s`;
    }
    function randomId() {
        if (window.crypto && crypto.getRandomValues) {
            const bytes = new Uint8Array(24); crypto.getRandomValues(bytes);
            return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
        }
        return (Date.now().toString(36) + '_' + Math.random().toString(36).slice(2) + '_' + Math.random().toString(36).slice(2));
    }

    function createCard(file) {
        const card = document.createElement('div');
        card.className = 'ucard';
        card.innerHTML = `
            <div class="uhead"><div class="uname" title="${file.fullPath || file.name}"></div><div class="upercent">0%</div></div>
            <div class="utrack"><div class="ufill"></div></div>
            <div class="umeta">
                <div class="ustat"><div class="ulabel">Speed</div><div class="uvalue speed">0 MB/s</div></div>
                <div class="ustat"><div class="ulabel">Transferred</div><div class="uvalue transferred">0 B</div></div>
                <div class="ustat"><div class="ulabel">Time left</div><div class="uvalue eta">Calculating…</div></div>
            </div>
        `;
        card.querySelector('.uname').textContent = file.fullPath || file.name;
        uploadList.append(card);
        return { percent: card.querySelector('.upercent'), fill: card.querySelector('.ufill'), speed: card.querySelector('.speed'), transferred: card.querySelector('.transferred'), eta: card.querySelector('.eta') };
    }

    function xhrPost(formData, onProgress, timeoutMs = 120000) {
        return new Promise((resolve, reject) => {
            const xhr = new XMLHttpRequest();
            xhr.open('POST', window.location.pathname + window.location.search, true);
            xhr.timeout = timeoutMs;
            xhr.setRequestHeader('X-Requested-With', 'XMLHttpRequest');
            xhr.upload.onprogress = event => { if (event.lengthComputable && typeof onProgress === 'function') onProgress(event.loaded, event.total); };
            xhr.onload = () => {
                let response;
                try { response = JSON.parse(xhr.responseText); } catch (error) { reject(new Error('Server returned invalid JSON.')); return; }
                if (xhr.status >= 200 && xhr.status < 300 && response.ok) resolve(response);
                else reject(new Error(response.message || `Request failed (${xhr.status})`));
            };
            xhr.onerror = () => reject(new Error('Network connection interrupted.'));
            xhr.ontimeout = () => reject(new Error('Upload request timed out.'));
            xhr.onabort = () => reject(new Error('Upload request was aborted.'));
            xhr.send(formData);
        });
    }

    async function uploadChunkWithRetry(makeFormData, onProgress, onRetry, maxAttempts = MAX_CHUNK_ATTEMPTS) {
        let lastError = null;
        for (let attempt = 1; attempt <= maxAttempts; attempt++) {
            try { return await xhrPost(makeFormData(), onProgress); }
            catch (error) {
                lastError = error;
                if (attempt >= maxAttempts) break;
                if (typeof onRetry === 'function') onRetry(attempt, maxAttempts, error);
                const waitMs = Math.min(1000 * Math.pow(2, attempt - 1), 10000);
                await new Promise(resolve => setTimeout(resolve, waitMs));
            }
        }
        throw (lastError || new Error('Chunk upload failed.'));
    }

    async function postForm(makeFormData) {
        let lastError = null;
        for (let attempt = 1; attempt <= 4; attempt++) {
            try {
                const response = await fetch(window.location.pathname + window.location.search, { method: 'POST', body: makeFormData(), cache: 'no-store' });
                const raw = await response.text();
                let data;
                try { data = JSON.parse(raw); } catch (error) { throw new Error('Server returned invalid JSON.'); }
                if (!response.ok || !data.ok) throw new Error(data.message || `Request failed (${response.status})`);
                return data;
            } catch (error) {
                lastError = error;
                if (attempt >= 4) break;
                await new Promise(resolve => setTimeout(resolve, 1000 * attempt));
            }
        }
        throw (lastError || new Error('Request failed.'));
    }

    async function uploadOne(file, ui) {
        const totalChunks = Math.max(1, Math.ceil(file.size / CHUNK_SIZE));
        const uploadId = randomId();
        const startedAt = performance.now();
        const chunkProgress = new Array(totalChunks).fill(0);
        const completedChunks = new Array(totalChunks).fill(false);
        let smoothedSpeed = 0; let lastTotalUploaded = 0; let lastSpeedTime = performance.now();

        function getTotalUploaded() {
            let total = 0;
            for (let i = 0; i < totalChunks; i++) total += chunkProgress[i];
            return Math.min(total, file.size);
        }

        function refreshUi() {
            const uploaded = getTotalUploaded();
            const now = performance.now();
            const deltaTime = Math.max((now - lastSpeedTime) / 1000, 0.001);
            const deltaBytes = Math.max(uploaded - lastTotalUploaded, 0);
            const instantSpeed = deltaBytes / deltaTime;
            if (instantSpeed > 0) smoothedSpeed = smoothedSpeed > 0 ? (smoothedSpeed * 0.75) + (instantSpeed * 0.25) : instantSpeed;
            lastTotalUploaded = uploaded; lastSpeedTime = now;
            
            const elapsed = Math.max((now - startedAt) / 1000, 0.001);
            const averageSpeed = uploaded / elapsed;
            const displaySpeed = smoothedSpeed > 0 ? smoothedSpeed : averageSpeed;
            const percentage = file.size === 0 ? 100 : Math.min(100, (uploaded / file.size) * 100);
            const remainingBytes = Math.max(file.size - uploaded, 0);
            const eta = displaySpeed > 0 ? remainingBytes / displaySpeed : NaN;
            
            ui.fill.style.width = `${percentage}%`;
            ui.percent.textContent = `${percentage.toFixed(1)}%`;
            ui.speed.textContent = formatSpeed(displaySpeed);
            ui.transferred.textContent = `${formatBytes(uploaded)} / ${formatBytes(file.size)}`;
            ui.eta.textContent = formatEta(eta);
        }

        async function uploadChunk(index) {
            const start = index * CHUNK_SIZE;
            const end = Math.min(start + CHUNK_SIZE, file.size);
            const chunk = file.slice(start, end);
            const chunkSize = end - start;

            const makeFormData = () => {
                const data = new FormData();
                data.append('ajax_action', 'upload_chunk');
                data.append('csrf', CSRF_TOKEN);
                data.append('upload_id', uploadId);
                data.append('file_name', file.name);
                data.append('file_path', file.fullPath || file.name);
                data.append('chunk_index', String(index));
                data.append('total_chunks', String(totalChunks));
                data.append('chunk', chunk, `${file.name}.part`);
                return data;
            };

            await uploadChunkWithRetry(makeFormData, loadedInChunk => {
                chunkProgress[index] = Math.min(loadedInChunk, chunkSize);
                refreshUi();
            }, (attempt, maxAttempts) => {
                if (!completedChunks[index]) { chunkProgress[index] = 0; refreshUi(); }
                ui.eta.textContent = `Retrying chunk ${index + 1}… ${attempt}/${maxAttempts - 1}`;
            });

            completedChunks[index] = true;
            chunkProgress[index] = chunkSize;
            refreshUi();
        }

        let nextChunkIndex = 0;
        async function chunkWorker() {
            while (true) {
                const index = nextChunkIndex++;
                if (index >= totalChunks) return;
                await uploadChunk(index);
            }
        }

        const chunkWorkers = [];
        const workerCount = Math.min(MAX_PARALLEL_CHUNKS, totalChunks);
        for (let i = 0; i < workerCount; i++) chunkWorkers.push(chunkWorker());
        await Promise.all(chunkWorkers);

        ui.fill.style.width = '100%';
        ui.percent.textContent = '100%';
        ui.eta.textContent = 'Finalizing…';

        const result = await postForm(() => {
            const data = new FormData();
            data.append('ajax_action', 'finalize_upload');
            data.append('csrf', CSRF_TOKEN);
            data.append('upload_id', uploadId);
            return data;
        });

        ui.eta.textContent = 'Complete ✓';
        ui.speed.textContent = 'Done';
        ui.transferred.textContent = formatBytes(file.size);
        return result;
    }

    async function runPool(tasks, concurrency) {
        let nextIndex = 0;
        async function worker() {
            while (true) {
                const index = nextIndex++;
                if (index >= tasks.length) return;
                await tasks[index]();
            }
        }
        const workers = [];
        for (let i = 0; i < Math.min(concurrency, tasks.length); i++) workers.push(worker());
        await Promise.all(workers);
    }

    function startUploads(files) {
        document.getElementById('modal-upload').classList.add('active');
        if(uploadButton) uploadButton.disabled = true; 
        if(fileInput) fileInput.disabled = true; 
        if(uploadList) uploadList.innerHTML = '';
        let failures = 0;
        const tasks = files.map(file => {
            const ui = createCard(file);
            return async () => {
                try { await uploadOne(file, ui); }
                catch (error) { failures++; ui.eta.textContent = 'Failed'; ui.percent.textContent = 'Error'; alert(`${file.name}: ` + (error instanceof Error ? error.message : String(error))); }
            };
        });
        
        runPool(tasks, MAX_SIMULTANEOUS_UPLOADS).finally(() => {
            if(uploadButton) uploadButton.disabled = false; 
            if(fileInput) fileInput.disabled = false;
            if (failures === 0) setTimeout(() => { window.location.reload(); }, 600);
        });
    }

    if (uploadButton) {
        uploadButton.addEventListener('click', async () => {
            const files = Array.from(fileInput.files);
            if (files.length === 0) { alert('Select one or more files first.'); return; }
            files.forEach(f => f.fullPath = f.name);
            startUploads(files);
        });
    }
})();
</script>
</body>
</html>
