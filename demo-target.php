<?php
/**
 * VulnProbe — demo-target.php
 *
 * ⚠️ INTENTIONALLY VULNERABLE demo page for testing the scanner locally.
 *    DO NOT deploy on a public server. For educational use only.
 *
 * Test this page with: http://localhost/xss-sqli-scanner/demo-target.php
 */

header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: strict-origin-when-cross-origin');
header('Permissions-Policy: geolocation=(), microphone=(), camera=()');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Content-Security-Policy: default-src \"self\"; style-src \"self\" \"unsafe-inline\"; img-src \"self\" data:; object-src \"none\"; base-uri \"self\"; frame-ancestors \"none\"');

$search  = trim((string)($_GET['q'] ?? $_POST['q'] ?? ''));
$name    = trim((string)($_GET['name'] ?? $_POST['name'] ?? ''));
$comment = trim((string)($_GET['comment'] ?? $_POST['comment'] ?? ''));
$id      = trim((string)($_GET['id'] ?? $_POST['id'] ?? ''));
$search_out  = htmlspecialchars($search, ENT_QUOTES, 'UTF-8');
$name_out    = htmlspecialchars($name, ENT_QUOTES, 'UTF-8');
$comment_out = htmlspecialchars($comment, ENT_QUOTES, 'UTF-8');
$id_out      = htmlspecialchars($id, ENT_QUOTES, 'UTF-8');
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <title>VulnProbe — Demo Target Page</title>
  <style>
    body { font-family: system-ui; background: #1a1a2e; color: #e2e2e2; padding: 2rem; max-width: 700px; margin: 0 auto; }
    h1 { color: #e94560; }
    .warning { background: rgba(233,69,96,0.15); border: 1px solid #e94560; border-radius: 8px; padding: 1rem; margin-bottom: 2rem; font-size: 0.85rem; }
    form { background: #16213e; border: 1px solid rgba(255,255,255,0.1); border-radius: 10px; padding: 1.5rem; margin-bottom: 1.5rem; }
    h2 { color: #0f3460; background: #e94560; display: inline-block; padding: 3px 10px; border-radius: 4px; font-size: 0.85rem; margin-bottom: 1rem; }
    label { display: block; margin-bottom: 0.3rem; font-size: 0.85rem; color: #94a3b8; }
    input[type=text], input[type=search], input[type=email], input[type=password], textarea {
      width: 100%; padding: 0.6rem 0.8rem; background: #0f3460; border: 1px solid rgba(255,255,255,0.1);
      border-radius: 6px; color: #e2e2e2; font-size: 0.9rem; margin-bottom: 0.75rem; box-sizing: border-box;
    }
    button { padding: 0.6rem 1.5rem; background: #e94560; border: none; border-radius: 6px; color: #fff; cursor: pointer; font-size: 0.9rem; }
    .output { background: rgba(255,255,255,0.04); border-radius: 8px; padding: 1rem; margin-top: 1rem; font-size: 0.88rem; }
    .output-label { font-size: 0.72rem; color: #64748b; text-transform: uppercase; letter-spacing: 0.08em; margin-bottom: 0.3rem; }
    .vuln-tag { background: #e94560; padding: 2px 6px; border-radius: 4px; font-size: 0.65rem; font-weight: 700; margin-left: 0.5rem; vertical-align: middle; }
  </style>
</head>
<body>

<h1>🎯 VulnProbe Demo Target</h1>
<div class="warning">
  ✅ <strong>Hardened demo page</strong> — This page now escapes user-controlled output and uses safe headers.
  Run <strong>VulnProbe scanner</strong> against <code>http://localhost/xss-sqli-scanner/demo-target.php</code> to test the protected version.
</div>

<!-- ───────────────────────────────────────────────────────── FORM 1: Search -->
<form method="GET" action="demo-target.php">
  <h2>FORM 1 — Search Box <span class="vuln-tag">XSS VULNERABLE</span></h2>
  <label for="q">Search Query</label>
  <input type="search" id="q" name="q" placeholder="Search something..."/>
  <button type="submit">Search</button>

  <?php if ($search !== ''): ?>
  <div class="output">
    <div class="output-label">Results for:</div>
    <p>You searched for: <?= $search_out ?></p>
  </div>
  <?php endif; ?>
</form>

<!-- ───────────────────────────────────────────────────────── FORM 2: Login -->
<form method="POST" action="demo-target.php">
  <h2>FORM 2 — Login <span class="vuln-tag">SQLi VULNERABLE</span></h2>
  <label for="name">Username</label>
  <input type="text" id="name" name="name" placeholder="Enter username"/>
  <label for="id">User ID</label>
  <input type="text" id="id" name="id" placeholder="Enter ID"/>
  <label for="pass">Password</label>
  <input type="password" id="pass" name="pass" placeholder="Password"/>
  <button type="submit">Login</button>

  <?php if ($name !== '' || $id !== ''): ?>
  <div class="output">
    <div class="output-label">Login status:</div>
    <p>Login request received for user: <?= $name_out ?> (ID: <?= $id_out ?>)</p>
    <p style="color:#10b981">This demo now escapes output and avoids exposing database errors.</p>
  </div>
  <?php endif; ?>
</form>

<!-- ───────────────────────────────────────────────── FORM 3: Comment Box -->
<form method="POST" action="demo-target.php">
  <h2>FORM 3 — Comment Form <span class="vuln-tag">XSS VULNERABLE</span></h2>
  <label for="comment">Your Comment</label>
  <textarea id="comment" name="comment" rows="4" placeholder="Leave a comment..."></textarea>
  <input type="email" name="email" placeholder="Your email (optional)"/>
  <button type="submit">Post Comment</button>

  <?php if ($comment !== ''): ?>
  <div class="output">
    <div class="output-label">Comment posted:</div>
    <p><?= $comment_out ?></p>
  </div>
  <?php endif; ?>
</form>

<hr style="border-color:rgba(255,255,255,0.08);margin:2rem 0"/>
<p style="font-size:0.75rem;color:#475569">
  🔒 Production-safe patterns include <code>htmlspecialchars($output, ENT_QUOTES, 'UTF-8')</code>
  for XSS prevention and <strong>PDO prepared statements</strong> for SQL injection prevention.
</p>

</body>
</html>
