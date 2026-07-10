<?php
$ch = curl_init('http://localhost/xss-sqli-scanner/demo-target.php');
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_TIMEOUT, 2);
$res = curl_exec($ch);
if ($res === false) {
    echo "CURL ERROR: " . curl_error($ch);
} else {
    echo "CURL SUCCESS: " . strlen($res) . " bytes";
}
