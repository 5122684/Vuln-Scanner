<?php
$_SERVER['REQUEST_METHOD'] = 'POST';
$_POST['url'] = 'http://localhost/xss-sqli-scanner/demo-target.php';
$_POST['scan_xss'] = '1';
$_POST['scan_sqli'] = '1';
$_POST['allow_local'] = '1';
$_POST['intensity'] = 'high';
require 'scanner.php';
