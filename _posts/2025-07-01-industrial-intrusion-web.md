---
title: Industrial Intrusion (2025) - Web Challenge Write-up
date: 2025-06-30 08:00:00 +0800
categories: [ctf, web]
tags: [ctf, tryhackme, web, sqli]    # TAG names should always be lowercase
description: "Challenge: Web Task 35"
---


## Introduction

This write-up details the solution and methodologies employed to solve **Task 35: Web Uninterrupted Problem Supply** from the "Industrial Intrusion (2025)" CTF.

## Task 35 Web Uninterrupted Problem Supply

### The Challenge

Virelia simply loves buying devices from Mechacore. Their most recent acquisition is a UPS unit. Mechacore promised the login page was 100% secure. Let's see if it can keep us out.

---


### Initial Reconnaissance & Solution Attempt

The challenge was hosted on port 80, presenting a "UPS Configuration Login" page upon access. Our initial hypothesis focused on identifying potential SQL injection vulnerabilities.

Using Burp Suite, I captured a login request and saved it to `request.txt`. Subsequently, I utilized `sqlmap` to automatically detect SQL injection vectors and dump database contents:

```bash
sqlmap -r request.txt --batch --dump
```

`sqlmap` successfully identified a SQL injection vulnerability and dumped the `users` table from the `industrial_system` database:

```
Database: industrial_system
Table: users
[1 entry]
+----+------------------------------------------------------------------+----------+
| id | password                                                         | username |
+----+------------------------------------------------------------------+----------+
| 1  | 6a9790ec070cf62edb10aa335bfd4c8f18b532126eea4dd9fe363423b4c73a8a | admin    |
+----+------------------------------------------------------------------+----------+
```

The database dump revealed what appeared to be the administrator's password hash: 6a9790ec070cf62edb10aa335bfd4c8f18b532126eea4dd9fe363423b4c73a8a. My immediate next step was to attempt cracking this hash using hashcat with a common wordlist:

```bash
hashcat -m 1400 -a 0 6a9790ec070cf62edb10aa335bfd4c8f18b532126eea4dd9fe363423b4c73a8a /path to wordlist/rockyou.txt
```

Unfortunately, extensive attempts to crack the hash using rockyou.txt and other common password lists proved futile.

---


### Authentication Bypass via UNION Injection

Given the uncrackable hash, I shifted my focus to a SQL-based authentication bypass via UNION injection. This vulnerability typically arises when the backend validates user credentials after retrieving data from the database, and lacks proper input sanitization or the use of prepared statements.

The following crafted payload exploits this flaw by injecting a fabricated user row that matches the expected password hash during the local validation process:

```sql
' UNION SELECT 1, 'admin', SHA2('joker', 256)-- -
```


### Exploitation Mechanism

This SQL injection vulnerability allowed us to bypass authentication by manipulating the underlying SQL query structure. The backend's design, which retrieved user data and then validating passwords locally, without proper input sanitization or prepared statements, was key to this exploit. Here's a breakdown of how the attack worked:

1.  **Query Termination:**
    The initial single quote `(')` prematurely closes the username string, causing the original condition (e.g., `username = ''`) to return no results.

2.  **UNION Injection:**
    The `UNION SELECT` clause appends a fake row to the query's result set. The original SQL query (e.g., `SELECT id, username, password_hash FROM users WHERE username = '[input]'`) is modified as follows:
    * 1 as a placeholder ID (assuming the first column is numeric).
    * 'admin' as the username.
    * SHA2('joker', 256) generating the hash of the password "joker".
    This matches the backend's expected column count and data types.

3.  **Commenting Out Validation:**
    The double-hyphen (`--`) and the trailing hyphen (`-`) comment out the remainder of the original SQL query, including the backend's password-checking logic (e.g., `AND password = '...'`), preventing it from executing.

4.  **Password Validation Bypass:**
    The backend retrieves the injected row. It then attempts to validate the user-submitted password ("joker") against the fabricated hash (SHA2('joker', 256)). Since the hash is directly derived from "joker", the validation succeeds, logging us in as "admin."

The final reconstructed SQL query that the backend processes appears similar to:

```sql
SELECT * FROM users WHERE username = '' UNION SELECT 1, 'admin', SHA2('joker', 256) --
```

---


## 🧾 Final Solution

By submitting the crafted payload as the username and "joker" as the password, the backend accepted the injected row, authenticated successfully, and redirected us to the logged-in section of the application. The flag was prominently displayed there:

`THM{energy_backup_systems_compromised}`

---

## 🧩 Summary of Vulnerabilities:

The successful authentication bypass underscored a profound failure in the application's security posture. The core issues stemmed from:

- Direct SQL Injection Vulnerability: The login form was susceptible to direct manipulation of database queries.

- Post-Query Password Validation: Critical password validation logic was executed after arbitrary data could be injected and retrieved, effectively nullifying its purpose.

- Absence of Secure Coding Practices: The lack of robust input sanitization and the neglect of prepared statements provided the necessary conditions for this bypass to occur.

---
