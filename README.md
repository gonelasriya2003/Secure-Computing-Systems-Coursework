# Secure-Computing-Systems-Coursework
## Overview

This repository contains three Python security tools developed for my coursework:

- Secure Authentication System
- SIEM Lite Threat Detection Tool
- Malware Analysis & Digital Forensics Tool

---

## Files

- task1_auth.py
- task2_siem.py
- task3_forensics.py
- auth.log
- users.json
- blocked_ips.json
- QUARANTINE_VAULT/

---

## Task 1 - Secure Authentication

Features:

- User registration and login
- Password hashing with salt
- Strong password validation
- Delay after failed login attempts

Run:

```bash
python task1_auth.py


**## Task 2 - SIEM Lite**

Features:

Reads log file
Detects repeated failed login attempts
Extracts suspicious IP addresses
Exports results to JSON

Run:

python task2_siem.py 3

**## Task 3 - Malware Analysis**

Features:

SHA-256 file hashing
Signature checking
Quarantine suspicious files
Extract EXIF image metadata

Run:

python task3_forensics.py

