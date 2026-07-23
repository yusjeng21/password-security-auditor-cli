Python 3.13
MIT License
Status: Completed
Course Project

# Password Security Auditor

A comprehensive command-line Password Security Auditor built with Python that helps users evaluate password strength, generate secure passwords, detect commonly used passwords, and audit multiple passwords from a file.

This project was developed as a **group project** for the **Security Script Programming** course at the **University of The Gambia**.

---

## Overview

Weak passwords remain one of the leading causes of compromised online accounts. This application was developed to promote better password security by providing users with tools to evaluate, generate, and audit passwords using modern security practices.

The application combines password strength analysis, secure password generation, blacklist checking, logging, and batch password auditing into a single easy-to-use command-line interface.

---

## Features

- Password Strength Checker
  - Evaluates passwords using multiple security criteria.
  - Assigns a strength score and rating.
  - Provides actionable suggestions for improvement.

- Secure Password Generator
  - Generates strong random passwords.
  - User-configurable length.
  - Optional uppercase, lowercase, digits, and special characters.

- Common Password Detection
  - Detects passwords found in a blacklist of 200+ commonly used passwords.
  - Warns users against choosing insecure passwords.

- Batch Password Analysis
  - Analyze multiple passwords stored in a text file.
  - Displays the strength of every password.
  - Generates a summary report after analysis.

- Event Logging
  - Records application events with timestamps.
  - Never stores passwords in plain text.

- Password History
  - Stores generated password metadata securely.
  - Passwords are stored as SHA-256 hashes instead of plain text.

- Improved Command-Line Interface
  - Clean terminal interface built using the Rich library.
  - Colorful output and improved readability.

---

## Technologies Used

- Python 3
- Rich
- Secrets
- Regular Expressions (re)
- hashlib
- json
- datetime
- os
- File Handling

---

## Project Structure

```text
Password-Security-Auditor/
│
├── password_security_auditor.py
├── common_passwords.txt
├── sample_passwords.txt
├── password_history.json
├── password_log.txt
├── audit_report.txt
├── README.md
└── screenshots/
```

---

## How It Works

### Password Strength Checker

The application evaluates passwords using several security criteria:

- Password length
- Uppercase letters
- Lowercase letters
- Numbers
- Special characters
- Common password detection

A score is calculated and converted into a strength level ranging from **Very Weak** to **Very Strong**.

---

### Password Generator

Users can generate secure passwords by selecting:

- Password length
- Uppercase letters
- Lowercase letters
- Digits
- Special characters

The generator creates passwords using cryptographically secure random values.

---

### Batch Password Analysis

Users can supply a text file containing multiple passwords.

The application:

1. Reads the file.
2. Analyzes each password individually.
3. Displays the strength of every password.
4. Generates a summary report.

This feature makes the tool useful for auditing multiple passwords at once.

---

### Secure Storage

Generated passwords are never stored in plain text.

Instead, they are converted into SHA-256 hashes before being saved to the history file.

---

## Screenshots

![Password Security Auditor Screenshot](<Screenshots/Feature 1 - Check Strength.png>)

---

## Future Improvements

- Export reports as PDF or CSV.
- Password entropy calculation.
- Password expiration recommendations.
- Breached-password API integration.
- Develop a modern web application using React for the frontend and Flask as the backend API.

---

## Project Roadmap

- Version 1.0 — Command-Line Password Security Auditor (Completed)
- Version 2.0 — React + Flask Web Application (Planned)
- Version 3.0 — Advanced Security Dashboard & Cloud Deployment (Future)

---

## Team Members

This project was completed as a group project for the Security Script Programming course.

Special thanks to my teammates for their contributions throughout the project:

- **Yusupha Jeng**
- **Modou Lamin Cham**
- **Alieu Modou Secka**

---

## License

This project was developed for educational purposes as part of coursework at the University of The Gambia.

Feel free to use it for learning and personal projects.
