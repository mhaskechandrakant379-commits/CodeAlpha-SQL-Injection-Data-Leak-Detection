
# Detecting Data Leaks Using SQL Injection

A Python Flask-based web application developed as a security project to demonstrate SQL injection detection, secure authentication, encrypted data storage, and controlled access to sensitive information.

## Project Overview

This project demonstrates security mechanisms that help reduce the risk of unauthorized access and data exposure in web applications. It includes a pattern-based SQL injection detection test, password hashing, encrypted notes, security event logging, and time-limited capability codes.

**Note:** The SQL injection test identifies suspicious input patterns. It is a demonstration tool, not a complete SQL injection prevention system.

## Features

- User registration and login
- Secure password hashing using Werkzeug
- SQLAlchemy-based database operations
- SQL injection suspicious-pattern detection
- Security event logging without recording raw test input
- Sensitive notes encrypted using AES-256-GCM
- Time-limited, single-use capability codes
- Authenticated dashboard and secure data access
- Flask web interface
- SQLite support for local development
- PostgreSQL configuration for deployment

## Technologies Used

- Python
- Flask
- Flask-SQLAlchemy
- SQLAlchemy
- SQLite
- PostgreSQL
- HTML and CSS
- Werkzeug password hashing
- Cryptography (AES-256-GCM)
- GitHub
- Render

## Project Structure

```text
CodeAlpha-SQL-Injection-Data-Leak-Detection/
├── app.py
├── crypto_utils.py
├── requirements.txt
├── static/
│   └── style.css
└── templates/
    ├── base.html
    ├── capability.html
    ├── dashboard.html
    ├── home.html
    ├── login.html
    ├── register.html
    ├── secure_data.html
    └── security_test.html
```

## How It Works

### 1. Authentication
Users can register and log in. Passwords are stored as password hashes rather than plaintext passwords.

### 2. SQL Injection Detection
The security testing page checks input for selected suspicious patterns, such as `UNION SELECT`, SQL comment markers, and potentially malicious statements. It reports suspicious patterns without executing the submitted test input as SQL.

### 3. Encrypted Data Storage
Sensitive notes are encrypted before being stored in the database. AES-256-GCM provides confidentiality and integrity protection when configured and used correctly.

### 4. Capability Codes
The application supports time-limited, single-use capability codes. A code can authorize a specific operation without revealing the original note owner's password.

### 5. Security Event Logging
Selected security events, including suspicious SQL injection patterns, are recorded for review. Raw test input and passwords should not be written to logs.

## Local Installation

### Prerequisites

- Python
- Git
- A terminal such as Windows PowerShell

### Setup

1. Clone the repository:

   ```bash
   git clone https://github.com/mhaskechandrakant379-commits/CodeAlpha-SQL-Injection-Data-Leak-Detection.git
   ```

2. Open the project directory:

   ```bash
   cd CodeAlpha-SQL-Injection-Data-Leak-Detection
   ```

3. Create and activate a virtual environment on Windows:

   ```powershell
   py -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```

4. Install dependencies:

   ```bash
   python -m pip install -r requirements.txt
   ```

5. Configure the required environment variables before running the application. Set a secure `FLASK_SECRET_KEY` and the encryption key required by `crypto_utils.py`. For PostgreSQL, configure `DATABASE_URL` and install the appropriate PostgreSQL driver.

6. Run the application:

   ```bash
   python app.py
   ```

7. Open the local URL shown in the terminal, normally:

   `http://127.0.0.1:5000`

## Security Configuration

- Use a strong, secret `FLASK_SECRET_KEY` in production.
- Keep the encryption key secure and persistent. Losing or changing it may make previously encrypted notes unreadable.
- Store database credentials and encryption keys in environment variables, not in source code.
- Use PostgreSQL for the deployed application when `DATABASE_URL` is configured.
- Do not commit `.env` files, passwords, database URLs containing credentials, or encryption keys.
- Use HTTPS in production.
- SQL injection pattern detection alone does not replace parameterized queries, input validation, and secure database access practices.

## Testing

The following features have been tested during project development:

- User registration and login
- Dashboard access after authentication
- Encrypted note storage and retrieval
- Suspicious SQL injection pattern detection
- Capability code creation, expiration, and single-use behavior

Live deployment should be retested after code or configuration changes.

## Deployment

The application is deployed on Render.

Live Demo: https://codealpha-sql-injection-data-leak.onrender.com

Repository: https://github.com/mhaskechandrakant379-commits/CodeAlpha-SQL-Injection-Data-Leak-Detection

## Project Purpose

This project was developed as a hands-on demonstration of web application security concepts, including authentication, encryption, suspicious SQL injection pattern detection, security logging, and controlled access to sensitive data.

## Disclaimer

This application is intended for educational and authorized security testing only. The detection feature uses selected patterns and cannot identify every SQL injection attack or guarantee that an application is secure.
