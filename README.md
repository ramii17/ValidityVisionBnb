👁️ ValidityVision: AI-Powered Expiry Date Scanner

💡 Project Summary
ValidityVision is a smart web application built using Python/Flask that leverages Google Cloud AI to automatically detect, track, and send reminders for the expiration dates of household items (like food, medication, or cosmetics) from a simple photo. This system promotes health, reduces waste, and automates manual inventory tracking.

🚀 Key Features
Snap and Scan Workflow: Users upload an image, and the system instantly returns the detected expiry date and a safety assessment.

AI-Powered OCR: Uses the Google Cloud Vision API to accurately extract text from uploaded images.

Robust Date Normalization: Employs a multi-pattern Regular Expression set and custom parsing logic (parse_date_string function) to reliably convert diverse text formats (e.g., 12/24, EXP 04-2025, Best By Dec 2024) into a standardized YYYY-MM-DD date object.

Scalable Persistence: Uses Google Cloud Firestore to securely store user data and scan history.

Automated Reminders: Features a dedicated, token-secured endpoint (/scheduled_reminders) and SMTP functionality (send_email and send_reminders) to proactively notify users about products expiring within 48 hours.

Resilience and Portability: Includes a full LocalStore fallback that utilizes local JSON files, allowing the application to run, register users, and store scans even when Google Cloud services are not configured or available (ideal for local development).

🛠️ Technical Stack & Architecture
Component,Technology,Rationale & Implementation Detail
Backend,"Python 3.x, Flask","Lightweight, efficient web framework for handling routes, session management, and business logic."
AI/OCR,Google Cloud Vision API,High-accuracy text extraction from images. Handled within the detect_expiry_date function with robust try...except blocks.
Database,Google Cloud Firestore,NoSQL document database for scalable storage of user profiles and a sub-collection for each user's scans.
Scheduled Jobs,Flask Endpoint (/scheduled_reminders),Designed to be triggered by external services like Google Cloud Scheduler or a cron job. Secured with an X-Scheduler-Token environment variable.
Notifications,SMTP (smtplib),Implements the reliable email notification system for 2-day expiry reminders.
User Management,Werkzeug Security,"Used for secure password hashing and verification (generate_password_hash, check_password_hash)."

⚙️ Setup and Installation
Prerequisites
Python 3.8+

A Google Cloud Project with the Cloud Vision API enabled (for live GCP functionality).

App Password for the sending email account (if using services like Gmail).

1. Clone the Repository
git clone https://github.com/yourusername/ValidityVision.git
cd ValidityVision

2. Install Dependencies
pip install -r requirements.txt

3. Configure Environment Variables
Create a file named .env in the root directory and populate it with your configuration details.
Variable,Description,Example Value
SECRET_KEY,Flask session security key.,a_long_random_string
PROJECT_ID,Your Google Cloud Project ID.,my-gaia-project-12345
SMTP_HOST,"Email provider's host (e.g., Gmail).",smtp.gmail.com
SMTP_PORT,Email provider's port (usually 587).,587
SMTP_USER,Email address to send reminders from.,my.app.email@gmail.com
SMTP_PASS,REQUIRED: The App Password for the SMTP user (not your main account password).,abcd1234efgh5678
SCHEDULE_TOKEN,Secret token to secure the reminder endpoint.,a_secret_schedule_key
