import os
import re
from datetime import datetime, date, timedelta
import json
import shutil
import smtplib
import sys
from email.message import EmailMessage

from flask import Flask, render_template, redirect, url_for, request, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Google Cloud Imports - Only needed if deploying to GCP
try:
    # Attempt to import GCP libraries
    from google.cloud import vision
    from google.cloud import firestore
    from google.api_core.exceptions import GoogleAPICallError
except ImportError:
    # Set to None and fall back to local store if imports fail
    vision = None
    firestore = None
    GoogleAPICallError = Exception
    print("Warning: Google Cloud libraries not installed or configured. Using local fallback.")


# --- 1. Configuration Class ---
class Config:
    """Application configuration settings."""
    
    SECRET_KEY = os.environ.get('SECRET_KEY', 'default_dev_secret_key_12345')
    PROJECT_ID = os.environ.get('PROJECT_ID', 'validityvision') 

    # Upload folder configuration: /tmp is the only writable directory in Cloud Run
    UPLOAD_FOLDER = '/tmp/uploads' 
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}

# --- 2. Initialization ---
app = Flask(__name__)
app.config.from_object(Config)

# Initialize Google Cloud Clients and Local Fallback
db = None
vision_client = None
USERS_COLLECTION = None

# --- Local Store Class (Used if Firestore is unavailable) ---
class LocalStore:
    def __init__(self, path):
        self.path = path
        os.makedirs(self.path, exist_ok=True)
        self.users_file = os.path.join(self.path, 'users.json')
        if not os.path.exists(self.users_file):
            with open(self.users_file, 'w', encoding='utf-8') as f:
                json.dump({}, f)

    def _read(self):
        # Handle empty file case
        try:
            with open(self.users_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except json.JSONDecodeError:
            return {}

    def _write(self, data):
        with open(self.users_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4, default=str)

    def user_exists(self, username):
        data = self._read()
        return username in data

    def create_user(self, username, user_data):
        data = self._read()
        data[username] = user_data
        data[username].setdefault('scans', [])
        self._write(data)

    def get_user(self, username):
        data = self._read()
        return data.get(username)

    def add_scan(self, username, scan_data):
        data = self._read()
        if username not in data:
            # Should not happen if user is logged in, but as a safeguard:
            data[username] = {'password_hash': None, 'created_at': None, 'scans': []}
        
        s = scan_data.copy()
        # Use a unique ID for local store scan items
        s.setdefault('id', datetime.utcnow().isoformat() + "_" + str(len(data[username]['scans'])))
        s.setdefault('notification_sent', False)
        # Store scan history in reverse chronological order
        data[username].setdefault('scans', []).insert(0, s) 
        self._write(data)

    def get_scans(self, username, limit=50):
        data = self._read()
        user = data.get(username, {})
        return user.get('scans', [])[:limit]

    def mark_notification_sent(self, username, scan_id):
        data = self._read()
        user = data.get(username)
        if not user:
            return False
        updated = False
        for s in user.get('scans', []):
            if s.get('id') == scan_id:
                s['notification_sent'] = True
                updated = True
                break
        if updated:
            self._write(data)
            return True
        return False

# Attempt to initialize GCP clients
local_store = None
if vision is not None and firestore is not None and os.environ.get('PROJECT_ID'):
    try:
        db = firestore.Client(project=Config.PROJECT_ID)
        vision_client = vision.ImageAnnotatorClient()
        USERS_COLLECTION = db.collection('users')
        print("Google Cloud Clients Initialized.")
    except Exception as e:
        print(f"Error initializing Google Cloud Clients: {e}")
        print('Falling back to local JSON store for users/scans (development mode).')
        local_store = LocalStore(os.path.join(os.getcwd(), 'dev_data'))
else:
    # Force local store if imports failed or PROJECT_ID is missing
    local_store = LocalStore(os.path.join(os.getcwd(), 'dev_data'))

os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)
os.makedirs(os.path.join(os.getcwd(), 'static', 'uploads'), exist_ok=True)


# --- 3. Utility Functions ---

def allowed_file(filename):
    """Checks if the file extension is allowed."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in Config.ALLOWED_EXTENSIONS

def parse_date_string(date_str):
    """
    Attempts to parse a detected date string into a Python date object.
    """
    date_formats = [
        ('%d/%m/%y', lambda d: date(d.year, d.month, d.day)), 
        ('%m/%d/%y', lambda d: date(d.year, d.month, d.day)), 
        ('%d/%m/%Y', lambda d: date(d.year, d.month, d.day)), 
        ('%m/%d/%Y', lambda d: date(d.year, d.month, d.day)), 
        ('%Y-%m-%d', lambda d: date(d.year, d.month, d.day)), 
        ('%m/%y', lambda d: date(d.year, d.month, 1)),     
        ('%m/%Y', lambda d: date(d.year, d.month, 1)),     
    ]
    
    clean_date_str = date_str.replace('-', '/').replace('.', '/').replace(' ', '/').strip()
    
    for fmt, func in date_formats:
        try:
            dt_obj = datetime.strptime(clean_date_str, fmt)
            # Basic year sanity check (e.g., prevent parsing 01/01/20 to mean 2020 if running in 2025)
            if fmt.endswith(('%y', '%Y')) and dt_obj.year < datetime.now().year - 2:
                 continue # Skip dates too far in the past
            return func(dt_obj), fmt
        except ValueError:
            continue
    
    return None, None 

def detect_expiry_date(image_path):
    """Uses Google Cloud Vision API OCR to extract text and find an expiry date."""
    print(f"Scanning image: {image_path}")
    if vision_client is None:
        return None, "OCR not available - Vision client not configured."

    try:
        with open(image_path, 'rb') as image_file:
            content = image_file.read()

        image = vision.Image(content=content)

        response = vision_client.document_text_detection(image=image)
        full_text = response.full_text_annotation.text

        # Regex patterns to find dates, prioritizing those near keywords
        date_patterns = [
            # EXP, EXPIRES, BEST BY etc. followed by a date
            r'(?:EXP|EXPIRES|BEST\s*BY|BB|USE\s*BY)[^0-9/.\-]*(\d{1,2}[/. -]\d{1,2}[/. -]\d{2,4})', 
            # MM/DD/YYYY or DD/MM/YYYY
            r'(\d{1,2}[/. -]\d{1,2}[/. -]\d{2,4})', 
            # YYYY-MM-DD
            r'(\d{4}[/. -]\d{1,2}[/. -]\d{1,2})', 
            # MM/YY or MM/YYYY
            r'(\d{1,2}[/. -]\d{2,4})', 
        ]
        
        extracted_date_str = None
        
        for pattern in date_patterns:
            match = re.search(pattern, full_text, re.IGNORECASE | re.MULTILINE)
            if match:
                extracted_date_str = match.group(1).strip()
                break
        
        return extracted_date_str, full_text

    except GoogleAPICallError as e:
        print(f"Vision API Error: {e}")
        return None, "Error communicating with Google Cloud Vision API."
    except Exception as e:
        print(f"General Error during detection: {e}")
        return None, "An unexpected error occurred during image processing."

def check_safety(expiry_date_str):
    """Compares the expiry date against today's date."""
    
    if not expiry_date_str:
        return None, "No expiry date detected or the format was unreadable."
        
    try:
        expiry_date, date_format_used = parse_date_string(expiry_date_str)
        
        if not expiry_date:
             return None, f"Detected date format '{expiry_date_str}' could not be safely parsed. Manual check required."

        today = date.today()
        display_date = expiry_date.strftime('%B %d, %Y')
        
        if expiry_date > today:
            message = f"SAFE TO CONSUME: Expires on {display_date}."
            return True, message
        elif expiry_date == today:
            message = f"USE WITH CAUTION: Expires TODAY, {display_date}. Treat as expired."
            return False, message 
        else:
            message = f"EXPIRED: Date was {display_date}. DO NOT USE."
            return False, message
            
    except Exception as e:
        print(f"Safety check error: {e}")
        return None, f"Internal error during date comparison: {e}"


# --- 4. Routes and Core Application Logic ---

@app.route('/')
def index():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('index.html', username=session.get('username'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form.get('email')
        
        if not username or not password or not email:
            flash('Username, password, and email are required!', 'danger')
            return redirect(url_for('register'))
            
        password_hash = generate_password_hash(password)
        if USERS_COLLECTION is not None:
            # Firestore
            if USERS_COLLECTION.document(username).get().exists:
                flash('Username already exists! Please login.', 'danger')
                return redirect(url_for('register'))
            user_data = {
                'username': username,
                'email': email,
                'password_hash': password_hash,
                'created_at': datetime.utcnow()
            }
            USERS_COLLECTION.document(username).set(user_data)
        else:
            # Local Store
            if local_store.user_exists(username):
                flash('Username already exists! Please login.', 'danger')
                return redirect(url_for('register'))
            user_data = {
                'username': username,
                'email': email,
                'password_hash': password_hash,
                'created_at': datetime.utcnow().isoformat()
            }
            local_store.create_user(username, user_data)
        
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user_data = None
        if USERS_COLLECTION is not None:
            user_doc = USERS_COLLECTION.document(username).get()
            if user_doc.exists:
                user_data = user_doc.to_dict()
        else:
            user_data = local_store.get_user(username)

        if user_data and user_data.get('password_hash') and check_password_hash(user_data['password_hash'], password):
            session['username'] = username
            flash(f'Welcome back, {username}!', 'success')
            return redirect(url_for('index'))

        flash('Invalid username or password.', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/upload_scan', methods=['POST'])
def upload_scan():
    if 'username' not in session:
        flash('Please log in to upload.', 'danger')
        return redirect(url_for('login'))
        
    if 'file' not in request.files:
        flash('No file part', 'danger')
        return redirect(url_for('index'))
        
    file = request.files['file']
    
    if file.filename == '':
        flash('No selected file.', 'danger')
        return redirect(url_for('index'))

    filename = secure_filename(file.filename)
    
    if not allowed_file(filename):
        flash('File type not allowed (use jpg, png, jpeg).', 'danger')
        return redirect(url_for('index'))

    temp_filename = f"{session['username']}_{datetime.now().strftime('%Y%m%d%H%M%S')}_{filename}"
    file_path = os.path.join(Config.UPLOAD_FOLDER, temp_filename)
    file.save(file_path) 
    
    # Save a copy to static for local UI preview if using local store
    preview_rel = None
    if local_store is not None:
        uploads_dir = os.path.join(os.getcwd(), 'static', 'uploads')
        saved_preview = os.path.join(uploads_dir, temp_filename)
        try:
            shutil.copyfile(file_path, saved_preview)
            preview_rel = os.path.join('static', 'uploads', temp_filename).replace('\\', '/')
        except Exception as e:
            print('Failed to save preview copy:', e)

    extracted_date_str = None
    is_safe = None
    safety_message = "An error occurred during scanning."
    raw_text_full = "N/A"
    
    scan_time = datetime.utcnow()
    formatted_scan_time = scan_time.strftime('%B %d, %Y, %I:%M:%S %p UTC')

    try:
        # 1. OCR Detection
        extracted_date_str, raw_text_full = detect_expiry_date(file_path)
        
        # 2. Safety Check
        is_safe, safety_message = check_safety(extracted_date_str)
        
        # 3. Prepare/Save Scan History
        expiry_date_obj = None
        if extracted_date_str:
            expiry_date_obj, _ = parse_date_string(extracted_date_str)

        scan_data = {
            'original_filename': filename,
            'scan_date': scan_time, 
            'detected_date': extracted_date_str if extracted_date_str else "N/A",
            'expiry_date_iso': expiry_date_obj.isoformat() if expiry_date_obj else None,
            'is_safe': is_safe,
            'safety_message': safety_message,
            'notification_sent': False
        }
        
        if USERS_COLLECTION is not None:
            # Firestore
            scans_ref = USERS_COLLECTION.document(session['username']).collection('scans')
            scans_ref.add(scan_data)
        else:
            # Local store
            scan_data_local = scan_data.copy()
            scan_data_local['scan_date'] = scan_time.isoformat()
            if preview_rel:
                scan_data_local['preview_path'] = preview_rel
            local_store.add_scan(session['username'], scan_data_local)
        
        user_friendly_raw_text = f"Full OCR text was: '{raw_text_full[:200]}...'" if raw_text_full and len(raw_text_full) > 200 else raw_text_full if raw_text_full else "No text could be extracted."
        
        return render_template(
            'result.html',
            filename=filename,
            expiry_date=extracted_date_str,
            is_safe=is_safe,
            message=safety_message,
            raw_text=user_friendly_raw_text,
            formatted_scan_time=formatted_scan_time
        )
        
    except Exception as e:
        flash(f'Scan failed due to an application error: {e}', 'danger')
        return redirect(url_for('index'))
    finally:
        # Clean up temporary file in /tmp/
        if os.path.exists(file_path):
            os.remove(file_path) 

@app.route('/history')
def history():
    if 'username' not in session:
        return redirect(url_for('login'))
        
    user_scans = []
    try:
        if USERS_COLLECTION is not None:
            scans_ref = USERS_COLLECTION.document(session['username']).collection('scans')
            query = scans_ref.order_by('scan_date', direction=firestore.Query.DESCENDING).limit(50)
            user_scans = [doc.to_dict() for doc in query.stream()]
        else:
            user_scans = local_store.get_scans(session['username'], limit=50)
        
    except Exception as e:
        flash(f'Error fetching history: {e}. Please check permissions.', 'danger')
        user_scans = []
        
    today = date.today()
    enriched = []
    for s in user_scans:
        expiry_iso = s.get('expiry_date_iso') or s.get('expiry_date')
        notified = s.get('notification_sent', False)
        days_left = None
        
        if expiry_iso:
            try:
                # Handle conversion from Firestore Timestamp or string
                if isinstance(expiry_iso, str):
                    expiry_date = datetime.fromisoformat(expiry_iso).date()
                elif hasattr(expiry_iso, 'date'):
                    expiry_date = expiry_iso.date() 
                else:
                    expiry_date = None

                if expiry_date:
                    days_left = (expiry_date - today).days
            except Exception:
                days_left = None
                
        s['_days_left'] = days_left
        s['_notification_sent'] = bool(notified)
        enriched.append(s)

    return render_template('history.html', scans=enriched)


@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))

    user_scans = []
    try:
        if USERS_COLLECTION is not None:
            scans_ref = USERS_COLLECTION.document(session['username']).collection('scans')
            query = scans_ref.order_by('scan_date', direction=firestore.Query.DESCENDING).limit(200)
            user_scans = [doc.to_dict() for doc in query.stream()]
        else:
            user_scans = local_store.get_scans(session['username'], limit=200)
    except Exception as e:
        flash(f'Error fetching dashboard data: {e}', 'danger')
        user_scans = []

    today = date.today()
    enriched = []
    upcoming = []
    reminders_sent = 0
    for s in user_scans:
        expiry_iso = s.get('expiry_date_iso') or s.get('expiry_date')
        notified = s.get('notification_sent', False)
        days_left = None
        
        if expiry_iso:
            try:
                if isinstance(expiry_iso, str):
                    expiry_date = datetime.fromisoformat(expiry_iso).date()
                elif hasattr(expiry_iso, 'date'):
                    expiry_date = expiry_iso.date()
                else:
                    expiry_date = None

                if expiry_date:
                    days_left = (expiry_date - today).days
            except Exception:
                days_left = None
                
        s['_days_left'] = days_left
        s['_notification_sent'] = bool(notified)
        
        # Upcoming is defined as expiring in 2 days or less, but not already expired
        if days_left is not None and days_left <= 2 and days_left >= 0: 
            upcoming.append(s)
        
        if s.get('is_safe') is False and days_left is not None and days_left < 0:
            s['_status_class'] = 'expired'
        elif days_left is not None and days_left <= 7 and days_left >= 0:
            s['_status_class'] = 'warning'
        else:
            s['_status_class'] = 'safe'

        if s['_notification_sent']:
            reminders_sent += 1
            
        enriched.append(s)

    summary = {
        'total_scans': len(enriched),
        'reminders_sent': reminders_sent,
        'upcoming': len(upcoming),
        'expired': sum(1 for s in enriched if s.get('is_safe') is False and (s.get('_days_left') is not None and s.get('_days_left') < 0)),
        'safe': sum(1 for s in enriched if s.get('is_safe') is True),
    }

    return render_template('dashboard.html', scans=enriched, upcoming=upcoming, summary=summary)

# --- Automated Reminder Logic ---

def send_email(to_email, subject, body):
    """Send an email using SMTP server configured via environment variables."""
    # Reads environment variables set in .env or Cloud Run secrets
    smtp_host = os.environ.get('SMTP_HOST')
    smtp_port = int(os.environ.get('SMTP_PORT', 587))
    smtp_user = os.environ.get('SMTP_USER')
    smtp_pass = os.environ.get('SMTP_PASS')
    from_email = os.environ.get('FROM_EMAIL', smtp_user)

    if not smtp_host or not smtp_user or not smtp_pass:
        print('SMTP not configured. Skipping email to', to_email)
        return False

    msg = EmailMessage()
    msg['Subject'] = subject
    msg['From'] = from_email
    msg['To'] = to_email
    msg.set_content(body)

    try:
        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.starttls()
            server.login(smtp_user, smtp_pass)
            server.send_message(msg)
        print(f'Email sent successfully to {to_email}')
        return True
    except Exception as e:
        print(f'Failed to send email to {to_email}: {e}')
        return False


def send_reminders(dry_run=False):
    """Scan stored scans and send reminder emails for items expiring in 2 days."""
    today = date.today()
    reminders_sent = 0

    if USERS_COLLECTION is not None:
        # Firestore Path
        users = USERS_COLLECTION.stream()
        for user_doc in users:
            username = user_doc.id
            user_data = user_doc.to_dict()
            email = user_data.get('email') # Get user's specific email address
            
            if not email:
                print(f"Skipping reminders for {username}: No email address registered.")
                continue

            scans_ref = USERS_COLLECTION.document(username).collection('scans')
            
            for scan_doc in scans_ref.stream():
                s = scan_doc.to_dict()
                expiry_iso = s.get('expiry_date_iso')
                notified = s.get('notification_sent', False)
                
                if not expiry_iso or notified:
                    continue
                
                try:
                    expiry_date = datetime.fromisoformat(expiry_iso).date()
                except Exception:
                    continue
                    
                days_left = (expiry_date - today).days
                
                # Reminder threshold: 2 days left
                if days_left == 2:
                    subject = '⏰ ValidityVision: Product Expiring in 2 Days!'
                    body = f"Hello {username},\n\nOur scan record shows that the product '{s.get('original_filename')}' is expiring on {expiry_date.strftime('%B %d, %Y')}. This is a friendly reminder to use or discard the product within 48 hours.\n\nRegards,\nValidityVision"
                    
                    if dry_run:
                        print(f'(dry) Would send to {email} about {s.get("original_filename")}')
                    else:
                        if send_email(email, subject, body):
                            try:
                                scan_doc.reference.update({'notification_sent': True})
                                reminders_sent += 1
                            except Exception as e:
                                print(f'Failed to mark notification_sent in Firestore for {scan_doc.id}: {e}')
    else:
        # Local JSON Store Path
        data = local_store._read()
        for username, u in data.items():
            email = u.get('email') # Get user's specific email address
            scans = u.get('scans', [])
            
            if not email:
                print(f"Skipping reminders for {username}: No email address registered.")
                continue
                
            for s in scans:
                expiry_iso = s.get('expiry_date_iso')
                notified = s.get('notification_sent', False)
                scan_id = s.get('id')
                
                if not expiry_iso or notified:
                    continue
                
                try:
                    expiry_date = datetime.fromisoformat(expiry_iso).date()
                except Exception:
                    continue
                    
                days_left = (expiry_date - today).days
                
                # Reminder threshold: 2 days left
                if days_left == 2:
                    subject = '⏰ ValidityVision: Product Expiring in 2 Days!'
                    body = f"Hello {username},\n\nOur scan record shows that the product '{s.get('original_filename')}' is expiring on {expiry_date.strftime('%B %d, %Y')}. This is a friendly reminder to use or discard the product within 48 hours.\n\nRegards,\nValidityVision"

                    if dry_run:
                        print(f'(dry) Would send to {email} about {s.get("original_filename")}')
                    else:
                        if send_email(email, subject, body):
                            local_store.mark_notification_sent(username, scan_id)
                            reminders_sent += 1

    print('Total reminders sent:', reminders_sent)
    return reminders_sent


# --- 5. Scheduled Automation Endpoint ---

@app.route('/scheduled_reminders', methods=['GET'])
def scheduled_reminders():
    """Secure endpoint triggered by a scheduled job (e.g., Cloud Scheduler)."""
    
    SCHEDULE_TOKEN = os.environ.get('SCHEDULE_TOKEN')
    
    # Check for the secret token in the request header
    if SCHEDULE_TOKEN:
        if request.headers.get('X-Scheduler-Token') != SCHEDULE_TOKEN:
            print("Access denied: Invalid scheduler token.")
            return {'status': 'error', 'message': 'Unauthorized'}, 401
    
    print("Running scheduled reminder job...")
    try:
        count = send_reminders(dry_run=False)
        return {'status': 'success', 'reminders_sent': count}, 200
    except Exception as e:
        print(f"Failed to run reminders: {e}")
        return {'status': 'error', 'message': str(e)}, 500


# --- 6. Application Run Command ---

if __name__ == '__main__':
    # Allows running reminder job from command-line for testing: 
    # `python app.py send_reminders [--dry-run]`
    if len(sys.argv) > 1 and sys.argv[1] == 'send_reminders':
        dry = '--dry-run' in sys.argv or '-n' in sys.argv
        print(f"Executing scheduled reminders in {'DRY RUN' if dry else 'LIVE'} mode.")
        send_reminders(dry_run=dry)
    else:
        # Standard Flask run command
        app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 8080)))