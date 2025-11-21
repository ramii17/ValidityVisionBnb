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
    from google.cloud import vision
    from google.cloud import firestore
    from google.api_core.exceptions import GoogleAPICallError
except ImportError:
    vision = None
    firestore = None
    GoogleAPICallError = Exception
    print("Warning: Google Cloud libraries not installed or configured. Using local fallback.")


# --- 1. Configuration Class ---
class Config:
    """Application configuration settings."""
    
    SECRET_KEY = os.environ.get('SECRET_KEY', 'default_dev_secret_key_12345')
    PROJECT_ID = os.environ.get('PROJECT_ID', 'validityvision') 

    UPLOAD_FOLDER = '/tmp/uploads' 
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}

# --- 2. Initialization ---
app = Flask(__name__)
app.config.from_object(Config)

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
            data[username] = {'password_hash': None, 'created_at': None, 'scans': []}
        
        s = scan_data.copy()
        s.setdefault('id', datetime.utcnow().isoformat() + "_" + str(len(data[username]['scans'])))
        s.setdefault('notification_sent', False)
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
        ('%d/%m/%Y', lambda d: date(d.year, d.month, d.day)), 
        ('%Y-%m-%d', lambda d: date(d.year, d.month, d.day)), 
        ('%m/%d/%y', lambda d: date(d.year, d.month, d.day)), 
        ('%m/%d/%Y', lambda d: date(d.year, d.month, d.day)), 
        ('%d %b %Y', lambda d: date(d.year, d.month, d.day)), 
        ('%d %B %Y', lambda d: date(d.year, d.month, d.day)), 
        ('%m/%y', lambda d: date(d.year, d.month, 1)),     
        ('%m/%Y', lambda d: date(d.year, d.month, 1)),     
    ]
    
    clean_date_str = date_str.replace('-', '/').replace('.', '/').replace(' ', ' ').strip()
    
    for fmt, func in date_formats:
        try:
            dt_obj = datetime.strptime(clean_date_str, fmt)
            if fmt.endswith(('%y', '%Y')) and dt_obj.year < datetime.now().year - 2:
                 continue 
            return func(dt_obj), fmt
        except ValueError:
            continue
    
    return None, None 

def detect_expiry_date(image_path):
    """Uses Google Cloud Vision API OCR to extract text and find an expiry date."""
    if vision_client is None:
        return None, "OCR not available - Vision client not configured."

    try:
        with open(image_path, 'rb') as image_file:
            content = image_file.read()

        image = vision.Image(content=content)
        response = vision_client.text_detection(image=image)

        full_text = ""
        if response.full_text_annotation:
            full_text = response.full_text_annotation.text
        elif response.text_annotations:
            full_text = response.text_annotations[0].description
        
        print("--- RAW OCR TEXT START ---")
        print(full_text)
        print("--- RAW OCR TEXT END ---")

        # REVISED REGEX FOR EXPLICIT LABELS
        date_patterns = [
            # 1. CRITICAL PRIORITY: Explicit EXP/USE BY/BB followed by a date 
            r'(?:EXP\.?|EXPIRES|USE\s*BY|UB|BEST\s*BY|BB)\s*[^0-9/.\-:\w]*(\d{1,2}[/. -]\d{1,2}[/. -]\d{2,4}|\d{1,2}[/. -]\w{3}[/. -]\d{4})',

            # 2. HIGH PRIORITY: Date immediately preceding 'USE BY' or 'EXP' 
            r'(\d{1,2}[/. -]\d{1,2}[/. -]\d{2,4})\s*(?:USE\s*BY|UB|EXP)',
            
            # 3. MEDIUM PRIORITY: General DD/MM/YYYY or MM/DD/YYYY format 
            r'(\d{1,2}[/. -]\d{1,2}[/. -]\d{2,4})', 
            
            # 4. LOW PRIORITY: YYYY-MM-DD
            r'(\d{4}[/. -]\d{1,2}[/. -]\d{1,2})', 
            
            # 5. LOWEST PRIORITY: MM/YY or MM/YYYY
            r'(\d{1,2}[/. -]\d{2,4})', 
        ]
        
        extracted_date_str = None
        
        for pattern in date_patterns:
            match = re.search(pattern, full_text, re.IGNORECASE | re.MULTILINE | re.DOTALL) 
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
    # Redirect logged-in users to the dashboard
    return redirect(url_for('dashboard'))

@app.route('/scanner')
def scanner_page():
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
        
        # Send a confirmation email (will fail if SMTP is not configured)
        send_email(email, "ValidityVision Registration Successful", 
                   f"Welcome, {username}! Your account is now active.")
        
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
            return redirect(url_for('dashboard')) # Go to dashboard
        
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
        return redirect(url_for('dashboard'))
        
    file = request.files['file']
    
    if file.filename == '':
        flash('No selected file.', 'danger')
        return redirect(url_for('dashboard'))

    filename = secure_filename(file.filename)
    
    if not allowed_file(filename):
        flash('File type not allowed (use jpg, png, jpeg).', 'danger')
        return redirect(url_for('dashboard'))

    temp_filename = f"{session['username']}_{datetime.now().strftime('%Y%m%d%H%M%S')}_{filename}"
    file_path = os.path.join(Config.UPLOAD_FOLDER, temp_filename)
    file.save(file_path) 
    
    # IMAGE PREVIEW MODIFICATION (FOR LOCAL DISPLAY)
    preview_rel = None
    uploads_dir = os.path.join(os.getcwd(), 'static', 'uploads')
    saved_preview = os.path.join(uploads_dir, temp_filename)
    try:
        shutil.copyfile(file_path, saved_preview)
        preview_rel = os.path.join('static', 'uploads', temp_filename).replace('\\', '/')
    except Exception as e:
        print('Failed to save preview copy for local display:', e)

    extracted_date_str = None
    is_safe = None
    safety_message = "An error occurred during scanning."
    raw_text_full = "N/A"
    scan_time = datetime.utcnow()

    try:
        extracted_date_str, raw_text_full = detect_expiry_date(file_path)
        is_safe, safety_message = check_safety(extracted_date_str)
        
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
        
        if preview_rel:
            scan_data['preview_path'] = preview_rel

        if USERS_COLLECTION is not None:
            scans_ref = USERS_COLLECTION.document(session['username']).collection('scans')
            scans_ref.add(scan_data)
        else:
            scan_data_local = scan_data.copy()
            scan_data_local['scan_date'] = scan_time.isoformat()
            local_store.add_scan(session['username'], scan_data_local)
        
        # Flash the result message and redirect to dashboard
        flash(safety_message, 'success' if is_safe is True else 'danger')
        return redirect(url_for('dashboard'))
        
    except Exception as e:
        flash(f'Scan failed due to an application error: {e}', 'danger')
        return redirect(url_for('dashboard'))
    finally:
        if os.path.exists(file_path):
            os.remove(file_path) 

@app.route('/history')
def history():
    if 'username' not in session:
        return redirect(url_for('login'))
        
    user_scans = []
    try:
        if USERS_COLLECTION is not None:
            query = USERS_COLLECTION.document(session['username']).collection('scans').order_by('scan_date', direction=firestore.Query.DESCENDING).limit(50)
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
        s['_notification_sent'] = bool(s.get('notification_sent', False))
        s['preview_path'] = s.get('preview_path')
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
            query = scans_ref.order_by('scan_date', direction=firestore.Query.DESCENDING).limit(50) 
            user_scans = [doc.to_dict() for doc in query.stream()]
        else:
            user_scans = local_store.get_scans(session['username'], limit=50)
    except Exception as e:
        flash(f'Error fetching dashboard data: {e}', 'danger')
        user_scans = []

    today = date.today()
    enriched = []
    upcoming = []
    reminders_sent = 0
    for s in user_scans:
        expiry_iso = s.get('expiry_date_iso') or s.get('expiry_date')
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
        s['_notification_sent'] = bool(s.get('notification_sent', False))
        
        if s['_notification_sent']:
            reminders_sent += 1
            
        if s.get('is_safe') is False and days_left is not None and days_left < 0:
            s['_status_class'] = 'expired'
        elif days_left is not None and days_left <= 7 and days_left >= 0:
            s['_status_class'] = 'warning'
        else:
            s['_status_class'] = 'safe'

        if days_left is not None and 0 <= days_left <= 2: 
            upcoming.append(s)
            
        s['preview_path'] = s.get('preview_path')

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
    """Send an email using SMTP server configured via environment variables (with debug logging)."""
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
            
            # --- DEBUG LOGGING ---
            print(f"Attempting login as {smtp_user}...")
            # --- END DEBUG LOGGING ---
            
            server.login(smtp_user, smtp_pass)
            
            # --- DEBUG LOGGING ---
            print("Login successful! Sending message...") 
            # --- END DEBUG LOGGING ---
            
            server.send_message(msg)
        print(f'Email sent successfully to {to_email}')
        return True
    except smtplib.SMTPAuthenticationError:
        print(f'Failed to send email to {to_email}: SMTP Authentication Error (Incorrect password or **App Password required**).')
        return False
    except smtplib.SMTPConnectError as e:
        print(f'Failed to send email to {to_email}: Connection Error (Check HOST/PORT/Firewall). Error: {e}')
        return False
    except Exception as e:
        print(f'Failed to send email to {to_email}: General Error. Error: {e}')
        return False


def send_reminders(dry_run=False):
    """Scan stored scans and send reminder emails for items expiring in 2 days."""
    today = date.today()
    reminders_sent = 0

    if USERS_COLLECTION is not None:
        # FIRESTORE PATH
        print("Running reminders job using Firestore...")
        users = USERS_COLLECTION.stream()
        
        for user_doc in users:
            username = user_doc.id
            user_data = user_doc.to_dict()
            email = user_data.get('email') # Get email from root user document
            
            if not email:
                print(f"Skipping reminders for {username}: No email address registered in Firestore.")
                continue

            scans_ref = USERS_COLLECTION.document(username).collection('scans')
            
            for scan_doc in scans_ref.stream():
                s = scan_doc.to_dict()
                expiry_iso = s.get('expiry_date_iso')
                notified = s.get('notification_sent', False)
                
                if not expiry_iso or notified:
                    continue
                
                try:
                    if isinstance(expiry_iso, str):
                        expiry_date = datetime.fromisoformat(expiry_iso).date()
                    elif hasattr(expiry_iso, 'date'):
                        expiry_date = expiry_iso.date()
                    else:
                        continue 
                except Exception:
                    continue
                    
                days_left = (expiry_date - today).days
                
                if days_left == 2:
                    subject = '⏰ ValidityVision: Product Expiring in 2 Days!'
                    body = f"Hello {username},\n\nOur scan record shows that the product '{s.get('original_filename')}' is expiring on {expiry_date.strftime('%B %d, %Y')}. This is a friendly reminder to use or discard the product within 48 hours.\n\nRegards,\nValidityVision"
                    
                    if dry_run:
                        print(f'(dry) Would send to {email} about {s.get("original_filename")} (Expiring in 2 days)')
                    else:
                        if send_email(email, subject, body):
                            try:
                                scan_doc.reference.update({'notification_sent': True}) 
                                reminders_sent += 1
                            except Exception as e:
                                print(f'Failed to mark notification_sent in Firestore for {scan_doc.id}: {e}')
    else:
        # LOCAL JSON STORE PATH
        print("Running reminders job using Local JSON Store...")
        data = local_store._read()
        for username, u in data.items():
            email = u.get('email')
            scans = u.get('scans', [])
            
            if not email:
                print(f"Skipping reminders for {username}: No email address registered in local store.")
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
                
                if days_left == 2:
                    subject = '⏰ ValidityVision: Product Expiring in 2 Days!'
                    body = f"Hello {username},\n\nOur scan record shows that the product '{s.get('original_filename')}' is expiring on {expiry_date.strftime('%B %d, %Y')}. This is a friendly reminder to use or discard the product within 48 hours.\n\nRegards,\nValidityVision"

                    if dry_run:
                        print(f'(dry) Would send to {email} about {s.get("original_filename")} (Expiring in 2 days)')
                    else:
                        if send_email(email, subject, body):
                            local_store.mark_notification_sent(username, scan_id)
                            reminders_sent += 1

    print('Total reminders sent:', reminders_sent)
    return reminders_sent


# --- 5. Scheduled Automation Endpoint ---

@app.route('/scheduled_reminders', methods=['GET'])
def scheduled_reminders():
    SCHEDULE_TOKEN = os.environ.get('SCHEDULE_TOKEN')
    
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
    if len(sys.argv) > 1 and sys.argv[1] == 'send_reminders':
        dry = '--dry-run' in sys.argv or '-n' in sys.argv
        print(f"Executing scheduled reminders in {'DRY RUN' if dry else 'LIVE'} mode.")
        send_reminders(dry_run=dry)
    else:
        app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 8080)))