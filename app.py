import os
import secrets
import csv
import io
from PIL import Image, UnidentifiedImageError
from flask import Flask, render_template, redirect, url_for, flash, request, make_response, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from datetime import datetime
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature

app = Flask(__name__)
app.config['SECRET_KEY'] = 'bawjiase-secure-key-2025'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///bawjiase.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Email configuration (replace with your real SMTP credentials)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your_email@example.com'          # change this
app.config['MAIL_PASSWORD'] = 'your_email_app_password_here'    # change this
app.config['MAIL_DEFAULT_SENDER'] = ('BARB Staff Portal', 'your_email@example.com')  # change this

# CONFIGURE FOLDERS
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
app.config['UPLOAD_FOLDER'] = os.path.join(BASE_DIR, 'static/profile_pics')
app.config['NEWS_FOLDER'] = os.path.join(BASE_DIR, 'static/news_images')

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['NEWS_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Email + token tools
mail = Mail(app)
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# --- ASSOCIATION TABLE ---
hidden_posts = db.Table('hidden_posts',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id')),
    db.Column('announcement_id', db.Integer, db.ForeignKey('announcement.id'))
)

# --- MODELS ---
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    fullname = db.Column(db.String(150), nullable=False)
    phone = db.Column(db.String(20), nullable=False, default="N/A")
    email = db.Column(db.String(150), unique=True, nullable=False)
    email_verified = db.Column(db.Boolean, default=False)  # NEW FIELD
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(50), default='General Staff')
    position = db.Column(db.String(100), nullable=True, default='Staff')
    department = db.Column(db.String(100), nullable=False)
    branch = db.Column(db.String(100), nullable=False)
    image_file = db.Column(db.String(20), nullable=False, default='default.jpg')
    is_active_user = db.Column(db.Boolean, default=True) 
    hidden_announcements = db.relationship('Announcement', secondary=hidden_posts, backref='hidden_by')
    def get_id(self): return str(self.id)

class Announcement(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    body = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(50), nullable=False)
    author = db.Column(db.String(100), nullable=False)
    date_posted = db.Column(db.DateTime, default=datetime.utcnow)
    image_file = db.Column(db.String(50), nullable=True)
    allow_download = db.Column(db.Boolean, default=True)
    is_deleted = db.Column(db.Boolean, default=False)
    poll = db.relationship('Poll', backref='announcement', uselist=False, cascade="all, delete-orphan")

class Poll(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    question = db.Column(db.String(200), nullable=False)
    announcement_id = db.Column(db.Integer, db.ForeignKey('announcement.id'), nullable=False)
    options = db.relationship('PollOption', backref='poll', lazy=True, cascade="all, delete-orphan")
    votes = db.relationship('PollVote', backref='poll', lazy=True, cascade="all, delete-orphan")

class PollOption(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(100), nullable=False)
    count = db.Column(db.Integer, default=0)
    poll_id = db.Column(db.Integer, db.ForeignKey('poll.id'), nullable=False)

class PollVote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    poll_id = db.Column(db.Integer, db.ForeignKey('poll.id'), nullable=False)

class Form(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    category = db.Column(db.String(50), nullable=False) 
    filename = db.Column(db.String(500), nullable=False) 
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)

class IncidentReport(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    agency = db.Column(db.String(100), nullable=False)
    issue_category = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    reporter_name = db.Column(db.String(150), nullable=False)
    contact = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(20), default='Open')
    date_submitted = db.Column(db.DateTime, default=datetime.utcnow)

class ProfileAmendment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    fullname = db.Column(db.String(150), nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    t24_username = db.Column(db.String(100), nullable=False)
    agency = db.Column(db.String(100), nullable=False)
    request_type = db.Column(db.String(150), nullable=False)
    new_role = db.Column(db.String(150), nullable=True)
    dept_change = db.Column(db.String(150), nullable=True)
    transfer_location = db.Column(db.String(100), nullable=True)
    status = db.Column(db.String(20), default='Open')
    date_submitted = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id): return db.session.get(User, int(user_id))

@app.context_processor
def inject_notifications():
    if current_user.is_authenticated:
        if current_user.department == 'IT' or current_user.role == 'Super Admin':
            incident_count = IncidentReport.query.filter_by(status='Open').count()
            amendment_count = ProfileAmendment.query.filter_by(status='Open').count()
            return dict(unread_count=incident_count + amendment_count)
    return dict(unread_count=0)

# --- EMAIL VERIFICATION HELPERS ---
def send_verification_email(user):
    token = serializer.dumps(user.id, salt='email-confirm')
    verify_url = url_for('verify_email', token=token, _external=True)

    msg = Message(
        subject='Verify your BARB Staff Portal account',
        recipients=[user.email],
    )
    msg.body = f"""Dear {user.fullname},

Welcome to the Bawjiase Area Rural Bank Staff Portal.

Please click the link below to verify your email and activate your account:

{verify_url}

If you did not create this account, you can safely ignore this email.

Thank you.
BARB ICT Unit
"""
    mail.send(msg)

def send_password_reset_email(user):
    """Send a password reset link to the user's email."""
    token = serializer.dumps(user.email, salt='password-reset')
    reset_url = url_for('reset_password', token=token, _external=True)

    msg = Message(
        subject='BARB Staff Portal – Reset Your Password',
        recipients=[user.email]
    )
    msg.body = f"""Hello {user.fullname},

You (or someone using your email) requested to reset your BARB Staff Portal password.

To reset your password, click the secure link below:

{reset_url}

If you did NOT request this, please ignore this email. Your password will remain unchanged.

Best regards,
Bawjiase Area Rural Bank – IT Team
"""
    mail.send(msg)

def save_uploaded_file(form_file, folder):
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_file.filename)
    f_ext = f_ext.lower()
    picture_fn = random_hex + f_ext
    picture_path = os.path.join(folder, picture_fn)
    
    # Updated allowed list for Excel and PPT
    allowed_docs = ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx']
    allowed_images = ['.jpg', '.jpeg', '.png', '.gif', '.webp']
    
    if f_ext in allowed_docs:
        form_file.save(picture_path)
        return picture_fn
    elif f_ext in allowed_images:
        try:
            i = Image.open(form_file)
            if i.width > 1200:
                output_size = (1200, 1200)
                i.thumbnail(output_size)
            i.save(picture_path)
            return picture_fn
        except: return None
    return None

# --- ROUTES ---
@app.route('/')
def home(): 
    if current_user.is_authenticated: return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    with app.app_context(): db.create_all()
    if request.method == 'POST':
        email = request.form.get('email', '').lower()
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, request.form.get('password')):
            # Block login if email not verified
            if not user.email_verified:
                flash('Please verify your email address before logging in. We have sent you a new verification email.', 'warning')
                send_verification_email(user)
                return redirect(url_for('login'))
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Invalid credentials', 'danger')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email', '').lower()
        if User.query.filter_by(email=email).first():
            flash('An account with this email already exists.', 'warning')
            return redirect(url_for('register'))
        pw = bcrypt.generate_password_hash(request.form.get('password')).decode('utf-8')
        user = User(
            fullname=request.form.get('fullname'),
            phone=request.form.get('phone'),
            email=email,
            password=pw,
            department=request.form.get('department'),
            branch=request.form.get('branch')
        )
        user.email_verified = False
        db.session.add(user)
        db.session.commit()
        send_verification_email(user)
        # UPDATED MESSAGE
        flash(
            'Account created. Check your email and click the verification link before logging in.',
            'info'
        )
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/verify/<token>')
def verify_email(token):
    try:
        user_id = serializer.loads(token, salt='email-confirm', max_age=60 * 60 * 24)  # 24 hours
    except SignatureExpired:
        flash('Verification link has expired. Please log in to request a new verification email.', 'warning')
        return redirect(url_for('login'))
    except BadSignature:
        flash('Invalid verification link.', 'danger')
        return redirect(url_for('login'))

    user = User.query.get(user_id)
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('login'))

    if user.email_verified:
        flash('Email already verified. You can log in.', 'info')
    else:
        user.email_verified = True
        db.session.commit()
        flash('Your email has been verified. You can now log in.', 'success')

    return redirect(url_for('login'))

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    reset_sent = False

    if request.method == 'POST':
        email = (request.form.get('email') or "").strip().lower()
        if email:
            user = User.query.filter_by(email=email).first()
            if user:
                # Send real reset email (but don't reveal existence)
                try:
                    send_password_reset_email(user)
                except Exception:
                    # Fail silently for the user; you can log errors internally
                    pass
        # Always show success state to avoid email enumeration
        reset_sent = True

    return render_template('forgot_password.html', reset_sent=reset_sent)

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = serializer.loads(token, salt='password-reset', max_age=3600)
    except Exception:
        flash('The reset link is invalid or has expired. Please request a new one.', 'danger')
        return redirect(url_for('forgot_password'))

    user = User.query.filter_by(email=email).first()
    if not user:
        flash('Account not found for this reset link.', 'danger')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        password = request.form.get('password') or ''
        confirm = request.form.get('confirm_password') or ''

        if len(password) < 8:
            flash('Password must be at least 8 characters long.', 'danger')
            return redirect(url_for('reset_password', token=token))

        if password != confirm:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('reset_password', token=token))

        user.password = bcrypt.generate_password_hash(password).decode('utf-8')
        db.session.commit()

        flash('Password updated successfully. You can now log in.', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html', token=token)

@app.route('/dashboard')
@login_required
def dashboard():
    hidden_ids = [post.id for post in current_user.hidden_announcements]
    query = Announcement.query.filter(Announcement.is_deleted == False)
    if hidden_ids:
        query = query.filter(Announcement.id.notin_(hidden_ids))
    announcements = query.order_by(Announcement.date_posted.desc()).limit(20).all()
    user_votes = [v.poll_id for v in PollVote.query.filter_by(user_id=current_user.id).all()]
    return render_template('dashboard.html', user=current_user, announcements=announcements, user_votes=user_votes)

@app.route('/hide-post/<int:post_id>')
@login_required
def hide_post(post_id):
    post = Announcement.query.get_or_404(post_id)
    if post not in current_user.hidden_announcements:
        current_user.hidden_announcements.append(post)
        db.session.commit()
        flash('Message dismissed.', 'success')
    return redirect(url_for('dashboard'))

@app.route('/move-to-trash/<int:post_id>')
@login_required
def move_to_trash(post_id):
    if current_user.department not in ['IT', 'HR'] and current_user.role != 'Super Admin':
        return redirect(url_for('dashboard'))
    post = Announcement.query.get_or_404(post_id)
    post.is_deleted = True 
    db.session.commit()
    flash('Moved to Recycle Bin.', 'info')
    return redirect(url_for('dashboard'))

@app.route('/recycle-bin')
@login_required
def recycle_bin():
    if current_user.department not in ['IT', 'HR'] and current_user.role != 'Super Admin':
        return redirect(url_for('dashboard'))
    trash_items = Announcement.query.filter_by(is_deleted=True).order_by(Announcement.date_posted.desc()).all()
    return render_template('recycle_bin.html', user=current_user, trash_items=trash_items)

@app.route('/restore-post/<int:post_id>')
@login_required
def restore_post(post_id):
    if current_user.department not in ['IT', 'HR'] and current_user.role != 'Super Admin':
        return redirect(url_for('dashboard'))
    post = Announcement.query.get_or_404(post_id)
    post.is_deleted = False
    db.session.commit()
    flash('Restored!', 'success')
    return redirect(url_for('recycle_bin'))

@app.route('/permanent-delete/<int:post_id>')
@login_required
def permanent_delete(post_id):
    if current_user.department not in ['IT', 'HR'] and current_user.role != 'Super Admin':
        return redirect(url_for('dashboard'))
    post = Announcement.query.get_or_404(post_id)
    if post.image_file:
        try:
            file_path = os.path.join(app.config['NEWS_FOLDER'], post.image_file)
            if os.path.exists(file_path): os.remove(file_path)
        except: pass
    db.session.delete(post)
    db.session.commit()
    flash('Permanently Deleted.', 'danger')
    return redirect(url_for('recycle_bin'))

@app.route('/empty-trash')
@login_required
def empty_trash():
    if current_user.department not in ['IT', 'HR'] and current_user.role != 'Super Admin':
        return redirect(url_for('dashboard'))
    trash_items = Announcement.query.filter_by(is_deleted=True).all()
    for post in trash_items:
        if post.image_file:
            try:
                file_path = os.path.join(app.config['NEWS_FOLDER'], post.image_file)
                if os.path.exists(file_path): os.remove(file_path)
            except: pass
        db.session.delete(post)
    db.session.commit()
    flash('Bin Emptied.', 'warning')
    return redirect(url_for('recycle_bin'))

@app.route('/news-portal', methods=['GET', 'POST'])
@login_required
def news_portal():
    if current_user.department not in ['IT', 'HR'] and current_user.role != 'Super Admin':
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        title = request.form.get('title')
        body = request.form.get('body')
        category = 'HR' if current_user.department == 'HR' else 'IT'
        allow_download = True if request.form.get('allow_download') else False
        
        image_filename = None
        if 'news_image' in request.files:
            file = request.files['news_image']
            if file.filename != '':
                saved = save_uploaded_file(file, app.config['NEWS_FOLDER'])
                if saved: image_filename = saved
                else:
                    flash('File error.', 'danger')
                    return redirect(url_for('news_portal'))

        post = Announcement(
            title=title,
            body=body,
            category=category,
            author=current_user.fullname,
            image_file=image_filename,
            allow_download=allow_download
        )
        db.session.add(post)
        db.session.commit()

        poll_q = request.form.get('poll_question')
        if poll_q:
            poll = Poll(question=poll_q, announcement_id=post.id)
            db.session.add(poll)
            db.session.commit()
            for opt in request.form.getlist('poll_options'):
                if opt.strip():
                    db.session.add(PollOption(text=opt, poll_id=poll.id))
            db.session.commit()

        flash('News Posted Successfully!', 'success')
        return redirect(url_for('news_portal'))

    return render_template('news_portal.html', user=current_user)

@app.route('/edit-post/<int:post_id>', methods=['POST'])
@login_required
def edit_post(post_id):
    if current_user.department not in ['IT', 'HR'] and current_user.role != 'Super Admin':
        return redirect(url_for('dashboard'))
    post = Announcement.query.get_or_404(post_id)
    post.title = request.form.get('title')
    post.body = request.form.get('body')
    post.allow_download = True if request.form.get('allow_download') else False
    if request.form.get('remove_file'):
        post.image_file = None
    if 'news_image' in request.files:
        file = request.files['news_image']
        if file.filename != '':
            saved = save_uploaded_file(file, app.config['NEWS_FOLDER'])
            if saved:
                post.image_file = saved
    db.session.commit()
    flash('Updated!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/vote/<int:poll_id>/<int:option_id>')
@login_required
def vote(poll_id, option_id):
    if PollVote.query.filter_by(user_id=current_user.id, poll_id=poll_id).first():
        return redirect(url_for('dashboard'))
    db.session.add(PollVote(user_id=current_user.id, poll_id=poll_id))
    PollOption.query.get_or_404(option_id).count += 1
    db.session.commit()
    return redirect(url_for('dashboard'))

@app.route('/directory')
@login_required
def directory():
    return render_template(
        'directory.html',
        user=current_user,
        directory=User.query.order_by(User.fullname).all()
    )

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        current_user.fullname = request.form.get('fullname')
        current_user.phone = request.form.get('phone')
        current_user.branch = request.form.get('branch')
        current_user.department = request.form.get('department')
        if 'profile_pic' in request.files:
            file = request.files['profile_pic']
            if file.filename != '':
                saved = save_uploaded_file(file, app.config['UPLOAD_FOLDER'])
                if saved:
                    current_user.image_file = saved
        db.session.commit()
        return redirect(url_for('profile'))
    image_file = url_for('static', filename='profile_pics/' + current_user.image_file)
    return render_template('profile.html', user=current_user, image_file=image_file)

@app.route('/admin-update-staff', methods=['POST'])
@login_required
def admin_update_staff():
    if current_user.department not in ['IT', 'HR'] and current_user.role != 'Super Admin':
        return redirect(url_for('directory'))
    staff = User.query.get(request.form.get('user_id'))
    if staff:
        staff.position = request.form.get('position')
        staff.department = request.form.get('department')
        staff.branch = request.form.get('branch')
        db.session.commit()
    return redirect(url_for('directory'))

@app.route('/forms')
@login_required
def forms():
    return render_template(
        'forms.html',
        user=current_user,
        forms=Form.query.order_by(Form.category).all()
    )

@app.route('/it-support', methods=['GET', 'POST'])
@login_required
def it_support():
    if request.method == 'POST':
        form_type = request.form.get('form_type')
        if form_type == 'incident':
            db.session.add(IncidentReport(
                agency=request.form.get('agency'),
                issue_category=request.form.get('issue'),
                description=request.form.get('description'),
                reporter_name=request.form.get('reporter_name'),
                contact=request.form.get('contact')
            ))
            db.session.commit()
            flash('Incident Report Submitted!', 'success_modal')
        elif form_type == 'amendment':
            db.session.add(ProfileAmendment(
                fullname=request.form.get('fullname'),
                phone=request.form.get('phone'),
                t24_username=request.form.get('t24_username'),
                agency=request.form.get('agency'),
                request_type=request.form.get('request_type'),
                new_role=request.form.get('new_role'),
                dept_change=request.form.get('dept_change'),
                transfer_location=request.form.get('transfer_location')
            ))
            db.session.commit()
            flash('Request Submitted!', 'success_modal')
        return redirect(url_for('it_support'))
    return render_template('it_support.html', user=current_user)

@app.route('/it-notifications')
@login_required
def it_notifications():
    if current_user.department != 'IT' and current_user.role != 'Super Admin':
        return redirect(url_for('dashboard'))
    return render_template(
        'it_notifications.html',
        user=current_user,
        incidents=IncidentReport.query.order_by(
            IncidentReport.status.desc(),
            IncidentReport.date_submitted.desc()
        ).all(),
        amendments=ProfileAmendment.query.order_by(
            ProfileAmendment.status.desc(),
            ProfileAmendment.date_submitted.desc()
        ).all()
    )

@app.route('/resolve-ticket/<string:type>/<int:id>')
@login_required
def resolve_ticket(type, id):
    if current_user.department != 'IT' and current_user.role != 'Super Admin':
        return redirect(url_for('dashboard'))
    if type == 'incident':
        IncidentReport.query.get_or_404(id).status = 'Resolved'
    elif type == 'amendment':
        ProfileAmendment.query.get_or_404(id).status = 'Resolved'
    db.session.commit()
    return redirect(url_for('it_notifications'))

@app.route('/export-data/<string:type>')
@login_required
def export_data(type):
    if current_user.department not in ['IT', 'HR'] and current_user.role != 'Super Admin':
        return redirect(url_for('dashboard'))
    si = io.StringIO(); cw = csv.writer(si)
    if type == 'incidents':
        records = IncidentReport.query.all()
        cw.writerow(['ID', 'Date', 'Agency', 'Reporter', 'Contact', 'Issue', 'Description', 'Status'])
        for r in records:
            cw.writerow([
                r.id,
                r.date_submitted.strftime('%Y-%m-%d'),
                r.agency,
                r.reporter_name,
                r.contact,
                r.issue_category,
                r.description,
                r.status
            ])
        filename = "IT_Incident_Reports.csv"
    elif type == 'amendments':
        records = ProfileAmendment.query.all()
        cw.writerow(['ID', 'Date', 'Agency', 'Name', 'Phone', 'Username', 'Request Type', 'Details', 'Status'])
        for r in records:
            details = f"{r.new_role or ''} {r.dept_change or ''} {r.transfer_location or ''}".strip()
            cw.writerow([
                r.id,
                r.date_submitted.strftime('%Y-%m-%d'),
                r.agency,
                r.fullname,
                r.phone,
                r.t24_username,
                r.request_type,
                details,
                r.status
            ])
        filename = "T24_Amendment_Requests.csv"
    output = make_response(si.getvalue())
    output.headers["Content-Disposition"] = f"attachment; filename={filename}"
    output.headers["Content-type"] = "text/csv"
    return output

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
