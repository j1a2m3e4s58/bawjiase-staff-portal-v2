import os
import secrets
import csv
import io
import random
import string
from PIL import Image, UnidentifiedImageError
from flask import (
    Flask,
    render_template,
    redirect,
    url_for,
    flash,
    request,
    make_response,
    send_from_directory,
    session,
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    login_required,
    logout_user,
    current_user,
)
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
from datetime import datetime
from dotenv import load_dotenv  # <-- env support
# >>> NEW: import for secure reset tokens
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired  # >>> NEW

load_dotenv()  # load .env

app = Flask(__name__)
app.config['SECRET_KEY'] = 'bawjiase-secure-key-2025'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///bawjiase.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# >>> NEW: salt used for password reset tokens (can also put in .env)
app.config['SECURITY_PASSWORD_SALT'] = os.environ.get(
    'SECURITY_PASSWORD_SALT',
    'bawjiase-reset-salt',
)  # >>> NEW

# EMAIL CONFIG (uses your env vars / Render)
app.config['MAIL_SERVER'] = os.environ.get(
    'MAIL_SERVER',
    'mail.bawjiasearearuralbank.com',
)
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 465))
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get(
    'MAIL_DEFAULT_SENDER',
    'noreply@bawjiasearearuralbank.com',
)

mail = Mail(app)

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

OFFICIAL_EMAIL_DOMAIN = '@bawjiasearearuralbank.com'

# --- ASSOCIATION TABLE ---
hidden_posts = db.Table(
    'hidden_posts',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id')),
    db.Column('announcement_id', db.Integer, db.ForeignKey('announcement.id')),
)

# --- MODELS ---
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    fullname = db.Column(db.String(150), nullable=False)
    phone = db.Column(db.String(20), nullable=False, default="N/A")
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(50), default='General Staff')
    position = db.Column(db.String(100), nullable=True, default='Staff')
    department = db.Column(db.String(100), nullable=False)
    branch = db.Column(db.String(100), nullable=False)
    image_file = db.Column(db.String(20), nullable=False, default='default.jpg')
    is_active_user = db.Column(db.Boolean, default=True)

    # Email verification fields
    is_verified = db.Column(db.Boolean, default=False)
    verification_code = db.Column(db.String(6), nullable=True)

    hidden_announcements = db.relationship(
        'Announcement',
        secondary=hidden_posts,
        backref='hidden_by',
    )

    def get_id(self):
        return str(self.id)

    # >>> NEW: password reset token helpers
    def get_reset_token(self, expires_sec: int = 1800) -> str:
        """
        Generate a signed password reset token valid for expires_sec seconds.
        """
        s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
        return s.dumps(
            {'user_id': self.id},
            salt=app.config['SECURITY_PASSWORD_SALT'],
        )

    @staticmethod
    def verify_reset_token(token: str, max_age: int = 1800):
        """
        Verify a reset token and return the corresponding user or None.
        """
        s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
        try:
            data = s.loads(
                token,
                salt=app.config['SECURITY_PASSWORD_SALT'],
                max_age=max_age,
            )
        except (BadSignature, SignatureExpired):
            return None
        return User.query.get(data.get('user_id'))
    # <<< NEW END


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
    poll = db.relationship(
        'Poll',
        backref='announcement',
        uselist=False,
        cascade="all, delete-orphan",
    )


class Poll(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    question = db.Column(db.String(200), nullable=False)
    announcement_id = db.Column(
        db.Integer,
        db.ForeignKey('announcement.id'),
        nullable=False,
    )
    options = db.relationship(
        'PollOption',
        backref='poll',
        lazy=True,
        cascade="all, delete-orphan",
    )
    votes = db.relationship(
        'PollVote',
        backref='poll',
        lazy=True,
        cascade="all, delete-orphan",
    )


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
def load_user(user_id):
    return db.session.get(User, int(user_id))


@app.context_processor
def inject_notifications():
    if current_user.is_authenticated:
        if current_user.department == 'IT' or current_user.role == 'Super Admin':
            incident_count = IncidentReport.query.filter_by(status='Open').count()
            amendment_count = ProfileAmendment.query.filter_by(status='Open').count()
            return dict(unread_count=incident_count + amendment_count)
    return dict(unread_count=0)


# --- HELPER FUNCTIONS (FILES) ---
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
        except:
            return None
    return None


# --- HELPER FUNCTIONS (EMAIL VERIFICATION) ---
def generate_verification_code(length: int = 6) -> str:
    return ''.join(random.choices(string.digits, k=length))


def send_verification_email(recipient_email: str, code: str):
    subject = "Bawjiase Staff Portal - Email Verification Code"
    body = (
        f"Dear Staff,\n\n"
        f"Your verification code for the Bawjiase Staff Portal is: {code}\n\n"
        f"If you did not try to register for the portal, please ignore this email.\n\n"
        f"Thank you.\n"
        f"Bawjiase Area Rural Bank PLC"
    )
    msg = Message(subject=subject, recipients=[recipient_email])
    msg.body = body
    mail.send(msg)


# >>> NEW: HELPER FUNCTION (PASSWORD RESET EMAIL)
def send_password_reset_email(user: User):  # >>> NEW
    token = user.get_reset_token()
    reset_url = url_for('reset_password', token=token, _external=True)
    subject = "Bawjiase Staff Portal - Password Reset"
    body = (
        f"Dear {user.fullname},\n\n"
        f"You requested to reset your password for the Bawjiase Staff Portal.\n\n"
        f"Please click the link below to set a new password (valid for 30 minutes):\n\n"
        f"{reset_url}\n\n"
        f"If you did not request this, please ignore this email.\n\n"
        f"Thank you.\n"
        f"Bawjiase Area Rural Bank PLC"
    )
    msg = Message(subject=subject, recipients=[user.email])
    msg.body = body
    mail.send(msg)
# <<< NEW END


# --- ROUTES ---
@app.route('/')
def home():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    with app.app_context():
        db.create_all()
    if request.method == 'POST':
        email = (request.form.get('email') or '').lower()
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, request.form.get('password')):
            # Block login if email not verified
            if not user.is_verified:
                flash('Please verify your email first. Check your inbox or spam for the code.', 'warning')
                return redirect(url_for('login'))
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Invalid credentials', 'danger')
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = (request.form.get('email') or '').lower()
        fullname = request.form.get('fullname')
        phone = request.form.get('phone')
        department = request.form.get('department')
        branch = request.form.get('branch')

        # Enforce official email domain on backend as well
        if not email.endswith(OFFICIAL_EMAIL_DOMAIN):
            flash('Please use your official Bawjiase email address.', 'danger')
            return render_template(
                'register.html',
                show_verification=False,
                invalid_code=False,
                email=email,
            )

        # Prevent duplicate email
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('This email is already registered. Please log in.', 'warning')
            return redirect(url_for('login'))

        pw = bcrypt.generate_password_hash(request.form.get('password')).decode('utf-8')

        # Generate verification code and create user as unverified
        code = generate_verification_code()
        user = User(
            fullname=fullname,
            phone=phone,
            email=email,
            password=pw,
            department=department,
            branch=branch,
            is_verified=False,
            verification_code=code,
        )
        db.session.add(user)
        db.session.commit()

        # Remember which user we are verifying
        session['pending_user_id'] = user.id

        try:
            send_verification_email(email, code)
            flash(
                'Registration successful. A verification code has been sent to your inbox or spam.',
                'success',
            )
        except Exception:
            app.logger.exception("Verification email failed")
            flash(
                'Account created but we could not send the verification email. Please contact IT.',
                'danger',
            )

        # Show the verification overlay with email shown
        return render_template(
            'register.html',
            show_verification=True,
            invalid_code=False,
            email=email,
        )

    # GET request
    return render_template(
        'register.html',
        show_verification=False,
        invalid_code=False,
        email='',
    )


@app.route('/verify_email', methods=['POST'])
def verify_email():
    code_entered = (request.form.get('code') or '').strip()
    pending_user_id = session.get('pending_user_id')

    if not pending_user_id:
        flash('No pending registration found. Please register again.', 'warning')
        return redirect(url_for('register'))

    user = User.query.get(pending_user_id)
    if not user:
        flash('User not found. Please register again.', 'danger')
        session.pop('pending_user_id', None)
        return redirect(url_for('register'))

    if user.verification_code == code_entered:
        user.is_verified = True
        user.verification_code = None
        db.session.commit()
        session.pop('pending_user_id', None)

        flash('Email verified successfully. You can now log in.', 'success')
        return redirect(url_for('login'))
    else:
        flash(
            'Incorrect verification code. Please check your inbox or spam and try again.',
            'danger',
        )
        # Re-show verification overlay with error and same email
        return render_template(
            'register.html',
            show_verification=True,
            invalid_code=True,
            email=user.email,
        )


@app.route('/resend_verification', methods=['POST'])
def resend_verification():
    pending_user_id = session.get('pending_user_id')
    if not pending_user_id:
        flash('No pending registration found. Please register again.', 'warning')
        return redirect(url_for('register'))

    user = User.query.get(pending_user_id)
    if not user:
        flash('User not found. Please register again.', 'danger')
        session.pop('pending_user_id', None)
        return redirect(url_for('register'))

    code = generate_verification_code()
    user.verification_code = code
    db.session.commit()

    try:
        send_verification_email(user.email, code)
        flash('A new verification code has been sent to your inbox or spam.', 'success')
    except Exception:
        flash('Could not resend verification email. Please contact IT.', 'danger')

    return render_template(
        'register.html',
        show_verification=True,
        invalid_code=False,
        email=user.email,
    )


@app.route('/change_email', methods=['GET'])
def change_email():
    pending_user_id = session.get('pending_user_id')
    if pending_user_id:
        user = User.query.get(pending_user_id)
        # if not yet verified, you can safely delete so they can start fresh
        if user and not user.is_verified:
            db.session.delete(user)
            db.session.commit()
        session.pop('pending_user_id', None)
    # Send them back to a fresh registration form
    return redirect(url_for('register'))


# forgot-password with POST and success flag
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    success = False
    if request.method == 'POST':
        email = (request.form.get('email') or '').strip().lower()

        # enforce official domain for reset as well
        if not email.endswith(OFFICIAL_EMAIL_DOMAIN):
            flash('Please enter your official Bawjiase staff email.', 'danger')
            return render_template('forgot_password.html', success=False)

        user = User.query.filter_by(email=email).first()

        if user:
            try:
                send_password_reset_email(user)
            except Exception:
                flash('We could not send the reset email. Please contact IT.', 'danger')
                return render_template('forgot_password.html', success=False)

        # Always show generic success message
        success = True
        flash('If an account with that email exists, a reset link has been sent.', 'success')

    return render_template('forgot_password.html', success=success)


# reset-password route
@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    user = User.verify_reset_token(token)
    if user is None:
        flash('That reset link is invalid or has expired. Please request a new one.', 'danger')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        password = (request.form.get('password') or '').strip()
        confirm_password = (request.form.get('confirm_password') or '').strip()

        if not password or not confirm_password:
            flash('Please fill in all password fields.', 'danger')
            return render_template('reset_password.html', token=token)

        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('reset_password.html', token=token)

        if len(password) < 8:
            flash('Password must be at least 8 characters long.', 'danger')
            return render_template('reset_password.html', token=token)

        hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
        user.password = hashed_pw
        db.session.commit()

        flash('Your password has been updated. You can now log in.', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html', token=token)


# simple test-mail route for debugging SMTP on Render
@app.route('/test-mail')
def test_mail():
    """Simple route to test SMTP configuration."""
    try:
        # TODO: change this to an email you can receive
        recipient = "your-email@bawjiasearearuralbank.com"

        msg = Message(
            subject="TEST EMAIL - BARB Staff Portal (Render)",
            recipients=[recipient],
        )
        msg.body = "If you see this message, SMTP from Render is working."

        mail.send(msg)
        return f"Test email sent to {recipient}"
    except Exception as e:
        app.logger.exception("Test email failed")
        return f"Error while sending test email: {e}", 500


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
            if os.path.exists(file_path):
                os.remove(file_path)
        except:
            pass
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
                if os.path.exists(file_path):
                    os.remove(file_path)
            except:
                pass
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
                if saved:
                    image_filename = saved
                else:
                    flash('File error.', 'danger')
                    return redirect(url_for('news_portal'))

        post = Announcement(
            title=title,
            body=body,
            category=category,
            author=current_user.fullname,
            image_file=image_filename,
            allow_download=allow_download,
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
        directory=User.query.order_by(User.fullname).all(),
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
    return render_template('forms.html', user=current_user, forms=Form.query.order_by(Form.category).all())


@app.route('/it-support', methods=['GET', 'POST'])
@login_required
def it_support():
    if request.method == 'POST':
        form_type = request.form.get('form_type')
        if form_type == 'incident':
            db.session.add(
                IncidentReport(
                    agency=request.form.get('agency'),
                    issue_category=request.form.get('issue'),
                    description=request.form.get('description'),
                    reporter_name=request.form.get('reporter_name'),
                    contact=request.form.get('contact'),
                )
            )
            db.session.commit()
            flash('Incident Report Submitted!', 'success_modal')
        elif form_type == 'amendment':
            db.session.add(
                ProfileAmendment(
                    fullname=request.form.get('fullname'),
                    phone=request.form.get('phone'),
                    t24_username=request.form.get('t24_username'),
                    agency=request.form.get('agency'),
                    request_type=request.form.get('request_type'),
                    new_role=request.form.get('new_role'),
                    dept_change=request.form.get('dept_change'),
                    transfer_location=request.form.get('transfer_location'),
                )
            )
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
            IncidentReport.date_submitted.desc(),
        ).all(),
        amendments=ProfileAmendment.query.order_by(
            ProfileAmendment.status.desc(),
            ProfileAmendment.date_submitted.desc(),
        ).all(),
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
    si = io.StringIO()
    cw = csv.writer(si)
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
                r.status,
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
                r.status,
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
