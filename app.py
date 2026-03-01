import base64
import os
import qrcode
import json
import io
import uuid
from urllib.parse import urlparse

from dotenv import load_dotenv
load_dotenv()
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, abort, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from sqlalchemy import func
from PIL import Image as PILImage

# ==================== تهيئة التطبيق الأساسية ====================
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-this-in-production'

from flask_mail import Mail, Message

# إعدادات البريد
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your-email@gmail.com'
app.config['MAIL_PASSWORD'] = 'your-app-password'
mail = Mail(app)

 
    
# ==================== إعدادات المجلدات (يجب أن تكون قبل استخدامها) ====================
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['QR_FOLDER'] = 'static/qrcodes'
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

# التأكد من وجود المجلدات
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['QR_FOLDER'], exist_ok=True)

# ==================== إعدادات قاعدة البيانات (PostgreSQL أو SQLite) ====================
database_url = os.environ.get('DATABASE_URL')
if database_url:
    print("✅ استخدام PostgreSQL مع SSL")
    if database_url.startswith('postgres://'):
        database_url = database_url.replace('postgres://', 'postgresql://', 1)
    if 'sslmode' not in database_url:
        if '?' in database_url:
            database_url += '&sslmode=require'
        else:
            database_url += '?sslmode=require'
    app.config['SQLALCHEMY_DATABASE_URI'] = database_url
else:
    print("✅ استخدام SQLite محلياً للتطوير")
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///gallery.db'

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# ==================== تهيئة Flask extensions ====================
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# ==================== نماذج قاعدة البيانات ====================
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default='viewer')  # admin, editor, viewer
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    slug = db.Column(db.String(100), unique=True)
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    images = db.relationship('Image', backref='category', lazy=True)
    image_url = db.Column(db.String(500))  # ← هذا السطر الجديد
    
class Image(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    filename = db.Column(db.String(500))
    file_size = db.Column(db.Integer)
    mime_type = db.Column(db.String(100))
    image_url = db.Column(db.String(500), nullable=False)
    thumbnail_url = db.Column(db.String(500))
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'))
    views = db.Column(db.Integer, default=0)
    downloads = db.Column(db.Integer, default=0)
    sort_order = db.Column(db.Integer, default=0)
    is_featured = db.Column(db.Boolean, default=False)
    is_published = db.Column(db.Boolean, default=True)
    show_in_carousel = db.Column(db.Boolean, default=False)  # ← حقل جديد للكاروسيل
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, onupdate=datetime.utcnow)
    uploaded_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    image_metadata = db.Column(db.JSON)
    
class SiteSettings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    site_title = db.Column(db.String(200), default='معرض الأعمال')
    site_description = db.Column(db.Text, default='مرحباً بكم في معرض أعمالنا')
    site_logo = db.Column(db.String(500))
    favicon = db.Column(db.String(500))
    contact_email = db.Column(db.String(200))
    social_links = db.Column(db.JSON)
    theme_color = db.Column(db.String(20), default='#667eea')
    qr_code_text = db.Column(db.Text)
    google_analytics_id = db.Column(db.String(50))
    updated_at = db.Column(db.DateTime, onupdate=datetime.utcnow)

class ActivityLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    action = db.Column(db.String(100))
    details = db.Column(db.JSON)
    ip_address = db.Column(db.String(50))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
class ContactMessage(db.Model):
    """نموذج رسائل الاتصال"""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(20))
    subject = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)  # هل تمت قراءتها؟
    is_replied = db.Column(db.Boolean, default=False)  # هل تم الرد عليها؟
    ip_address = db.Column(db.String(50))
    
    def __repr__(self):
        return f'<Message {self.name}: {self.subject}>'

       
# ==================== الدوال المساعدة ====================
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def generate_qr_code(url, size=10):
    """توليد QR Code"""
    qr = qrcode.QRCode(
        version=1,
        box_size=size,
        border=5,
        error_correction=qrcode.constants.ERROR_CORRECT_H
    )
    qr.add_data(url)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    img_io = io.BytesIO()
    img.save(img_io, 'PNG')
    img_io.seek(0)
    img_base64 = base64.b64encode(img_io.getvalue()).decode()
    return img_base64

def create_thumbnail(image_path, size=(300, 300)):
    """إنشاء صورة مصغرة"""
    try:
        img = PILImage.open(image_path)
        img.thumbnail(size, PILImage.Resampling.LANCZOS)
        thumb_path = image_path.replace('.', '_thumb.')
        img.save(thumb_path)
        return thumb_path
    except Exception as e:
        print(f"Error creating thumbnail: {e}")
        return image_path

def log_activity(user_id, action, details=None, ip=None):
    """تسجيل النشاطات"""
    log = ActivityLog(
        user_id=user_id,
        action=action,
        details=details,
        ip_address=ip or request.remote_addr
    )
    db.session.add(log)
    db.session.commit()

# ==================== Google Drive Integration ====================
import json
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload

def get_drive_service():
    """الاتصال بخدمة Google Drive"""
    try:
        credentials_path = 'google-credentials.json'
        if not os.path.exists(credentials_path):
            print("⚠️ ملف google-credentials.json غير موجود")
            return None
        credentials = service_account.Credentials.from_service_account_file(
            credentials_path,
            scopes=['https://www.googleapis.com/auth/drive.file']
        )
        service = build('drive', 'v3', credentials=credentials)
        print("✅ تم الاتصال بـ Google Drive")
        return service
    except Exception as e:
        print(f"❌ خطأ في الاتصال: {e}")
        return None

def upload_to_drive(file_path, filename, folder_id=None):
    """رفع ملف إلى Google Drive"""
    try:
        drive_service = get_drive_service()
        if not drive_service:
            return None
        if not folder_id:
            folder_id = '1AxV1rFoS2KaeyQzFRhlf1rvn1m1_6UEb'  # ⬅️ ضع معرف مجلدك هنا
        file_metadata = {
            'name': filename,
            'parents': [folder_id]
        }
        media = MediaFileUpload(file_path, mimetype='image/jpeg', resumable=True)
        file = drive_service.files().create(
            body=file_metadata,
            media_body=media,
            fields='id'
        ).execute()
        file_id = file.get('id')
        drive_service.permissions().create(
            fileId=file_id,
            body={'type': 'anyone', 'role': 'reader'}
        ).execute()
        direct_link = f"https://drive.google.com/uc?id={file_id}"
        print(f"✅ تم رفع {filename}, ID: {file_id}")
        return direct_link
    except Exception as e:
        print(f"❌ خطأ في رفع {filename}: {e}")
        return None

# ==================== Azure Blob Storage Integration ====================
from azure.storage.blob import BlobServiceClient

AZURE_CONNECTION_STRING = os.environ.get('AZURE_CONNECTION_STRING', '')
AZURE_CONTAINER_NAME = 'gallery-images'

def upload_to_azure(file_path, filename):
    """رفع ملف إلى Azure Blob Storage"""
    try:
        if not AZURE_CONNECTION_STRING:
            print("⚠️ AZURE_CONNECTION_STRING غير موجود")
            return None
        blob_service = BlobServiceClient.from_connection_string(AZURE_CONNECTION_STRING)
        container_client = blob_service.get_container_client(AZURE_CONTAINER_NAME)
        try:
            container_client.get_container_properties()
        except Exception:
            print(f"⚠️ الحاوية {AZURE_CONTAINER_NAME} غير موجودة")
            return None
        blob_name = f"{uuid.uuid4().hex}_{filename}"
        with open(file_path, "rb") as data:
            blob_client = container_client.upload_blob(
                name=blob_name, 
                data=data,
                overwrite=True
            )
        blob_url = f"https://{blob_service.account_name}.blob.core.windows.net/{AZURE_CONTAINER_NAME}/{blob_name}"
        print(f"✅ تم رفع {filename} إلى Azure Blob Storage")
        print(f"🔗 الرابط: {blob_url}")
        return blob_url
    except Exception as e:
        print(f"❌ خطأ في رفع الملف إلى Azure: {e}")
        return None

# ==================== صفحات الاختبار والتشخيص ====================
@app.route('/debug-db')
def debug_db():
    """اختبار الاتصال بقاعدة البيانات"""
    try:
        from sqlalchemy import text
        with app.app_context():
            db.session.execute(text('SELECT 1'))
            db_url = app.config['SQLALCHEMY_DATABASE_URI']
            return f"""
            <h1>✅ الاتصال بقاعدة البيانات ناجح</h1>
            <p>نوع قاعدة البيانات: {'PostgreSQL' if 'postgresql' in db_url else 'SQLite'}</p>
            <p>الرابط: {db_url}</p>
            """
    except Exception as e:
        return f"""
        <h1>❌ فشل الاتصال بقاعدة البيانات</h1>
        <p>الخطأ: {str(e)}</p>
        <p>نوع الخطأ: {type(e).__name__}</p>
        """

@app.route('/check-images')
@login_required
def check_images():
    """فحص الصور في قاعدة البيانات"""
    images = Image.query.all()
    output = "<h1>الصور في قاعدة البيانات</h1><ul>"
    for img in images:
        output += f"<li>{img.id}: {img.title} - المشاهدات: {img.views} - الرابط: {img.image_url}</li>"
    output += "</ul>"
    return output

# ==================== API للمشاهدات ====================
@app.route('/api/view/<int:image_id>', methods=['POST'])
def api_increment_view(image_id):
    """زيادة عدد المشاهدات"""
    image = Image.query.get_or_404(image_id)
    image.views += 1
    db.session.commit()
    return jsonify({'success': True, 'views': image.views})

# ==================== الصفحات العامة ====================
@app.route('/')
def index():
    """الصفحة الرئيسية"""
    page = request.args.get('page', 1, type=int)
    per_page = 12
    category_id = request.args.get('category', type=int)
    featured_only = request.args.get('featured', type=bool)
    search_query = request.args.get('q', '')
    
    # الاستعلام الأساسي للصور
    query = Image.query.filter_by(is_published=True)
    
    if category_id:
        query = query.filter_by(category_id=category_id)
    
    if featured_only:
        query = query.filter_by(is_featured=True)
    
    if search_query:
        query = query.filter(
            db.or_(
                Image.title.contains(search_query),
                Image.description.contains(search_query)
            )
        )
    
    # الصور للصفحة الرئيسية (مع pagination)
    images = query.order_by(Image.sort_order.desc(), Image.created_at.desc())\
                  .paginate(page=page, per_page=per_page, error_out=False)
    
    # صور الكاروسيل (جديد) - نأخذ أول 6 صور
    carousel_images = Image.query.filter_by(
        show_in_carousel=True, 
        is_published=True
    ).order_by(Image.sort_order.asc(), Image.created_at.desc()).limit(6).all()
    
    # الصور المميزة
    featured_images = Image.query.filter_by(
        is_featured=True, 
        is_published=True
    ).order_by(Image.created_at.desc()).limit(6).all()
    
    # التصنيفات
    categories = db.session.query(
        Category, func.count(Image.id).label('image_count')
    ).outerjoin(Image).group_by(Category.id).all()
    
    # إعدادات الموقع
    settings = SiteSettings.query.first()
    if not settings:
        settings = SiteSettings()
        db.session.add(settings)
        db.session.commit()
    
    # QR Code
    current_url = request.host_url
    qr_code = generate_qr_code(current_url)
    
    return render_template('index_advanced.html',
                         images=images,
                         categories=categories,
                         carousel_images=carousel_images,  # ← متغير جديد للكاروسيل
                         featured_images=featured_images,
                         settings=settings,
                         qr_code=qr_code,
                         search_query=search_query,
                         current_category=category_id)

@app.route('/image/<int:image_id>')
def view_image(image_id):
    """عرض صورة واحدة"""
    image = Image.query.get_or_404(image_id)
    image.views += 1
    db.session.commit()
    
    log_activity(
        user_id=current_user.id if current_user.is_authenticated else None,
        action='view_image',
        details={'image_id': image_id, 'title': image.title},
        ip=request.remote_addr
    )
    
    similar_images = Image.query.filter(
        Image.category_id == image.category_id,
        Image.id != image.id,
        Image.is_published == True
    ).limit(4).all()
    
    return render_template('view_image_advanced.html',
                         image=image,
                         similar_images=similar_images)

@app.route('/category/<int:category_id>')
def view_category(category_id):
    """عرض صور التصنيف"""
    category = Category.query.get_or_404(category_id)
    images = Image.query.filter_by(
        category_id=category_id, 
        is_published=True
    ).order_by(Image.created_at.desc()).all()
    
    print(f"Category: {category.name}, Images found: {len(images)}")
    
    return render_template('category.html',
                         category=category,
                         images=images)

@app.route('/search')
def search():
    """بحث متقدم"""
    q = request.args.get('q', '')
    category = request.args.get('category', type=int)
    sort = request.args.get('sort', 'newest')
    
    query = Image.query.filter_by(is_published=True)
    
    if q:
        query = query.filter(
            db.or_(
                Image.title.contains(q),
                Image.description.contains(q)
            )
        )
    
    if category:
        query = query.filter_by(category_id=category)
    
    if sort == 'popular':
        query = query.order_by(Image.views.desc())
    elif sort == 'downloads':
        query = query.order_by(Image.downloads.desc())
    else:
        query = query.order_by(Image.created_at.desc())
    
    images = query.all()
    categories = Category.query.all()
    
    return render_template('search.html',
                         images=images,
                         categories=categories,
                         query=q,
                         selected_category=category,
                         sort=sort)

@app.route('/download/<int:image_id>')
def download_image(image_id):
    """تحميل الصورة"""
    image = Image.query.get_or_404(image_id)
    image.downloads += 1
    db.session.commit()
    return redirect(image.image_url)

# ==================== نظام المصادقة ====================
@app.route('/register', methods=['GET', 'POST'])
def register():
    """تسجيل مستخدم جديد"""
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        if User.query.filter_by(username=username).first():
            flash('اسم المستخدم موجود مسبقاً', 'danger')
            return redirect(url_for('register'))
        
        if User.query.filter_by(email=email).first():
            flash('البريد الإلكتروني موجود مسبقاً', 'danger')
            return redirect(url_for('register'))
        
        user = User(username=username, email=email, role='viewer')
        user.set_password(password)
        
        db.session.add(user)
        db.session.commit()
        
        log_activity(user.id, 'register', {'email': email})
        
        flash('تم التسجيل بنجاح، يمكنك تسجيل الدخول الآن', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """تسجيل الدخول"""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        remember = request.form.get('remember', False)
        
        user = User.query.filter(
            db.or_(User.username == username, User.email == username)
        ).first()
        
        if user and user.check_password(password) and user.is_active:
            login_user(user, remember=remember)
            user.last_login = datetime.utcnow()
            db.session.commit()
            
            log_activity(user.id, 'login', {'ip': request.remote_addr})
            
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('admin_dashboard'))
        else:
            flash('بيانات الدخول غير صحيحة', 'danger')
    
    return render_template('login_advanced.html')

@app.route('/logout')
def logout():
    """تسجيل الخروج"""
    logout_user()
    flash('تم تسجيل الخروج بنجاح', 'success')
    return redirect(url_for('index'))

@app.route('/profile')
@login_required
def profile():
    """صفحة الملف الشخصي"""
    user_activity = ActivityLog.query.filter_by(user_id=current_user.id)\
                                     .order_by(ActivityLog.timestamp.desc())\
                                     .limit(10).all()
    
    user_images = Image.query.filter_by(uploaded_by=current_user.id)\
                             .order_by(Image.created_at.desc())\
                             .limit(12).all()
    
    return render_template('profile.html',
                         user=current_user,
                         activities=user_activity,
                         images=user_images)

@app.route('/profile/edit', methods=['GET', 'POST'])
@login_required
def edit_profile():
    """تعديل الملف الشخصي"""
    if request.method == 'POST':
        current_user.email = request.form['email']
        
        if request.form.get('new_password'):
            if current_user.check_password(request.form['current_password']):
                current_user.set_password(request.form['new_password'])
            else:
                flash('كلمة المرور الحالية غير صحيحة', 'danger')
                return redirect(url_for('edit_profile'))
        
        db.session.commit()
        flash('تم تحديث الملف الشخصي', 'success')
        return redirect(url_for('profile'))
    
    return render_template('edit_profile.html', user=current_user)






# ==================== لوحة التحكم ====================

@app.route('/admin/categories/upload-image/<int:category_id>', methods=['POST'])
@login_required
def upload_category_image(category_id):
    """رفع صورة للتصنيف"""
    category = Category.query.get_or_404(category_id)
    
    if 'image' not in request.files:
        flash('❌ لم يتم اختيار صورة', 'danger')
        return redirect(url_for('manage_categories'))
    
    file = request.files['image']
    if file.filename == '':
        flash('❌ لم يتم اختيار صورة', 'danger')
        return redirect(url_for('manage_categories'))
    
    if file and allowed_file(file.filename):
        # اسم آمن للملف
        filename = secure_filename(file.filename)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        unique_id = uuid.uuid4().hex[:8]
        new_filename = f"category_{unique_id}_{timestamp}_{filename}"
        
        # حفظ مؤقتاً
        temp_path = os.path.join(app.config['UPLOAD_FOLDER'], new_filename)
        file.save(temp_path)
        
        # رفع إلى Azure (إذا كنت تستخدم Azure)
        image_url = upload_to_azure(temp_path, new_filename)
        
        if image_url:
            # حذف الملف المؤقت
            os.remove(temp_path)
            
            # تحديث التصنيف
            category.image_url = image_url
            db.session.commit()
            
            flash('✅ تم رفع صورة التصنيف بنجاح', 'success')
        else:
            flash('❌ فشل رفع الصورة', 'danger')
    else:
        flash('❌ نوع الملف غير مسموح به', 'danger')
    
    return redirect(url_for('manage_categories'))


@app.route('/about')
def about():
    """صفحة من نحن"""
    try:
        settings = SiteSettings.query.first()
        categories = Category.query.all()
        return render_template('about.html', settings=settings, categories=categories)
    except Exception as e:
        print(f"خطأ في صفحة about: {e}")
        return render_template('500.html'), 500

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    """صفحة اتصل بنا - تستقبل الرسائل"""
    settings = SiteSettings.query.first()
    categories = Category.query.all()
    
    if request.method == 'POST':
        try:
            # طباعة البيانات المستلمة للتأكد (في Terminal)
            print("📩 تم استلام طلب POST")
            print(f"البيانات: {request.form}")
            
            # استقبال البيانات من النموذج
            name = request.form.get('name')
            email = request.form.get('email')
            phone = request.form.get('phone')
            subject = request.form.get('subject')
            message = request.form.get('message')
            
            # التحقق من الحقول المطلوبة
            if not name or not email or not subject or not message:
                flash('❌ جميع الحقول المطلوبة يجب أن تمتلئ', 'danger')
                return redirect(url_for('contact'))
            
            # حفظ الرسالة في قاعدة البيانات
            new_message = ContactMessage(
                name=name,
                email=email,
                subject=subject,
                message=message,
                phone=phone,
                ip_address=request.remote_addr
            )
            db.session.add(new_message)
            db.session.commit()
            
            print(f"✅ تم حفظ رسالة جديدة من {name}")
            flash('✅ تم إرسال رسالتك بنجاح. سنتواصل معك قريباً.', 'success')
            
        except Exception as e:
            print(f"❌ خطأ في حفظ الرسالة: {e}")
            flash('❌ حدث خطأ في إرسال الرسالة. حاول مرة أخرى.', 'danger')
            db.session.rollback()
        
        return redirect(url_for('contact'))
    
    return render_template('contact.html', settings=settings, categories=categories)

def send_admin_notification(message):
    """إرسال إشعار بريد إلكتروني للأدمن عند وصول رسالة جديدة"""
    try:
        from flask_mail import Mail, Message
        mail = Mail(app)
        
        admin_email = SiteSettings.query.first().contact_email or 'admin@example.com'
        
        msg = Message(
            subject=f"📬 رسالة جديدة من {message.name}",
            sender=app.config.get('MAIL_USERNAME'),
            recipients=[admin_email]
        )
        msg.body = f"""
        📬 رسالة جديدة من موقع معرض الأعمال
        
        👤 الاسم: {message.name}
        📧 البريد: {message.email}
        📞 الهاتف: {message.phone or 'غير متوفر'}
        📝 الموضوع: {message.subject}
        
        💬 الرسالة:
        {message.message}
        
        🕒 التاريخ: {message.created_at.strftime('%Y-%m-%d %H:%M')}
        """
        mail.send(msg)
    except Exception as e:
        print(f"⚠️ فشل إرسال بريد الإشعار: {e}")

@app.route('/admin/messages')
@login_required
def admin_messages():
    """صفحة إدارة رسائل الاتصال للأدمن"""
    if current_user.role != 'admin':
        abort(403)
    
    # جلب جميع الرسائل مع الترتيب (الأحدث أولاً)
    messages = ContactMessage.query.order_by(ContactMessage.created_at.desc()).all()
    
    # تحديث عدد الرسائل غير المقروءة
    unread_count = ContactMessage.query.filter_by(is_read=False).count()
    
    return render_template('admin_messages.html', 
                         messages=messages, 
                         unread_count=unread_count)

@app.route('/admin/messages/<int:message_id>/read', methods=['POST'])
@login_required
def mark_message_read(message_id):
    """تحديد رسالة كمقروءة"""
    if current_user.role != 'admin':
        abort(403)
    
    message = ContactMessage.query.get_or_404(message_id)
    message.is_read = True
    db.session.commit()
    
    return jsonify({'success': True})
@app.route('/admin/messages/<int:message_id>/delete', methods=['POST'])
@login_required
def delete_message(message_id):
    """حذف رسالة"""
    if current_user.role != 'admin':
        abort(403)
    
    message = ContactMessage.query.get_or_404(message_id)
    db.session.delete(message)
    db.session.commit()
    
    flash('✅ تم حذف الرسالة', 'success')
    return redirect(url_for('admin_messages'))

@app.route('/api/unread-count')
@login_required
def api_unread_count():
    """API للحصول على عدد الرسائل غير المقروءة"""
    count = ContactMessage.query.filter_by(is_read=False).count()
    return jsonify({'count': count})

@app.route('/admin')
@login_required
def admin_dashboard():
    """لوحة التحكم الرئيسية"""
    if current_user.role not in ['admin', 'editor']:
        abort(403)

    today = datetime.utcnow().date()
    stats = {
        'total_images': Image.query.count(),
        'total_categories': Category.query.count(),
        'total_users': User.query.count(),
        'total_views': db.session.query(func.sum(Image.views)).scalar() or 0,
        'total_downloads': db.session.query(func.sum(Image.downloads)).scalar() or 0,
        'images_today': Image.query.filter(func.date(Image.created_at) == today).count(),
        'popular_images': Image.query.order_by(Image.views.desc()).limit(5).all(),
        'recent_activities': ActivityLog.query.order_by(ActivityLog.timestamp.desc()).limit(10).all()
    }
    
    last_week = [(today - timedelta(days=i)).strftime('%Y-%m-%d') for i in range(7, 0, -1)]
    views_data = []
    
    for day in last_week:
        count = ActivityLog.query.filter(
            func.date(ActivityLog.timestamp) == day,
            ActivityLog.action == 'view_image'
        ).count()
        views_data.append(count)
    
    chart_data = {
        'labels': last_week,
        'views': views_data
    }
    
    site_url = request.host_url
    qr_base64 = generate_qr_code(site_url)
    unread_messages_count = ContactMessage.query.filter_by(is_read=False).count()
    return render_template('admin_dashboard_advanced.html',
                     stats=stats,
                     chart_data=json.dumps(chart_data),
                     qr_code=qr_base64,
                     site_url=site_url,
                     unread_messages_count=unread_messages_count)  # هذا السطر الجديد

@app.route('/admin/images')
@login_required
def manage_images():
    """إدارة الصور"""
    page = request.args.get('page', 1, type=int)
    per_page = 12
    images = Image.query.order_by(Image.created_at.desc())\
                        .paginate(page=page, per_page=per_page, error_out=False)
    return render_template('manage_images.html', images=images)

@app.route('/admin/add', methods=['GET', 'POST'])
@login_required
def add_image():
    """إضافة صورة جديدة مع رفع إلى Google Drive"""
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        
        if 'image' not in request.files:
            flash('لم يتم اختيار صورة', 'danger')
            return redirect(request.url)
        
        file = request.files['image']
        if file.filename == '':
            flash('لم يتم اختيار صورة', 'danger')
            return redirect(request.url)
        
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            new_filename = f"{timestamp}_{filename}"
            temp_path = os.path.join(app.config['UPLOAD_FOLDER'], new_filename)
            file.save(temp_path)
            print(f"✅ تم حفظ الملف مؤقتاً: {temp_path}")
            
            drive_url = upload_to_drive(temp_path, new_filename)
            
            if drive_url:
                os.remove(temp_path)
                print(f"✅ تم حذف الملف المؤقت")
                
                new_image = Image(
                    title=title,
                    description=description,
                    filename=new_filename,
                    image_url=drive_url,
                    uploaded_by=current_user.id
                )
                db.session.add(new_image)
                db.session.commit()
                
                flash('✅ تم رفع الصورة إلى Google Drive بنجاح', 'success')
            else:
                flash('❌ فشل رفع الصورة إلى Google Drive', 'danger')
                if os.path.exists(temp_path):
                    os.remove(temp_path)
            
            return redirect(url_for('manage_images'))
    
    categories = Category.query.all()
    return render_template('upload_images.html', categories=categories)

@app.route('/admin/upload', methods=['GET', 'POST'])
@login_required
def upload_images():
    """رفع صور متعدد مع خيارات متقدمة"""
    if request.method == 'POST':
        files = request.files.getlist('images')
        category_id = request.form.get('category_id', type=int)
        is_featured = 'is_featured' in request.form
        show_in_carousel = 'show_in_carousel' in request.form  # جديد
        carousel_order = request.form.get('carousel_order', 0, type=int)  # جديد
        is_published = 'is_published' in request.form
        default_title = request.form.get('title', '')
        default_description = request.form.get('description', '')
        
        uploaded = 0
        failed = 0
        
        for file in files:
            if file and allowed_file(file.filename):
                try:
                    filename = secure_filename(file.filename)
                    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                    unique_id = uuid.uuid4().hex[:8]
                    new_filename = f"{unique_id}_{timestamp}_{filename}"
                    
                    # حفظ مؤقتاً
                    temp_path = os.path.join(app.config['UPLOAD_FOLDER'], new_filename)
                    file.save(temp_path)
                    
                    # إنشاء صورة مصغرة
                    thumb_path = create_thumbnail(temp_path)
                    thumb_filename = os.path.basename(thumb_path)
                    
                    # رفع إلى Azure
                    azure_url = upload_to_azure(temp_path, new_filename)
                    
                    if azure_url:
                        # رفع الصورة المصغرة
                        thumb_azure_url = upload_to_azure(thumb_path, thumb_filename)
                        
                        # حذف الملفات المؤقتة
                        os.remove(temp_path)
                        if os.path.exists(thumb_path):
                            os.remove(thumb_path)
                        
                        # حفظ في قاعدة البيانات مع الخيارات الجديدة
                        new_image = Image(
                            title=default_title or filename,
                            description=default_description,
                            filename=new_filename,
                            image_url=azure_url,
                            thumbnail_url=thumb_azure_url or azure_url,
                            category_id=category_id,
                            is_featured=is_featured,
                            show_in_carousel=show_in_carousel,  # ← جديد
                            sort_order=carousel_order,  # ← جديد (نستخدم sort_order لترتيب الكاروسيل)
                            is_published=is_published,
                            uploaded_by=current_user.id
                        )
                        db.session.add(new_image)
                        uploaded += 1
                    else:
                        failed += 1
                        
                except Exception as e:
                    failed += 1
                    print(f"خطأ في رفع الصورة: {e}")
        
        db.session.commit()
        flash(f'✅ تم رفع {uploaded} صورة بنجاح', 'success')
        if failed:
            flash(f'❌ فشل رفع {failed} صورة', 'warning')
        
        return redirect(url_for('manage_images'))
    
    categories = Category.query.all()
    return render_template('upload_images.html', categories=categories) 


@app.route('/admin/edit/<int:image_id>', methods=['GET', 'POST'])
@login_required
def edit_image(image_id):
    """تعديل صورة"""
    image = Image.query.get_or_404(image_id)
    categories = Category.query.all()
    
    if request.method == 'POST':
        image.title = request.form['title']
        image.description = request.form['description']
        image.category_id = request.form.get('category_id', type=int) or None
        image.is_featured = 'is_featured' in request.form
        image.show_in_carousel = 'show_in_carousel' in request.form  # ← جديد
        image.is_published = 'is_published' in request.form
        image.sort_order = request.form.get('sort_order', 0, type=int)
        
        if 'new_image' in request.files and request.files['new_image'].filename:
            file = request.files['new_image']
            if file and allowed_file(file.filename):
                if image.filename:
                    old_file = os.path.join(app.config['UPLOAD_FOLDER'], image.filename)
                    if os.path.exists(old_file):
                        os.remove(old_file)
                    old_thumb = old_file.replace('.', '_thumb.')
                    if os.path.exists(old_thumb):
                        os.remove(old_thumb)
                
                filename = secure_filename(file.filename)
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                new_filename = f"{timestamp}_{filename}"
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], new_filename)
                file.save(file_path)
                
                thumb_path = create_thumbnail(file_path)
                
                image.filename = new_filename
                image.file_size = os.path.getsize(file_path)
                image.mime_type = file.mimetype
                image.image_url = url_for('static', filename=f'uploads/{new_filename}', _external=True)
                image.thumbnail_url = url_for('static', filename=f'uploads/{os.path.basename(thumb_path)}', _external=True)
        
        image.updated_at = datetime.utcnow()
        db.session.commit()
        
        log_activity(current_user.id, 'edit_image', {'image_id': image.id, 'title': image.title})
        
        flash('✅ تم تحديث الصورة بنجاح', 'success')
        return redirect(url_for('manage_images'))
    
    return render_template('edit_image_advanced.html', 
                         image=image, 
                         categories=categories)

@app.route('/admin/delete/<int:image_id>')
@login_required
def delete_image(image_id):
    """حذف صورة"""
    image = Image.query.get_or_404(image_id)
    
    if image.filename:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], image.filename)
        if os.path.exists(file_path):
            os.remove(file_path)
        thumb_path = file_path.replace('.', '_thumb.')
        if os.path.exists(thumb_path):
            os.remove(thumb_path)
    
    db.session.delete(image)
    db.session.commit()
    
    flash('تم حذف الصورة بنجاح', 'success')
    return redirect(url_for('manage_images'))

@app.route('/admin/images/bulk-action', methods=['POST'])
@login_required
def bulk_action():
    """إجراءات جماعية على الصور"""
    action = request.form.get('action')
    image_ids = request.form.getlist('image_ids[]')
    
    if not image_ids:
        flash('لم يتم اختيار أي صور', 'warning')
        return redirect(url_for('manage_images'))
    
    images = Image.query.filter(Image.id.in_(image_ids)).all()
    
    if action == 'delete':
        for image in images:
            if image.filename:
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], image.filename)
                if os.path.exists(file_path):
                    os.remove(file_path)
                thumb_path = file_path.replace('.', '_thumb.')
                if os.path.exists(thumb_path):
                    os.remove(thumb_path)
            db.session.delete(image)
        flash(f'تم حذف {len(images)} صورة', 'success')
    
    elif action == 'publish':
        for image in images:
            image.is_published = True
        flash(f'تم نشر {len(images)} صورة', 'success')
    
    elif action == 'unpublish':
        for image in images:
            image.is_published = False
        flash(f'تم إلغاء نشر {len(images)} صورة', 'success')
    
    elif action == 'feature':
        for image in images:
            image.is_featured = True
        flash(f'تم تمييز {len(images)} صورة', 'success')
    
    db.session.commit()
    log_activity(current_user.id, 'bulk_action', {'action': action, 'count': len(images)})
    
    return redirect(url_for('manage_images'))

@app.route('/admin/categories')
@login_required
def manage_categories():
    """إدارة التصنيفات"""
    categories = Category.query.all()
    return render_template('manage_categories.html', categories=categories)

@app.route('/admin/categories/add', methods=['POST'])
@login_required
def add_category():
    """إضافة تصنيف"""
    name = request.form['name']
    slug = name.lower().replace(' ', '-')
    category = Category(name=name, slug=slug, description=request.form.get('description', ''))
    db.session.add(category)
    db.session.commit()
    flash('تم إضافة التصنيف بنجاح', 'success')
    return redirect(url_for('manage_categories'))

@app.route('/admin/categories/edit/<int:category_id>', methods=['POST'])
@login_required
def edit_category(category_id):
    """تعديل تصنيف"""
    category = Category.query.get_or_404(category_id)
    category.name = request.form['name']
    category.description = request.form.get('description', '')
    db.session.commit()
    flash('تم تحديث التصنيف', 'success')
    return redirect(url_for('manage_categories'))

@app.route('/admin/categories/delete/<int:category_id>')
@login_required
def delete_category(category_id):
    """حذف تصنيف"""
    category = Category.query.get_or_404(category_id)
    default_category = Category.query.filter_by(name='عام').first()
    if not default_category:
        default_category = Category(name='عام', slug='general')
        db.session.add(default_category)
    for image in category.images:
        image.category_id = default_category.id
    db.session.delete(category)
    db.session.commit()
    flash('تم حذف التصنيف', 'success')
    return redirect(url_for('manage_categories'))

@app.route('/admin/users')
@login_required
def manage_users():
    """إدارة المستخدمين"""
    if current_user.role != 'admin':
        abort(403)
    users = User.query.all()
    return render_template('manage_users.html', users=users)

@app.route('/admin/users/add', methods=['POST'])
@login_required
def add_user():
    """إضافة مستخدم"""
    if current_user.role != 'admin':
        abort(403)
    username = request.form['username']
    email = request.form['email']
    password = request.form['password']
    role = request.form['role']
    
    if User.query.filter_by(username=username).first():
        flash('اسم المستخدم موجود', 'danger')
        return redirect(url_for('manage_users'))
    
    user = User(username=username, email=email, role=role)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    flash('تم إضافة المستخدم', 'success')
    return redirect(url_for('manage_users'))

@app.route('/admin/users/toggle/<int:user_id>')
@login_required
def toggle_user(user_id):
    """تفعيل/تعطيل مستخدم"""
    if current_user.role != 'admin':
        abort(403)
    user = User.query.get_or_404(user_id)
    user.is_active = not user.is_active
    db.session.commit()
    status = 'تفعيل' if user.is_active else 'تعطيل'
    flash(f'تم {status} المستخدم', 'success')
    return redirect(url_for('manage_users'))

# ==================== إعدادات الموقع ====================
@app.route('/admin/settings', methods=['GET', 'POST'])
@login_required
def site_settings():
    """إعدادات الموقع (النصية)"""
    settings = SiteSettings.query.first()
    
    if not settings:
        settings = SiteSettings()
        db.session.add(settings)
        db.session.commit()
    
    if request.method == 'POST':
        print("📝 تم استقبال طلب POST للإعدادات")
        print("📦 البيانات:", request.form)
        
        settings.site_title = request.form.get('site_title', 'معرض الأعمال')
        settings.site_description = request.form.get('site_description', '')
        settings.contact_email = request.form.get('contact_email', '')
        settings.theme_color = request.form.get('theme_color', '#667eea')
        settings.google_analytics_id = request.form.get('google_analytics_id', '')
        
        settings.social_links = {
            'facebook': request.form.get('facebook', ''),
            'twitter': request.form.get('twitter', ''),
            'instagram': request.form.get('instagram', '')
        }
        
        db.session.commit()
        flash('✅ تم حفظ الإعدادات بنجاح', 'success')
        return redirect(url_for('site_settings'))
    
    return render_template('settings_advanced.html', settings=settings)

@app.route('/admin/upload-logo', methods=['POST'])
@login_required
def upload_logo():
    """رفع شعار الموقع"""
    if 'logo' not in request.files:
        flash('❌ لم يتم اختيار ملف', 'danger')
        return redirect(url_for('site_settings'))
    
    file = request.files['logo']
    if file.filename == '':
        flash('❌ لم يتم اختيار ملف', 'danger')
        return redirect(url_for('site_settings'))
    
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        new_filename = f"logo_{timestamp}_{filename}"
        temp_path = os.path.join(app.config['UPLOAD_FOLDER'], new_filename)
        file.save(temp_path)
        
        logo_url = upload_to_azure(temp_path, new_filename)
        
        if logo_url:
            os.remove(temp_path)
            
            settings = SiteSettings.query.first()
            if not settings:
                settings = SiteSettings()
                db.session.add(settings)
            
            settings.site_logo = logo_url
            db.session.commit()
            
            flash('✅ تم رفع الشعار بنجاح', 'success')
        else:
            flash('❌ فشل رفع الشعار', 'danger')
    else:
        flash('❌ نوع الملف غير مسموح به', 'danger')
    
    return redirect(url_for('site_settings'))

# ==================== التحليلات ====================
@app.route('/admin/analytics')
@login_required
def analytics():
    """صفحة التحليلات"""
    try:
        period = request.args.get('period', 'week')
        
        # تحديد الفترة
        if period == 'week':
            days = 7
        elif period == 'month':
            days = 30
        else:
            days = 365
        
        start_date = datetime.utcnow() - timedelta(days=days)
        
        # المشاهدات عبر الزمن (مع التأكد من وجود بيانات)
        views_over_time = []
        try:
            views_over_time = db.session.query(
                func.date(ActivityLog.timestamp).label('date'),
                func.count().label('count')
            ).filter(
                ActivityLog.action == 'view_image',
                ActivityLog.timestamp >= start_date
            ).group_by('date').all()
        except:
            views_over_time = []
        
        # أكثر الصور مشاهدة
        popular_images = Image.query.order_by(Image.views.desc()).limit(10).all()
        
        # أكثر المستخدمين نشاطاً
        active_users = []
        try:
            active_users = db.session.query(
                User.username,
                func.count(ActivityLog.id).label('activity_count')
            ).join(ActivityLog, isouter=True).group_by(User.id).order_by(func.count(ActivityLog.id).desc()).limit(5).all()
        except:
            active_users = []
        
        # إحصائيات سريعة
        stats = {
            'total_views': db.session.query(func.sum(Image.views)).scalar() or 0,
            'total_downloads': db.session.query(func.sum(Image.downloads)).scalar() or 0,
            'total_images': Image.query.count(),
            'total_users': User.query.count()
        }
        
        return render_template('analytics.html',
                             period=period,
                             views_over_time=views_over_time,
                             popular_images=popular_images,
                             active_users=active_users,
                             stats=stats)
    except Exception as e:
        print(f"⚠️ خطأ في التحليلات: {e}")
        flash('حدث خطأ في تحميل التحليلات', 'danger')
        return redirect(url_for('admin_dashboard'))

# ==================== النسخ الاحتياطي ====================
@app.route('/admin/backup')
@login_required
def backup_system():
    """إنشاء نسخة احتياطية"""
    if current_user.role != 'admin':
        abort(403)
    
    backup_data = {
        'timestamp': datetime.utcnow().isoformat(),
        'users': [{'id': u.id, 'username': u.username, 'email': u.email, 'role': u.role} for u in User.query.all()],
        'categories': [{'id': c.id, 'name': c.name, 'description': c.description} for c in Category.query.all()],
        'images_count': Image.query.count(),
        'settings': {
            'site_title': SiteSettings.query.first().site_title if SiteSettings.query.first() else None,
            'site_description': SiteSettings.query.first().site_description if SiteSettings.query.first() else None
        }
    }
    
    backup_file = f"backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    backup_path = os.path.join(app.config['QR_FOLDER'], backup_file)
    
    with open(backup_path, 'w', encoding='utf-8') as f:
        json.dump(backup_data, f, ensure_ascii=False, indent=2)
    
    flash('تم إنشاء النسخة الاحتياطية', 'success')
    return send_file(backup_path, as_attachment=True)

# ==================== QR Code ====================
@app.route('/admin/generate-qr')
@login_required
def admin_generate_qr():
    """توليد QR Code للموقع"""
    site_url = request.host_url
    qr_base64 = generate_qr_code(site_url)
    return render_template('show_qr.html', qr_code=qr_base64, site_url=site_url)

@app.route('/api/generate-qr')
def api_generate_qr():
    """API لتوليد QR Code"""
    site_url = request.host_url
    qr_base64 = generate_qr_code(site_url)
    return jsonify({
        'qr_code': f'data:image/png;base64,{qr_base64}',
        'site_url': site_url
    })

# ==================== API للاستخدام مع AJAX ====================
@app.route('/api/images/featured')
def api_featured_images():
    """API للحصول على الصور المميزة"""
    images = Image.query.filter_by(is_featured=True, is_published=True)\
                        .order_by(Image.created_at.desc())\
                        .limit(6).all()
    return jsonify([{
        'id': img.id,
        'title': img.title,
        'image_url': img.image_url,
        'thumbnail_url': img.thumbnail_url,
        'views': img.views
    } for img in images])

@app.route('/api/images/search')
def api_search():
    """API للبحث"""
    q = request.args.get('q', '')
    if len(q) < 2:
        return jsonify([])
    images = Image.query.filter(
        db.or_(
            Image.title.contains(q),
            Image.description.contains(q)
        ),
        Image.is_published == True
    ).limit(10).all()
    return jsonify([{
        'id': img.id,
        'title': img.title,
        'thumbnail_url': img.thumbnail_url
    } for img in images])

@app.route('/api/analytics/view/<int:image_id>', methods=['POST'])
def track_view(image_id):
    """تتبع المشاهدات عبر API"""
    image = Image.query.get_or_404(image_id)
    image.views += 1
    db.session.commit()
    return jsonify({'success': True})

# ==================== معالجات الأخطاء ====================
@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(403)
def forbidden_error(error):
    return render_template('403.html'), 403

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500


def init_db():
    """تهيئة قاعدة البيانات"""
    with app.app_context():
        print("🔄 جاري إنشاء جداول قاعدة البيانات...")
        db.create_all()
        print("✅ تم إنشاء الجداول بنجاح")
        
        if not User.query.filter_by(username='admin').first():
            admin = User(username='admin', email='admin@example.com', role='admin')
            admin.set_password('admin123')
            db.session.add(admin)
            print("✅ تم إنشاء مستخدم admin افتراضي")
        
        default_categories = ['عام', 'أعمال', 'منتجات', 'فعاليات']
        for cat_name in default_categories:
            if not Category.query.filter_by(name=cat_name).first():
                category = Category(name=cat_name, slug=cat_name.lower().replace(' ', '-'))
                db.session.add(category)
        
        if not SiteSettings.query.first():
            settings = SiteSettings()
            db.session.add(settings)
        
        db.session.commit()
        print("✅ تم تهيئة قاعدة البيانات بنجاح")

# ✅ هذا هو السطر الجديد الذي يجب إضافته
with app.app_context():
    init_db()

# ==================== تشغيل التطبيق ====================
if __name__ == '__main__':
    # init_db()  # يمكنك تعليق أو إزالة هذا السطر الآن
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)