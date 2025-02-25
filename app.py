import os
import io
import socket
import qrcode
import pytz
import logging
from datetime import datetime, timedelta
from flask import Flask, render_template, redirect, url_for, request, flash, send_file, abort, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, current_user, login_required, UserMixin, fresh_login_required
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from sqlalchemy import or_
import re

# Load biến môi trường từ file .env
load_dotenv()

# Cấu hình ứng dụng
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your_secret_key_should_be_very_long_and_secure')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URI', 'sqlite:///app.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)  # Thời gian lưu session
app.config['REMEMBER_COOKIE_DURATION'] = timedelta(days=30)  # Thời gian remember me
@app.template_filter('nl2br')
def nl2br_filter(text):
    if text:
        return text.replace('\n', '<br>')
    return ''
# Cấu hình logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('app.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Khởi tạo các extension
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Vui lòng đăng nhập để truy cập trang này.'
login_manager.login_message_category = 'warning'
csrf = CSRFProtect(app)

# Định nghĩa các vai trò
ROLE_USER = 'user'
ROLE_MANAGER = 'manager'
ROLE_ADMIN = 'admin'

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=True)
    password_hash = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(50), default=ROLE_USER)
    is_approved = db.Column(db.Boolean, default=False)
    approved_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    full_name = db.Column(db.String(150), nullable=True)
    employee_code = db.Column(db.String(50), unique=True, nullable=True)
    date_created = db.Column(db.DateTime, default=datetime.now)
    last_login = db.Column(db.DateTime, nullable=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date_entry = db.Column(db.DateTime, nullable=False)
    product_code = db.Column(db.String(50), unique=True, nullable=False)
    product_name = db.Column(db.String(150), nullable=False)
    serial_number = db.Column(db.String(150), unique=True, nullable=False)
    date_issue = db.Column(db.Date, nullable=False)
    department = db.Column(db.String(150), nullable=False)
    status = db.Column(db.String(50), nullable=False)
    qr_code_data = db.Column(db.LargeBinary)
    qr_url = db.Column(db.String(500))
    entered_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    entered_by_user = db.relationship('User', foreign_keys=[entered_by])
    notes = db.Column(db.Text, nullable=True)
    last_updated = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now)

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.now)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    action = db.Column(db.String(50), nullable=False)
    details = db.Column(db.Text, nullable=True)
    ip_address = db.Column(db.String(50), nullable=True)
    
    user = db.relationship('User', foreign_keys=[user_id])

# Helpers
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.context_processor
def utility_processor():
    def get_approver(approver_id):
        return User.query.get(approver_id)
    return dict(get_approver=get_approver, now=datetime.now())

def generate_product_code():
    return "SP" + datetime.now().strftime("%Y%m%d%H%M%S")

def log_audit(action, details=None):
    if current_user.is_authenticated:
        log = AuditLog(
            user_id=current_user.id,
            action=action,
            details=details,
            ip_address=request.remote_addr
        )
        db.session.add(log)
        db.session.commit()

def is_safe_url(target):
    ref_url = request.host_url
    test_url = target.replace(ref_url, '') if target.startswith(ref_url) else target
    return not test_url.startswith('//')

def is_valid_password(password):
    # Kiểm tra mật khẩu có ít nhất 8 ký tự, bao gồm chữ hoa, chữ thường, số và ký tự đặc biệt
    if len(password) < 8:
        return False
    if not re.search(r'[A-Z]', password):
        return False
    if not re.search(r'[a-z]', password):
        return False
    if not re.search(r'[0-9]', password):
        return False
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False
    return True

# Middleware
@app.before_request
def log_request_info():
    app.logger.info(f"Request: {request.method} {request.path} from {request.remote_addr}")

# Error handlers
@app.errorhandler(404)
def page_not_found(e):
    return render_template('errors/404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('errors/500.html'), 500

@app.errorhandler(403)
def forbidden(e):
    return render_template('errors/403.html'), 403

# Routes
@app.route('/')
def index():
    # Nếu chưa đăng nhập, chuyển sang trang đăng nhập
    if not current_user.is_authenticated:
        return redirect(url_for('login'))

    # Lấy tham số GET
    page = request.args.get('page', 1, type=int)
    search = request.args.get('search', '')
    status_filter = request.args.get('status', '')
    department_filter = request.args.get('department', '')

    # Tạo query gốc
    query = Product.query

    # Tìm kiếm theo tên, mã sản phẩm hoặc số seri (không phân biệt hoa thường)
    if search:
        query = query.filter(
            or_(
                Product.product_name.ilike(f'%{search}%'),
                Product.product_code.ilike(f'%{search}%'),
                Product.serial_number.ilike(f'%{search}%')
            )
        )

    # Lọc theo tình trạng nếu có chọn
    if status_filter:
        query = query.filter(Product.status == status_filter)
        
    # Lọc theo bộ phận nếu có chọn
    if department_filter:
        query = query.filter(Product.department == department_filter)

    # Lấy danh sách tất cả các bộ phận để hiển thị trong dropdown filter
    departments = db.session.query(Product.department).distinct().all()
    department_list = [d[0] for d in departments]

    # Phân trang (mỗi trang 10 sản phẩm)
    products = query.order_by(Product.id.desc()).paginate(page=page, per_page=10)

    # Tính số liệu thống kê toàn cục (không phụ thuộc tìm kiếm/lọc)
    total_products = Product.query.count()
    running_count = Product.query.filter_by(status='chạy tốt').count()
    repairing_count = Product.query.filter_by(status='đang sửa').count()
    broken_count = Product.query.filter_by(status='hỏng').count()

    return render_template(
        'index.html',
        products=products,
        search=search,
        status_filter=status_filter,
        department_filter=department_filter,
        departments=department_list,
        total_products=total_products,
        running_count=running_count,
        repairing_count=repairing_count,
        broken_count=broken_count
    )

@app.route('/edit_product/<int:product_id>', methods=['GET', 'POST'])
@login_required
def edit_product(product_id):
    if current_user.role not in [ROLE_MANAGER, ROLE_ADMIN]:
        flash("Bạn không có quyền chỉnh sửa sản phẩm.", "danger")
        return redirect(url_for('index'))
        
    product = Product.query.get_or_404(product_id)
    
    if request.method == 'POST':
        try:
            old_values = {
                'product_name': product.product_name,
                'serial_number': product.serial_number,
                'date_issue': product.date_issue,
                'department': product.department,
                'status': product.status,
                'notes': product.notes
            }
            
            product.product_name = request.form['product_name']
            product.serial_number = request.form['serial_number']
            product.date_issue = datetime.strptime(request.form['date_issue'], '%Y-%m-%d').date()
            product.department = request.form['department']
            product.status = request.form['status']
            product.notes = request.form.get('notes', '')
            product.last_updated = datetime.now()
            
            db.session.commit()
            
            # Ghi nhật ký
            changes = []
            for key, old_value in old_values.items():
                new_value = getattr(product, key)
                if old_value != new_value:
                    changes.append(f"{key}: {old_value} -> {new_value}")
                    
            if changes:
                log_audit(
                    'edit_product',
                    f"Chỉnh sửa sản phẩm ID: {product.id}, Mã SP: {product.product_code}. Thay đổi: {', '.join(changes)}"
                )
            
            flash('Cập nhật sản phẩm thành công!', 'success')
            return redirect(url_for('product_detail', product_id=product.id))
        except Exception as e:
            db.session.rollback()
            flash(f'Có lỗi xảy ra khi cập nhật sản phẩm: {str(e)}', 'danger')
            app.logger.error(f"Lỗi cập nhật sản phẩm: {e}")
            
    return render_template('edit_product.html', product=product)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form.get('email')
        password = request.form['password']
        confirm_password = request.form.get('confirm_password')
        full_name = request.form.get('full_name')
        employee_code = request.form.get('employee_code')
        
        # Kiểm tra username
        if len(username) < 4:
            flash('Tên đăng nhập phải có ít nhất 4 ký tự.', 'danger')
            return redirect(url_for('register'))
            
        # Kiểm tra email hợp lệ (nếu có)
        if email and not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            flash('Email không hợp lệ.', 'danger')
            return redirect(url_for('register'))
        
        # Kiểm tra mật khẩu
        if not is_valid_password(password):
            flash('Mật khẩu phải có ít nhất 8 ký tự, bao gồm chữ hoa, chữ thường, số và ký tự đặc biệt.', 'danger')
            return redirect(url_for('register'))
            
        # Kiểm tra mật khẩu xác nhận
        if password != confirm_password:
            flash('Mật khẩu xác nhận không khớp.', 'danger')
            return redirect(url_for('register'))
            
        # Kiểm tra username đã tồn tại
        if User.query.filter_by(username=username).first():
            flash('Tên đăng nhập đã tồn tại.', 'danger')
            return redirect(url_for('register'))
            
        # Kiểm tra email đã tồn tại (nếu có)
        if email and User.query.filter_by(email=email).first():
            flash('Email đã được sử dụng.', 'danger')
            return redirect(url_for('register'))
            
        # Kiểm tra mã nhân viên đã tồn tại (nếu có)
        if employee_code and User.query.filter_by(employee_code=employee_code).first():
            flash('Mã nhân viên đã tồn tại.', 'danger')
            return redirect(url_for('register'))
        
        try:
            user = User(
                username=username,
                email=email,
                full_name=full_name,
                employee_code=employee_code,
                date_created=datetime.now()
            )
            user.set_password(password)
            user.is_approved = False
            db.session.add(user)
            db.session.commit()
            
            flash('Đăng ký thành công. Vui lòng chờ người quản lý phê duyệt.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash(f'Đã xảy ra lỗi: {str(e)}', 'danger')
            app.logger.error(f"Lỗi đăng ký: {e}")
            
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
        
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        remember = 'remember' in request.form
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            if not user.is_approved:
                flash('Tài khoản chưa được phê duyệt.', 'warning')
                return redirect(url_for('login'))
                
            login_user(user, remember=remember)
            
            # Cập nhật thời gian đăng nhập cuối
            user.last_login = datetime.now()
            db.session.commit()
            
            # Ghi nhật ký
            log_audit('login', f"Đăng nhập thành công")
            
            flash('Đăng nhập thành công.', 'success')
            
            next_page = request.args.get('next')
            if next_page and is_safe_url(next_page):
                return redirect(next_page)
            else:
                return redirect(url_for('index'))
        else:
            flash('Sai thông tin đăng nhập.', 'danger')
            
        # Ghi nhật ký đăng nhập thất bại
        if user:
            app.logger.warning(f"Đăng nhập thất bại cho user: {username} từ IP: {request.remote_addr}")
            
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    log_audit('logout', "Đăng xuất")
    logout_user()
    flash('Đăng xuất thành công.', 'success')
    return redirect(url_for('login'))

# Định nghĩa thứ tự quyền (role_order) để so sánh cấp bậc
role_order = {"user": 1, "manager": 2, "admin": 3}

@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin_panel():
    # Chỉ admin và manager được truy cập trang quản trị
    if current_user.role not in [ROLE_MANAGER, ROLE_ADMIN]:
        flash('Bạn không có quyền truy cập trang quản trị.', 'danger')
        return redirect(url_for('index'))

    # Lấy số trang cho các tab
    pending_page = request.args.get('pending_page', 1, type=int)
    approved_page = request.args.get('approved_page', 1, type=int)
    admin_users_page = request.args.get('admin_users_page', 1, type=int)
    
    # Tab mặc định
    default_tab = request.args.get('tab', '#pending')

    # Query & phân trang cho 3 nhóm user:
    pending_users_paginated = User.query.filter_by(is_approved=False)\
        .order_by(User.id.desc())\
        .paginate(page=pending_page, per_page=10)

    approved_users_paginated = User.query.filter(
        User.is_approved == True,
        User.role == ROLE_USER
    ).order_by(User.id.desc())\
     .paginate(page=approved_page, per_page=10)

    admin_users_paginated = User.query.filter(
        User.role.in_([ROLE_MANAGER, ROLE_ADMIN])
    ).order_by(User.id.desc())\
     .paginate(page=admin_users_page, per_page=10)
     
    # Lấy dữ liệu cho tab Audit Log
    audit_page = request.args.get('audit_page', 1, type=int)
    audit_logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).paginate(page=audit_page, per_page=20)

    if request.method == 'POST':
        user_id = request.form.get('user_id')
        action = request.form.get('action')
        current_tab = request.form.get('current_tab', '#pending')
        user = User.query.get(user_id)
        
        if user:
            if action == 'approve':
                # Manager chỉ phê duyệt nếu tài khoản là user (pending)
                if current_user.role == ROLE_MANAGER and user.role != ROLE_USER:
                    flash("Manager chỉ có thể phê duyệt tài khoản user.", "warning")
                else:
                    user.is_approved = True
                    user.approved_by = current_user.id
                    log_audit('approve_user', f"Phê duyệt tài khoản: {user.username}")
                    flash("Tài khoản đã được phê duyệt.", "success")
                    
            elif action == 'delete':
                if user.id == current_user.id:
                    flash("Bạn không thể xóa tài khoản của chính mình.", "danger")
                    return redirect(url_for('admin_panel', 
                                            pending_page=pending_page,
                                            approved_page=approved_page,
                                            admin_users_page=admin_users_page, 
                                            tab=current_tab))
                # Chỉ xóa được nếu user mục tiêu có cấp bậc thấp hơn
                elif role_order[current_user.role] > role_order[user.role]:
                    username = user.username
                    db.session.delete(user)
                    log_audit('delete_user', f"Xóa tài khoản: {username}")
                    flash("Tài khoản đã được xóa.", "success")
                else:
                    flash("Không được phép xóa tài khoản cùng cấp hoặc cao hơn.", "danger")
                    
            elif action == 'update_role':
                # Chỉ admin mới có quyền cập nhật role
                if current_user.role != ROLE_ADMIN:
                    flash("Chỉ admin có quyền cập nhật role.", "warning")
                else:
                    new_role = request.form.get('new_role')
                    if new_role not in [ROLE_USER, ROLE_MANAGER, ROLE_ADMIN]:
                        flash("Giá trị role không hợp lệ.", "danger")
                    else:
                        # Không cho admin thay đổi role của admin khác (cùng cấp)
                        if user.role == ROLE_ADMIN and user.id != current_user.id:
                            flash("Không thể thay đổi role của admin khác.", "warning")
                        elif new_role == ROLE_ADMIN and user.id != current_user.id:
                            user.role = new_role
                            user.approved_by = current_user.id
                            log_audit('change_role', f"Thay đổi quyền cho {user.username}: {user.role} -> {new_role}")
                            flash(f"Đã cập nhật role của {user.username} thành {new_role}.", "success")
                        else:
                            # Cập nhật role
                            old_role = user.role
                            user.role = new_role
                            user.approved_by = current_user.id
                            log_audit('change_role', f"Thay đổi quyền cho {user.username}: {old_role} -> {new_role}")
                            flash(f"Đã cập nhật role của {user.username} thành {new_role}.", "success")
                            
            elif action == 'reset_password':
                if current_user.role != ROLE_ADMIN and user.id != current_user.id:
                    flash("Bạn không có quyền đặt lại mật khẩu cho tài khoản này.", "danger")
                else:
                    # Tạo mật khẩu ngẫu nhiên
                    import secrets
                    import string
                    alphabet = string.ascii_letters + string.digits + '!@#$%^&*()'
                    new_password = ''.join(secrets.choice(alphabet) for i in range(12))
                    
                    user.set_password(new_password)
                    log_audit('reset_password', f"Đặt lại mật khẩu cho {user.username}")
                    
                    flash(f"Đã đặt lại mật khẩu cho {user.username}. Mật khẩu mới: {new_password}", "success")
            
            db.session.commit()

        return redirect(url_for('admin_panel', 
                                pending_page=pending_page,
                                approved_page=approved_page,
                                admin_users_page=admin_users_page,
                                audit_page=audit_page,
                                tab=current_tab))

    return render_template(
        'admin.html',
        pending_users=pending_users_paginated,
        approved_users=approved_users_paginated,
        admin_users=admin_users_paginated,
        audit_logs=audit_logs,
        default_tab=default_tab
    )

@app.route('/add_product', methods=['GET', 'POST'])
@login_required
def add_product():
    if current_user.role not in [ROLE_MANAGER, ROLE_ADMIN]:
         flash("Bạn không có quyền truy cập trang thêm sản phẩm.", "danger")
         return redirect(url_for('index'))
         
    if request.method == 'POST':
        vietnam_tz = pytz.timezone('Asia/Ho_Chi_Minh')
        date_entry = datetime.now(vietnam_tz)
        product_code = generate_product_code()
        product_name = request.form['product_name']
        serial_number = request.form['serial_number']
        
        # Kiểm tra serial number đã tồn tại
        if Product.query.filter_by(serial_number=serial_number).first():
            flash('Số seri đã tồn tại.', 'danger')
            return redirect(url_for('add_product'))
        
        try:
            date_issue = datetime.strptime(request.form['date_issue'], '%Y-%m-%d').date()
        except ValueError:
            flash('Ngày cấp không hợp lệ.', 'danger')
            return redirect(url_for('add_product'))
            
        department = request.form['department']
        status = request.form['status']
        notes = request.form.get('notes', '')
        
        try:
            product = Product(
                date_entry=date_entry,
                product_code=product_code,
                product_name=product_name, 
                serial_number=serial_number,
                date_issue=date_issue, 
                department=department, 
                status=status,
                notes=notes,
                entered_by=current_user.id
            )
            db.session.add(product)
            db.session.flush()
            
            # Tạo QR code
            base_url = request.url_root.rstrip('/')
            qr_url = f"{base_url}/product/{product.id}"
            product.qr_url = qr_url
            
            try:
                qr = qrcode.QRCode(version=1, box_size=10, border=5)
                qr.add_data(qr_url)
                qr.make(fit=True)
                img = qr.make_image(fill='black', back_color='white')
                buf = io.BytesIO()
                img.save(buf, format='PNG')
                product.qr_code_data = buf.getvalue()
            except Exception as e:
                app.logger.error(f"Lỗi tạo QR code: {e}")
                flash("Có lỗi xảy ra khi tạo QR code.", "warning")
                
            db.session.commit()
            
            # Ghi nhật ký
            log_audit('add_product', f"Thêm sản phẩm mới: {product_name}, Mã SP: {product_code}")
            
            flash('Sản phẩm đã được thêm thành công!', 'success')
            return redirect(url_for('product_detail', product_id=product.id))
            
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Lỗi thêm sản phẩm: {e}")
            flash(f"Có lỗi xảy ra khi thêm sản phẩm: {str(e)}", "danger")
            
    return render_template('add_product.html')

@app.route('/product/<int:product_id>')
def product_detail(product_id):
    product = Product.query.get_or_404(product_id)
    return render_template('product_detail.html', product=product)

@app.route('/qr/<int:product_id>')
def get_qr(product_id):
    product = Product.query.get_or_404(product_id)
    if not product.qr_code_data:
        abort(404)
    return send_file(io.BytesIO(product.qr_code_data), mimetype='image/png')

@app.route('/print/<int:product_id>')
@login_required
def print_product(product_id):
    product = Product.query.get_or_404(product_id)
    return render_template('print_product.html', product=product)

@app.route('/scan_qr', methods=['GET', 'POST'])
def scan_qr():
    product = None
    error = None
    if request.method == 'POST':
        qr_content = request.form['qr_content']
        
        # Kiểm tra xem qr_content có phải là URL sản phẩm không
        if '/product/' in qr_content:
            try:
                product_id = int(qr_content.split('/product/')[-1])
                product = Product.query.get(product_id)
            except (ValueError, IndexError):
                pass
        
        # Nếu không tìm được, thử tìm theo mã sản phẩm
        if not product:
            product = Product.query.filter(
                or_(
                    Product.product_code.ilike(f"%{qr_content}%"),
                    Product.serial_number.ilike(f"%{qr_content}%")
                )
            ).first()
        
        if not product:
            error = 'Không tìm thấy sản phẩm với mã QR này.'
            
    return render_template('scan_qr.html', product=product, error=error)

@app.route('/delete_product/<int:product_id>', methods=['POST'])
@login_required
def delete_product(product_id):
    if current_user.role not in [ROLE_MANAGER, ROLE_ADMIN]:
        flash("Bạn không có quyền xóa sản phẩm.", "danger")
        return redirect(url_for('index'))
        
    product = Product.query.get_or_404(product_id)
    
    try:
        product_name = product.product_name
        product_code = product.product_code
        db.session.delete(product)
        db.session.commit()
        
        # Ghi nhật ký
        log_audit('delete_product', f"Xóa sản phẩm: {product_name}, Mã SP: {product_code}")
        
        flash('Sản phẩm đã được xóa thành công!', 'success')
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Lỗi xóa sản phẩm: {e}")
        flash(f"Có lỗi xảy ra khi xóa sản phẩm: {str(e)}", "danger")
        
    return redirect(url_for('index'))

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'update_profile':
            current_user.full_name = request.form.get('full_name')
            current_user.email = request.form.get('email')
            
            try:
                db.session.commit()
                flash('Thông tin hồ sơ đã được cập nhật thành công!', 'success')
                log_audit('update_profile', f"Cập nhật thông tin hồ sơ")
            except Exception as e:
                db.session.rollback()
                flash(f'Có lỗi xảy ra: {str(e)}', 'danger')
                
        elif action == 'change_password':
            current_password = request.form.get('current_password')
            new_password = request.form.get('new_password')
            confirm_password = request.form.get('confirm_password')
            
            if not current_user.check_password(current_password):
                flash('Mật khẩu hiện tại không đúng.', 'danger')
            elif new_password != confirm_password:
                flash('Mật khẩu mới và xác nhận không khớp.', 'danger')
            elif not is_valid_password(new_password):
                flash('Mật khẩu mới phải có ít nhất 8 ký tự, bao gồm chữ hoa, chữ thường, số và ký tự đặc biệt.', 'danger')
            else:
                current_user.set_password(new_password)
                try:
                    db.session.commit()
                    flash('Mật khẩu đã được thay đổi thành công!', 'success')
                    log_audit('change_password', "Thay đổi mật khẩu")
                except Exception as e:
                    db.session.rollback()
                    flash(f'Có lỗi xảy ra: {str(e)}', 'danger')
    
    return render_template('profile.html')

@app.route('/api/check_serial', methods=['POST'])
@login_required
def check_serial():
    serial = request.form.get('serial')
    product_id = request.form.get('product_id')
    
    query = Product.query.filter_by(serial_number=serial)
    
    # Nếu đang chỉnh sửa sản phẩm, loại trừ sản phẩm hiện tại
    if product_id:
        query = query.filter(Product.id != int(product_id))
        
    existing_product = query.first()
    
    if existing_product:
        return jsonify(valid=False, message="Số seri này đã tồn tại.")
    else:
        return jsonify(valid=True)

@app.route('/export_qr/<int:product_id>')
@login_required
def export_qr(product_id):
    product = Product.query.get_or_404(product_id)
    if not product.qr_code_data:
        abort(404)
        
    response = make_response(product.qr_code_data)
    response.headers.set('Content-Type', 'image/png')
    response.headers.set('Content-Disposition', 'attachment', 
                         filename=f'qr_{product.product_code}.png')
    return response

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role not in [ROLE_MANAGER, ROLE_ADMIN]:
        flash("Bạn không có quyền truy cập trang thống kê.", "danger")
        return redirect(url_for('index'))
        
    # Thống kê tổng quan
    total_products = Product.query.count()
    running_count = Product.query.filter_by(status='chạy tốt').count()
    repairing_count = Product.query.filter_by(status='đang sửa').count()
    broken_count = Product.query.filter_by(status='hỏng').count()
    
    # Số lượng sản phẩm theo bộ phận
    departments = db.session.query(
        Product.department, 
        db.func.count(Product.id).label('count')
    ).group_by(Product.department).all()
    
    # Số lượng sản phẩm theo tháng
    monthly_data = db.session.query(
        db.func.strftime('%Y-%m', Product.date_entry).label('month'), 
        db.func.count(Product.id).label('count')
    ).group_by('month').order_by('month').all()
    
    # Người dùng mới đăng ký trong tháng
    new_users = User.query.filter(
        db.func.strftime('%Y-%m', User.date_created) == db.func.strftime('%Y-%m', datetime.now())
    ).count()
    
    # Người dùng hoạt động trong 24h qua
    active_users = User.query.filter(
        User.last_login > datetime.now() - timedelta(days=1)
    ).count()
    
    return render_template(
        'dashboard.html',
        total_products=total_products,
        running_count=running_count,
        repairing_count=repairing_count,
        broken_count=broken_count,
        departments=departments,
        monthly_data=monthly_data,
        new_users=new_users,
        active_users=active_users
    )

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        
        # Kiểm tra xem có admin mặc định chưa
        if not User.query.filter_by(username='huy04082000@gmail.com').first():
            admin = User(
                username='huy04082000@gmail.com', 
                email='huy04082000@gmail.com',
                role=ROLE_ADMIN, 
                is_approved=True, 
                full_name="Quản trị viên hệ thống", 
                employee_code="ADMIN001"
            )
            admin.set_password('Duchuy9617@')
            db.session.add(admin)
            db.session.commit()
            print("Đã tạo tài khoản admin mặc định: username 'huy04082000@gmail.com', password 'Duchuy9617@'")
        else:
            print("Tài khoản admin đã tồn tại.")
            
    server_ip = socket.gethostbyname(socket.gethostname())
    print(f"Địa chỉ IP máy chủ: {server_ip}")
    app.run(host='0.0.0.0', port=5000, debug=True)