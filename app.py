import os
import io
import socket
import qrcode
import pytz
from datetime import datetime
from flask import Flask, render_template, redirect, url_for, request, flash, send_file, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, current_user, login_required, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
import logging



# Load biến môi trường từ file .env
load_dotenv()

# Cấu hình ứng dụng
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your_secret_key')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URI', 'sqlite:///app.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Cấu hình logging cơ bản
logging.basicConfig(level=logging.INFO)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Định nghĩa các vai trò
ROLE_USER = 'user'       # Người dùng chỉ xem sản phẩm
ROLE_MANAGER = 'manager' # Quản lý: có quyền duyệt thành viên
ROLE_ADMIN = 'admin'     # Admin: quyền cao nhất, quản lý hệ thống

# Model User mở rộng thêm thông tin (họ tên, mã nhân viên, ai phê duyệt)
class User(UserMixin, db.Model):
    """Model người dùng, bao gồm thông tin đăng nhập và thông tin cá nhân."""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(50), default=ROLE_USER)
    is_approved = db.Column(db.Boolean, default=False)
    approved_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    full_name = db.Column(db.String(150), nullable=True)
    employee_code = db.Column(db.String(50), unique=True, nullable=True)

    def set_password(self, password):
        """Hash mật khẩu và lưu vào trường password_hash."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Kiểm tra mật khẩu nhập vào so với hash đã lưu."""
        return check_password_hash(self.password_hash, password)

# Model Product (sản phẩm)
class Product(db.Model):
    """Model sản phẩm với các thông tin chi tiết và QR code."""
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

# Hàm tải người dùng cho Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Context processor để lấy thông tin người duyệt
@app.context_processor
def utility_processor():
    def get_approver(approver_id):
        return User.query.get(approver_id)
    return dict(get_approver=get_approver)

def generate_product_code():
    """Sinh mã sản phẩm dựa vào thời gian hiện tại."""
    return "SP" + datetime.now().strftime("%Y%m%d%H%M%S")

@app.before_request
def log_ip():
    """Middleware ghi nhận IP của người dùng gửi request."""
    ip = request.remote_addr
    app.logger.info("Incoming request from IP: %s", ip)

# Route trang chủ: chỉ người dùng đã đăng nhập được xem danh sách sản phẩm

@app.route('/')
def index():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    
    # Lấy số trang hiện tại từ query string, mặc định là 1
    page = request.args.get('page', 1, type=int)
    
    # Query và phân trang, mỗi trang 5 sản phẩm (tuỳ bạn chọn)
    products = Product.query.order_by(Product.id.desc()).paginate(page=page, per_page=5)
    
    # Trả về đối tượng phân trang 'products' thay vì list
    return render_template('index.html', products=products)


# Route đăng ký
@app.route('/register', methods=['GET', 'POST'])
def register():
    """Đăng ký tài khoản mới, mặc định chưa được phê duyệt."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        full_name = request.form.get('full_name')
        employee_code = request.form.get('employee_code')
        
        if User.query.filter_by(username=username).first():
            flash('Tên đăng nhập đã tồn tại.')
            return redirect(url_for('register'))
        
        user = User(username=username, full_name=full_name, employee_code=employee_code)
        user.set_password(password)
        user.is_approved = False
        
        db.session.add(user)
        db.session.commit()
        
        flash('Đăng ký thành công. Vui lòng chờ người quản lý phê duyệt.')
        return redirect(url_for('login'))
    
    return render_template('register.html')

# Route đăng nhập
@app.route('/login', methods=['GET', 'POST'])
def login():
    """Xử lý đăng nhập người dùng."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            if not user.is_approved:
                flash('Tài khoản chưa được phê duyệt.')
                return redirect(url_for('login'))
            login_user(user)
            flash('Đăng nhập thành công.')
            return redirect(url_for('index'))
        
        flash('Sai thông tin đăng nhập.')
        return redirect(url_for('login'))
    
    return render_template('login.html')

# Route đăng xuất
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Đăng xuất thành công.')
    return redirect(url_for('login'))

# Route quản trị (admin): chỉ cho phép truy cập nếu user có role là manager hoặc admin
@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin_panel():
    if current_user.role not in [ROLE_MANAGER, ROLE_ADMIN]:
        flash('Bạn không có quyền truy cập trang quản trị.')
        return redirect(url_for('index'))

    # Lấy số trang cho mỗi tab (pending, approved, adminUsers)
    pending_page = request.args.get('pending_page', 1, type=int)
    approved_page = request.args.get('approved_page', 1, type=int)
    admin_users_page = request.args.get('admin_users_page', 1, type=int)

    # Query & paginate
    pending_users_paginated = User.query.filter_by(is_approved=False) \
        .order_by(User.id.desc()) \
        .paginate(page=pending_page, per_page=5)

    approved_users_paginated = User.query.filter(
        User.is_approved == True, 
        User.role == ROLE_USER
    ).order_by(User.id.desc()) \
     .paginate(page=approved_page, per_page=5)

    admin_users_paginated = User.query.filter(
        User.role.in_([ROLE_MANAGER, ROLE_ADMIN])
    ).order_by(User.id.desc()) \
     .paginate(page=admin_users_page, per_page=5)

    if request.method == 'POST':
        user_id = request.form.get('user_id')
        action = request.form.get('action')
        current_tab = request.form.get('current_tab', '#pending')
        user = User.query.get(user_id)
        
        if user:
            if action == 'approve':
                user.is_approved = True
                user.approved_by = current_user.id
            elif action == 'delete':
                if user.id == current_user.id:
                    flash("Bạn không thể xóa tài khoản của chính mình.")
                    return redirect(url_for('admin_panel', tab=current_tab))
                else:
                    db.session.delete(user)
            elif action == 'promote_manager':
                if user.role == ROLE_USER:
                    user.role = ROLE_MANAGER
                    user.approved_by = current_user.id
            elif action == 'promote_admin':
                if user.role == ROLE_MANAGER:
                    user.role = ROLE_ADMIN
                    user.approved_by = current_user.id
            elif action == 'demote_manager':
                if user.role == ROLE_ADMIN:
                    user.role = ROLE_MANAGER
                    user.approved_by = current_user.id
            elif action == 'demote_user':
                if user.role in [ROLE_MANAGER, ROLE_ADMIN]:
                    user.role = ROLE_USER
                    user.approved_by = current_user.id
            
            db.session.commit()
            flash("Cập nhật thành công.")
        
        return redirect(url_for('admin_panel', tab=current_tab))

    return render_template(
        'admin.html', 
        pending_users=pending_users_paginated, 
        approved_users=approved_users_paginated, 
        admin_users=admin_users_paginated
    )


# Route thêm sản phẩm
@app.route('/add_product', methods=['GET', 'POST'])
@login_required
def add_product():
    if current_user.role not in [ROLE_MANAGER, ROLE_ADMIN]:
         flash("Bạn không có quyền truy cập trang thêm sản phẩm.")
         return redirect(url_for('index'))
    
    if request.method == 'POST':
        vietnam_tz = pytz.timezone('Asia/Ho_Chi_Minh')
        date_entry = datetime.now(vietnam_tz)
        
        product_code = generate_product_code()
        product_name = request.form['product_name']
        serial_number = request.form['serial_number']
        try:
            date_issue = datetime.strptime(request.form['date_issue'], '%Y-%m-%d').date()
        except ValueError:
            flash('Ngày cấp không hợp lệ.')
            return redirect(url_for('add_product'))
        department = request.form['department']
        status = request.form['status']
        
        product = Product(
            date_entry=date_entry,
            product_code=product_code,
            product_name=product_name, 
            serial_number=serial_number,
            date_issue=date_issue, 
            department=department, 
            status=status,
            entered_by=current_user.id
        )
        
        db.session.add(product)
        db.session.flush()  # Lấy product.id mới tạo
        
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
            app.logger.error("Lỗi tạo QR code: %s", e)
            flash("Có lỗi xảy ra khi tạo QR code.")
            return redirect(url_for('add_product'))
        
        db.session.commit()
        flash('Sản phẩm đã được thêm thành công!')
        return redirect(url_for('index'))
    
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
    if request.method == 'POST':
        qr_content = request.form['qr_content']
        product = Product.query.filter(Product.product_code.like(f"%{qr_content}%")).first()
        if not product:
            flash('Sản phẩm không tồn tại.')
    return render_template('scan_qr.html', product=product)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # Tạo tài khoản admin mặc định nếu chưa có
        if not User.query.filter_by(username='admin').first():
            admin = User(username='admin', role=ROLE_ADMIN, is_approved=True, full_name="Quản trị viên cao nhất", employee_code="EMP_ADMIN")
            admin.set_password('admin123')
            db.session.add(admin)
            db.session.commit()
            print("Đã tạo tài khoản admin mặc định: username 'admin', password 'admin123'")
        else:
            print("Tài khoản admin đã tồn tại.")
    
    server_ip = socket.gethostbyname(socket.gethostname())
    print(f"Địa chỉ IP máy chủ: {server_ip}")
    app.run(host='0.0.0.0', port=5000, debug=True)
