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
from sqlalchemy import or_


# Load biến môi trường từ file .env
load_dotenv()

# Cấu hình ứng dụng
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your_secret_key')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URI', 'sqlite:///app.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

logging.basicConfig(level=logging.INFO)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

ROLE_USER = 'user'
ROLE_MANAGER = 'manager'
ROLE_ADMIN = 'admin'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(50), default=ROLE_USER)
    is_approved = db.Column(db.Boolean, default=False)
    approved_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    full_name = db.Column(db.String(150), nullable=True)
    employee_code = db.Column(db.String(50), unique=True, nullable=True)

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

@app.before_request
def log_ip():
    ip = request.remote_addr
    app.logger.info("Incoming request from IP: %s", ip)





@app.route('/')
def index():
    # Nếu chưa đăng nhập, chuyển sang trang đăng nhập
    if not current_user.is_authenticated:
        return redirect(url_for('login'))

    # Lấy tham số GET
    page = request.args.get('page', 1, type=int)
    search = request.args.get('search', '')
    status_filter = request.args.get('status', '')

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

    # Phân trang (mỗi trang 5 sản phẩm)
    products = query.order_by(Product.id.desc()).paginate(page=page, per_page=5)

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
        total_products=total_products,
        running_count=running_count,
        repairing_count=repairing_count,
        broken_count=broken_count
    )



@app.route('/edit_product/<int:product_id>', methods=['GET', 'POST'])
@login_required
def edit_product(product_id):
    if current_user.role not in [ROLE_MANAGER, ROLE_ADMIN]:
        flash("Bạn không có quyền chỉnh sửa sản phẩm.")
        return redirect(url_for('index'))
    product = Product.query.get_or_404(product_id)
    if request.method == 'POST':
        try:
            product.product_name = request.form['product_name']
            product.serial_number = request.form['serial_number']
            product.date_issue = datetime.strptime(request.form['date_issue'], '%Y-%m-%d').date()
            product.department = request.form['department']
            product.status = request.form['status']
            db.session.commit()
            flash('Cập nhật sản phẩm thành công!')
            return redirect(url_for('product_detail', product_id=product.id))
        except Exception as e:
            flash('Có lỗi xảy ra khi cập nhật sản phẩm.')
            app.logger.error("Lỗi cập nhật sản phẩm: %s", e)
    return render_template('edit_product.html', product=product)

@app.route('/register', methods=['GET', 'POST'])
def register():
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

@app.route('/login', methods=['GET', 'POST'])
def login():
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

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Đăng xuất thành công.')
    return redirect(url_for('login'))

# Định nghĩa thứ tự quyền (role_order) để so sánh cấp bậc
# Định nghĩa thứ tự quyền (role_order) để so sánh cấp bậc
role_order = {"user": 1, "manager": 2, "admin": 3}

@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin_panel():
    # Chỉ admin và manager được truy cập trang quản trị
    if current_user.role not in [ROLE_MANAGER, ROLE_ADMIN]:
        flash('Bạn không có quyền truy cập trang quản trị.')
        return redirect(url_for('index'))

    # Lấy số trang cho các tab
    pending_page = request.args.get('pending_page', 1, type=int)
    approved_page = request.args.get('approved_page', 1, type=int)
    admin_users_page = request.args.get('admin_users_page', 1, type=int)

    # Query & phân trang cho 3 nhóm user:
    pending_users_paginated = User.query.filter_by(is_approved=False)\
        .order_by(User.id.desc())\
        .paginate(page=pending_page, per_page=5)

    approved_users_paginated = User.query.filter(
        User.is_approved == True,
        User.role == ROLE_USER
    ).order_by(User.id.desc())\
     .paginate(page=approved_page, per_page=5)

    admin_users_paginated = User.query.filter(
        User.role.in_([ROLE_MANAGER, ROLE_ADMIN])
    ).order_by(User.id.desc())\
     .paginate(page=admin_users_page, per_page=5)

    if request.method == 'POST':
        user_id = request.form.get('user_id')
        action = request.form.get('action')
        current_tab = request.form.get('current_tab', '#pending')
        user = User.query.get(user_id)
        if user:
            if action == 'approve':
                # Manager chỉ phê duyệt nếu tài khoản là user (pending)
                if current_user.role == ROLE_MANAGER and user.role != ROLE_USER:
                    flash("Manager chỉ có thể phê duyệt tài khoản user.")
                else:
                    user.is_approved = True
                    user.approved_by = current_user.id
                    flash("Tài khoản đã được phê duyệt.")
            elif action == 'delete':
                if user.id == current_user.id:
                    flash("Bạn không thể xóa tài khoản của chính mình.")
                    return redirect(url_for('admin_panel', 
                                            pending_page=pending_page,
                                            approved_page=approved_page,
                                            admin_users_page=admin_users_page, 
                                            tab=current_tab))
                # Chỉ xóa được nếu user mục tiêu có cấp bậc thấp hơn
                elif role_order[current_user.role] > role_order[user.role]:
                    db.session.delete(user)
                    flash("Tài khoản đã được xóa.")
                else:
                    flash("Không được phép xóa tài khoản cùng cấp hoặc cao hơn.")
            elif action == 'update_role':
                # Chỉ admin mới có quyền cập nhật role
                if current_user.role != ROLE_ADMIN:
                    flash("Chỉ admin có quyền cập nhật role.")
                else:
                    new_role = request.form.get('new_role')
                    if new_role not in [ROLE_USER, ROLE_MANAGER, ROLE_ADMIN]:
                        flash("Giá trị role không hợp lệ.")
                    else:
                        # Không cho admin thay đổi role của admin khác (cùng cấp)
                        if user.role == ROLE_ADMIN and new_role == ROLE_ADMIN:
                            flash("Không thể thay đổi role của admin cùng cấp.")
                        elif new_role == ROLE_ADMIN:
                            flash("Chỉ admin mới có thể cấp quyền admin (và bạn đang là admin).")
                            # Vẫn cho cập nhật, nếu logic của bạn cho phép
                            user.role = new_role
                            user.approved_by = current_user.id
                            flash(f"Đã cập nhật role của {user.username} thành {new_role}.")
                        else:
                            # Cập nhật role nếu target có cấp thấp hơn admin hiện tại
                            user.role = new_role
                            user.approved_by = current_user.id
                            flash(f"Đã cập nhật role của {user.username} thành {new_role}.")
            db.session.commit()

        return redirect(url_for('admin_panel', 
                                pending_page=pending_page,
                                approved_page=approved_page,
                                admin_users_page=admin_users_page, 
                                tab=current_tab))

    return render_template(
        'admin.html',
        pending_users=pending_users_paginated,
        approved_users=approved_users_paginated,
        admin_users=admin_users_paginated
    )




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
        db.session.flush()
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
    error = None
    if request.method == 'POST':
        qr_content = request.form['qr_content']
        # Tìm sản phẩm theo mã
        product = Product.query.filter(Product.product_code.ilike(f"%{qr_content}%")).first()
        if not product:
            error = 'Sản phẩm không tồn tại.'
    return render_template('scan_qr.html', product=product, error=error)


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
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
