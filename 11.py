from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
import jwt
import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from marshmallow import Schema, fields, validate

# راه‌اندازی برنامه Flask و تنظیمات پایگاه داده
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///tasks.db'
app.config['SECRET_KEY'] = 'mysecretkey'
db = SQLAlchemy(app)

# تعریف مدل‌ها
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)  # اضافه کردن فیلد رمز عبور

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=False)  # autoincrement غیرفعال شد
    description = db.Column(db.String(200), nullable=False)
    status = db.Column(db.String(50), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)

# اسکیما برای اعتبارسنجی
class TaskSchema(Schema):
    description = fields.String(required=True, validate=validate.Length(min=3, max=200))
    status = fields.String(required=True, validate=validate.OneOf(["pending", "in progress", "completed"]))

# تابع برای احراز هویت کاربر از طریق توکن JWT
def token_required(f):
    def decorator(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(" ")[1]

        if not token:
            return jsonify({'message': 'Token is missing!'}), 403

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.filter_by(id=data['user_id']).first()
        except Exception as e:
            return jsonify({'message': 'Token is invalid or expired!'}), 403

        return f(current_user, *args, **kwargs)
    
    decorator.__name__ = f"decorator_{f.__name__}"
    return decorator

# ثبت‌نام کاربر
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'message': 'Username and password are required!'}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({'message': 'User already exists!'}), 400

    hashed_password = generate_password_hash(password)  # هش کردن رمز عبور
    new_user = User(username=username, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'User created successfully!'}), 201

# ورود
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'message': 'Username and password are required!'}), 400

    user = User.query.filter_by(username=username).first()
    if not user or not check_password_hash(user.password, password):  # مقایسه رمز عبور هش شده
        return jsonify({'message': 'Invalid credentials!'}), 401

    # ایجاد توکن بدون نیاز به رمز عبور
    token = jwt.encode({'user_id': user.id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)}, app.config['SECRET_KEY'], algorithm="HS256")
    return jsonify({'token': token}), 200

# ایجاد کار با ID مشخص شده توسط کاربر
@app.route('/tasks', methods=['POST'])
@token_required
def create_task(current_user):
    data = request.get_json()
    task_id = data.get('id')  # ← گرفتن id از کاربر
    description = data.get('description')
    status = data.get('status')

    if not task_id or not description or not status:  # اصلاح خطای نوشتاری
        return jsonify({'message': 'Missing data!'}), 400

    # بررسی اینکه ID تسک قبلا وجود ندارد
    if Task.query.get(task_id):
        return jsonify({'message': 'Task with this ID already exists!'}), 400

    new_task = Task(id=task_id, description=description, status=status, user_id=current_user.id)
    db.session.add(new_task)
    db.session.commit()

    return jsonify({'message': 'Task created successfully!'}), 201

# دریافت همه تسک‌ها
@app.route('/tasks', methods=['GET'])
@token_required
def get_tasks(current_user):
    tasks = Task.query.filter_by(user_id=current_user.id).all()  # فقط تسک‌های مربوط به کاربر را نمایش بده
    task_schema = TaskSchema(many=True)
    return jsonify(task_schema.dump(tasks)), 200

# ویرایش کار
@app.route('/tasks/<int:id>', methods=['PUT'])
@token_required
def update_task(current_user, id):
    task = Task.query.get(id)
    if not task or task.user_id != current_user.id:
        return jsonify({'message': 'Task not found or unauthorized!'}), 404

    data = request.get_json()
    task.description = data.get('description', task.description)
    task.status = data.get('status', task.status)

    db.session.commit()
    return jsonify({'message': 'Task updated successfully!'}), 200

# حذف کار
@app.route('/tasks/<int:id>', methods=['DELETE'])
@token_required
def delete_task(current_user, id):
    task = Task.query.get(id)
    if not task or task.user_id != current_user.id:
        return jsonify({'message': 'Task not found or unauthorized!'}), 404

    db.session.delete(task)
    db.session.commit()
    return jsonify({'message': 'Task deleted successfully!'}), 200

# راه‌اندازی پایگاه داده
def init_db():
    db.create_all()

with app.app_context():
    init_db()

if __name__ == '__main__':
    app.run(debug=True)
