# 📝 Flask Task Manager API

یک API ساده برای مدیریت وظایف (تسک‌ها) با استفاده از Flask، احراز هویت JWT و پایگاه‌داده SQLite.

---

## 🚀 ویژگی‌ها

- ثبت‌نام و ورود کاربران با رمز هش شده
- صدور توکن JWT برای احراز هویت
- ایجاد، مشاهده، ویرایش و حذف تسک‌ها
- استفاده از Marshmallow برای اعتبارسنجی
- حفاظت از مسیرها با `@token_required`

---

## 🛠️ نصب و اجرا

```bash
git clone https://github.com/yourusername/flask-task-api.git
cd flask-task-api
pip install -r requirements.txt
python app.py
