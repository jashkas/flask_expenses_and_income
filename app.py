from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from datetime import datetime
from models import db, User, Expense
from forms import RegistrationForm, LoginForm, ExpenseForm
from markupsafe import escape # защита от XSS
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Настройки CSP
CSP_POLICY = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self'; "
    "img-src 'self'; "
    "font-src 'self'; "
    "object-src 'none'; "
    "base-uri 'self'; "
    "frame-ancestors 'none';"
)
def add_csp_header(response):
    """Добавляет CSP-заголовок к HTTP-ответу"""
    response.headers['Content-Security-Policy'] = CSP_POLICY
    return response

app.after_request(add_csp_header)


db.init_app(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(escape(form.password.data)).decode('utf-8')
        user = User(username=escape(form.username.data), password=hashed_password)
        db.session.add(user)
        db.session.commit()
        # ДЕМОНСТРАЦИЯ ТОГО ЧТО ПАРОЛЬ В БД ЗАШИФРОВАН
        users = User.query.all()
        for u in users:
            print(u.username, "  ", u.password)
        flash('Успешная регистрация! Теперь войдите в систему.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=escape(form.username.data)).first()
        if user and bcrypt.check_password_hash(user.password, escape(form.password.data)):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Ошибка входа. Проверьте логин и пароль.', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    expenses = Expense.query.filter_by(user_id=current_user.id).all()
    return render_template('dashboard.html', expenses=expenses)

@app.route('/add', methods=['GET', 'POST'])
@login_required
def add_expense():
    form = ExpenseForm()
    if form.validate_on_submit():
        try:
            # Преобразуем дату из строки формата дд.мм.гггг в объект datetime.date
            date_obj = datetime.strptime(form.date.data, '%d.%m.%Y').date()
        except ValueError:
            flash('Ошибка: дата должна быть в формате дд.мм.гггг.', 'danger')
            return render_template('add_expense.html', form=form)
        # Объект расхода/дохода
        expense = Expense(
                        user_id=current_user.id,
                        date=date_obj,  # Используем преобразованную дату
                        amount=form.amount.data, 
                        category=escape(form.category.data), 
                        description=escape(form.description.data), 
                        is_income=form.is_income.data)
        db.session.add(expense)
        db.session.commit()
        flash('Запись добавлена!', 'success')
        return redirect(url_for('dashboard'))
    return render_template('add_expense.html', form=form)

@app.route('/edit/<int:expense_id>', methods=['GET', 'POST'])
@login_required
def edit_expense(expense_id):
    expense = Expense.query.get_or_404(expense_id)  # Получить запись или вернуть 404, если её нет
    # Проверить, что запись принадлежит текущему пользователю
    if expense.user_id != current_user.id:
        flash("Вы не можете редактировать эту запись.", "danger")
        return redirect(url_for('dashboard'))
    
    # Создаём форму для редактирования записи, передав текущие значения
    form = ExpenseForm(obj=expense)
    
    if request.method == 'GET':
        # Преобразуем существующую дату в формат дд.мм.гггг для отображения в поле формы
        form.date.data = expense.date.strftime('%d.%m.%Y')


    elif form.validate_on_submit():
        try:
            # Преобразуем дату из строки формата дд.мм.гггг в объект datetime.date
            date_obj = datetime.strptime(form.date.data, '%d.%m.%Y').date()
            print(date_obj)
            expense.date = date_obj
            print(expense.date, form.date.data)
        except ValueError:
            flash('Ошибка: дата должна быть в формате дд.мм.гггг.', 'danger')
            return render_template('edit_expense.html', form=form, expense=expense)
        
        expense.amount = form.amount.data
        expense.category = escape(form.category.data)
        expense.description = escape(form.description.data)
        expense.is_income = form.is_income.data

        db.session.commit()
        flash('Запись обновлена!', 'success')
        return redirect(url_for('dashboard'))
    return render_template('edit_expense.html', form=form, expense=expense)

@app.route('/delete/<int:expense_id>')
@login_required
def delete_expense(expense_id):
    expense = Expense.query.get_or_404(expense_id)
    if expense.user_id != current_user.id:
        flash('Вы не можете удалить эту запись.', 'danger')
        return redirect(url_for('dashboard'))
    db.session.delete(expense)
    db.session.commit()
    flash('Запись удалена!', 'success')
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    # Создание базы данных
    with app.app_context():
        db.create_all()
    app.run(debug=True)