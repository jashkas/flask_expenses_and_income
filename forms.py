from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, DecimalField, TextAreaField, BooleanField
from wtforms.validators import DataRequired, Length, NumberRange, EqualTo, ValidationError
from models import User

class RegistrationForm(FlaskForm):
    username = StringField('Имя пользователя', validators=[DataRequired(), Length(min=3, max=20)])
    password = PasswordField('Пароль', validators=[DataRequired()])
    confirm_password = PasswordField('Подтвердить пароль', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Зарегистрироваться')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Имя пользователя уже занято.')

class LoginForm(FlaskForm):
    username = StringField('Имя пользователя', validators=[DataRequired()])
    password = PasswordField('Пароль', validators=[DataRequired()])
    submit = SubmitField('Войти')

class ExpenseForm(FlaskForm):
    category = StringField('Категория', validators=[DataRequired(), Length(max=100)])
    description = TextAreaField('Описание', validators=[Length(max=200)])
    amount = DecimalField('Сумма', validators=[DataRequired(), NumberRange(min=0.01)], places=2)
    is_income = BooleanField('Это доход?') # Чекбокс для выбора типа (доход или расход)
    submit = SubmitField('Добавить')