# app/forms.py - MAKE SURE CSRF IS DISABLED
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, SelectField, SubmitField, PasswordField
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError
from app.models import User


class TaskForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired(), Length(max=100)])
    description = TextAreaField('Description', validators=[Length(max=200)])
    status = SelectField(
        'Status', choices=[
            ('Pending', 'Pending'), ('Done', 'Done')])
    submit = SubmitField('Submit')

    class Meta:
        csrf = False  # IMPORTANT: Disable CSRF


class RegistrationForm(FlaskForm):
    username = StringField(
        'Username', validators=[
            DataRequired(), Length(
                min=4, max=50)])
    password = PasswordField(
        'Password', validators=[
            DataRequired(), Length(
                min=6)])
    confirm_password = PasswordField(
        'Confirm Password', validators=[
            DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

    class Meta:
        csrf = False  # IMPORTANT: Disable CSRF

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Username already exists.')


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

    class Meta:
        csrf = False  # IMPORTANT: Disable CSRF