from flask import Flask, request, Blueprint, make_response, redirect, url_for, flash, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate, upgrade, init, migrate
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, get_jwt, set_access_cookies, unset_jwt_cookies
from flask_cors import CORS
from flask_restx import Api, Resource, Namespace, fields
from flask_admin import Admin, AdminIndexView, expose
from flask_admin.contrib.sqla import ModelView
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired

from werkzeug.security import generate_password_hash, check_password_hash

from datetime import timedelta

from check_user import send_email, create_code
from admin import AdminUser

from config import SECRET_KEY, JWT_SECRET_KEY, SQLALCHEMY_DATABASE_URI



# App
app = Flask(__name__)

app.config['SECRET_KEY'] = SECRET_KEY
app.config['JWT_SECRET_KEY'] = JWT_SECRET_KEY
app.config['JWT_TOKEN_LOCATION'] = ['cookies']
app.config['JWT_COOKIE_CSRF_PROTECT'] = True
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=15)
app.config['JWT_BLACKLIST_ENABLED'] = True
app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access']
app.config['JWT_COOKIE_SAMESITE'] = 'None'
app.config['JWT_COOKIE_SECURE'] = True
app.config['JWT_COOKIE_CSRF_PROTECT'] = False


# CORS
CORS(app, supports_credentials=True)

# JWT
jwt = JWTManager(app)

# API
api_bp = Blueprint('API', __name__, url_prefix='/api')
api = Api(api_bp)
auth_api = Namespace('auth')
act_api = Namespace('act')

# DataBase
app.config['SQLALCHEMY_DATABASE_URI'] = SQLALCHEMY_DATABASE_URI
db = SQLAlchemy(app)
migrate = Migrate(app, db)


class users(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(80), nullable=False)
    password = db.Column(db.Text, nullable=False)
    name = db.Column(db.String(40), nullable=False)
    lastname = db.Column(db.String(40), nullable=False)
    fathername = db.Column(db.String(40), nullable=False)
    owner = db.Column(db.Boolean, nullable=False, default=False)

    confirmed = db.Column(db.Boolean, default=False, nullable=False)
    code = db.Column(db.String(6), nullable=False)

    def __repr__(self):
        return '<users %r>' % self.id


# Models
user_login_model = auth_api.model('user_register', {
    'email': fields.String(required=True, description='email'),
    'password': fields.String(required=True, description='password')
})

user_register_model = auth_api.model('user_login', {
    'email': fields.String(required=True, description='email'),
    'password': fields.String(required=True, description='password'),
    'repeated_password': fields.String(required=True, description='repeated_password'),
    'name': fields.String(required=True, description='name'),
    'lastname': fields.String(required=True, description='lastname'),
    'fathername': fields.String(required=True, description='fathername'),
    'as_org': fields.Boolean(required=True, description='as_org')
})

user_confirm_model = auth_api.model('user_confirm', {
    'code': fields.String(required=True, description='code'),
})


BLACKLIST = set()

@jwt.token_in_blocklist_loader
def check_if_token_in_blacklist(jwt_header, jwt_payload):
    jti = jwt_payload['jti']
    return jti in BLACKLIST


# Admin Login
class AdminLoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


# Admin
class MyAdminIndexView(AdminIndexView):
    @expose('/')
    @jwt_required()
    def index(self):
        return super(MyAdminIndexView, self).index()

class MyModelView(ModelView):
    @jwt_required()
    def is_accessible(self):
        return True
    

admin = Admin(app, name='Admin', template_mode='bootstrap3', index_view=MyAdminIndexView())
admin.add_view(MyModelView(users, db.session))


# User API
@auth_api.route('/register')
class Register(Resource):
    @auth_api.expect(user_register_model)
    def post(self):
        data = request.json

        if (users.query.filter(users.email == data['email']).all()):
            return {'error': 'Пользователь уже существует'}, 400
        
        if not (len(data['email'])):
            return {'error': 'Введите email'}, 400
        
        if not (len(data['name'])):
            return {'error': 'Введите имя'}, 400
        
        if not (len(data['lastname'])):
            return {'error': 'Введите фамилию'}, 400
        
        if not (len(data['fathername'])):
            return {'error': 'Введите отчество'}, 400

        if (len(data['password']) < 6):
            return {'error': 'Минимальная длина 6 символов'}, 400

        if (data['password'] != data['repeated_password']):
            return {'error': 'Пароли не совпадают'}, 400
        
        code = create_code()
        if (data['as_org']):
            new_user = users(
                email=str(data['email']),
                password=generate_password_hash(str(data['password'])),
                name=str(data['name']),
                lastname=str(data['lastname']),
                fathername=str(data['fathername']),
                owner=data['as_org'],
                code=code
            )
        else:
            new_user = users(
                email=str(data['email']),
                password=generate_password_hash(str(data['password'])),
                name=str(data['name']),
                lastname=str(data['lastname']),
                fathername=str(data['fathername']),
                owner=data['as_org'],
                code=code
            )
        try:
            db.session.add(new_user)
            db.session.commit()
            send_email(str(data['email']), code)
            return '', 204
        except:
            return '', 500


@auth_api.route('/login')
class Login(Resource):
    @auth_api.expect(user_login_model)
    def post(self):
        data = request.json
        user = users.query.filter_by(email=data['email']).first()
        if user:
            if check_password_hash(user.password, data['password']):
                access_token = create_access_token(identity=user.id)
                response = make_response()
                set_access_cookies(response, access_token)
                return response
            else:
                return {'error': 'Неправильный пароль'}, 401
        else:
            return {'error': 'Нет такого пользователя'}, 401


@auth_api.route('/logout')
class Logout(Resource):
    @jwt_required(optional=True)
    def post(self):
        user = db.session.get(users, get_jwt_identity())
        if (user):
            jti = get_jwt()['jti']
            BLACKLIST.add(jti)
            response = make_response()
            unset_jwt_cookies(response)
            return response
        else:
            return '', 401
    

@auth_api.route('/get_user')
class CheckLogin(Resource):
    @jwt_required(optional=True)
    def get(self):
        user = db.session.get(users, get_jwt_identity())
        if (user):
            return {
                'email': user.email,
                'name': user.name,
                'lastname': user.lastname,
                'fathername': user.fathername,
                'owner': user.owner
            }, 200
        else:
            return '', 401
        

@auth_api.route('/confirm_email')
class ConfirmEmail(Resource):
    @jwt_required(optional=True)
    @auth_api.expect(user_confirm_model)
    def post(self):
        user = db.session.get(users, get_jwt_identity())

        if (user):
            if (not user.confirmed):
                code = request.json['code']
                if (code == user.check_code):
                    user.check_code = ''
                    user.confirmed = True
                    try:
                        db.session.commit()
                        return '', 204
                    except:
                        return '', 500
                else:
                    return {'error': 'Неправильный код'}, 400
            else:
                return {'error': 'Почта уже подтверждена'}, 400
        else:
            return '', 401
        
        

@auth_api.route('/remove')
class RemoveUser(Resource):
    @jwt_required(optional=True)
    def post(self):
        user = db.session.get(users, get_jwt_identity())

        if (user):
            try:
                db.session.delete(user)
                db.session.commit()
                jti = get_jwt()['jti']
                BLACKLIST.add(jti)
                response = make_response()
                unset_jwt_cookies(response)
                return response
            except:
                return '', 500
        else:
            return '', 401


# Act API

@act_api.route('/set_day_as_done')
class DoneDay(Resource):
    @jwt_required(optional=True)
    def post(self):
        user = db.session.get(users, get_jwt_identity())

        if (user):
            data = request.json
            if ('set_day' in data):
                if (data['set_day'] == 1):
                    user.day_one = True
                elif (data['set_day'] == 2):
                    user.day_two = True
                elif (data['set_day'] == 3):
                    user.day_three = True
                    
                if (user.day_one and user.day_two and user.day_three):
                    user.success = '0'

                try:
                    db.session.commit()
                    return '', 200
                except:
                    return '', 500
            else:
                    return '', 400
        else:
            return '', 401


@act_api.route('/send_result')
class Result(Resource):
    @jwt_required(optional=True)
    def post(self):
        user = db.session.get(users, get_jwt_identity())

        if (user):
            data = request.json
            if ('success' in data):
                if (data['success']):
                    user.success = '1'
                else:
                    user.success = '-1'
                    
                try:
                    db.session.commit()
                    return {'success': user.success}, 200
                except:
                    return '', 500 
            else:
                return '', 400
        else:
            return '', 401 
        

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    form = AdminLoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        
        if (AdminUser.check_admin(username, password)):
            access_token = create_access_token(identity=username)
            response = make_response(redirect(url_for('admin.index')))
            set_access_cookies(response, access_token)
            return response
        else:
            flash('Invalid username or password')
    
    return render_template('login.html', form=form)


# Register
api.add_namespace(auth_api, path='/auth')
api.add_namespace(act_api, path='/act')

app.register_blueprint(api_bp)



if __name__ == '__main__':
    app.run(debug=False)