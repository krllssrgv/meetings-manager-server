from flask import Flask, request, Blueprint, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, get_jwt, set_access_cookies, unset_jwt_cookies
from flask_cors import CORS
from flask_restx import Api, Resource, Namespace, fields
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView

from werkzeug.security import generate_password_hash, check_password_hash

from datetime import timedelta

from check_user import send_email, create_code

from config import SECRET_KEY, JWT_SECRET_KEY, SQLALCHEMY_DATABASE_URI



# App
app = Flask(__name__)

app.config['SECRET_KEY'] = SECRET_KEY
app.config['JWT_SECRET_KEY'] = JWT_SECRET_KEY
app.config['JWT_TOKEN_LOCATION'] = ['cookies']
app.config['JWT_COOKIE_CSRF_PROTECT'] = True
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=5)
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


# Entities
class Users(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(80), nullable=False)
    password = db.Column(db.Text, nullable=False)
    name = db.Column(db.String(40), nullable=False)
    lastname = db.Column(db.String(40), nullable=False)
    fathername = db.Column(db.String(40), nullable=False)
    confirmed = db.Column(db.Boolean, default=False, nullable=False)
    code = db.Column(db.String(6), nullable=False)
    

class Organizations(db.Model):
    __tablename__ = 'organizations'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    owner = db.Column(db.Integer, db.ForeignKey('users.id'))

    user = db.relationship('Users', backref='owned_organizations')


class Events(db.Model):
    __tablename__ = 'events'
    id = db.Column(db.Integer, primary_key=True)
    organizer_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    title = db.Column(db.String(200), nullable=False)
    room = db.Column(db.String(100), nullable=True)
    description = db.Column(db.Text, nullable=True)

    organizer = db.relationship('Users', backref=db.backref('organized_events', cascade="all, delete-orphan"))


# Associations
class UserOrganization(db.Model):
    __tablename__ = 'user_organization'
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), primary_key=True)
    organization_id = db.Column(db.Integer, db.ForeignKey('organizations.id'), primary_key=True)
    
    user = db.relationship('Users', backref=db.backref('user_organization', cascade="all, delete-orphan"))
    organization = db.relationship('Organizations', backref=db.backref('user_organization', cascade="all, delete-orphan"))

    
class EventMembers(db.Model):
    __tablename__ = 'event_members'

    event_id = db.Column(db.Integer, db.ForeignKey('events.id'), primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), primary_key=True)
    
    event = db.relationship('Events', backref=db.backref('participants', cascade="all, delete-orphan"))
    user = db.relationship('Users', backref=db.backref('participated_events', cascade="all, delete-orphan"))



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
})

user_confirm_model = auth_api.model('user_confirm', {
    'code': fields.String(required=True, description='code'),
})



# Admin
admin = Admin(app, template_mode='bootstrap3')
admin.add_view(ModelView(Users, db.session))
admin.add_view(ModelView(Organizations, db.session))
admin.add_view(ModelView(Events, db.session))
admin.add_view(ModelView(UserOrganization, db.session))
admin.add_view(ModelView(EventMembers, db.session))


# Auth API
@auth_api.route('/register')
class Register(Resource):
    @auth_api.expect(user_register_model)
    def post(self):
        data = request.json

        if (Users.query.filter(Users.email == data['email']).all()):
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
        new_user = Users(
            email=str(data['email']),
            password=generate_password_hash(str(data['password'])),
            name=str(data['name']),
            lastname=str(data['lastname']),
            fathername=str(data['fathername']),
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
        user = Users.query.filter_by(email=data['email']).first()
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
        user = db.session.get(Users, get_jwt_identity())
        if (user):
            response = make_response()
            unset_jwt_cookies(response)
            return response
        else:
            return '', 401
    

@auth_api.route('/get_user')
class GetUser(Resource):
    @jwt_required(optional=True)
    def get(self):
        user = db.session.get(Users, get_jwt_identity())
        if (user):
            return {
                'email': user.email,
                'name': user.name,
                'lastname': user.lastname,
                'fathername': user.fathername,
            }, 200
        else:
            return '', 401
        

@auth_api.route('/confirm_email')
class ConfirmEmail(Resource):
    @jwt_required(optional=True)
    @auth_api.expect(user_confirm_model)
    def post(self):
        user = db.session.get(Users, get_jwt_identity())

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
        user = db.session.get(Users, get_jwt_identity())

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
@act_api.route('/create_org')
class CreateOrg(Resource):
    @jwt_required(optional=True)
    def post(self):
        user = db.session.get(Users, get_jwt_identity())

        if (user):
            data = request.json
            new_org = Organizations(
                name=data['name'],
                owner = user.id
            )
            try:
                db.session.add(new_org)
                db.session.commit()
                return '', 200
            except:
                return '', 500
        else:
            return '', 401
         

@act_api.route('/create_event')
class CreateEvent(Resource):
    @jwt_required(optional=True)
    def post(self):
        user = db.session.get(Users, get_jwt_identity())

        if (user):
            data = request.json
            new_event = Events(
                organizer_id=user.id,
                title=data['title'],
                room=data['room'],
                description=data['description'],
                classroom_id=data['classroom'],
            )

            members = []
            for e in data['members']:
                members.push(EventMembers(
                    event_id=new_event.id,
                    user_id=e.id,
                ))
            try:
                db.session.add(new_event)
                for e in members:
                    db.session.add(members)
                db.session.commit()
                return '', 200
            except:
                return '', 500
        else:
            return '', 401



# Register
api.add_namespace(auth_api, path='/auth')
api.add_namespace(act_api, path='/act')
app.register_blueprint(api_bp)



if __name__ == '__main__':
    app.run(debug=True)