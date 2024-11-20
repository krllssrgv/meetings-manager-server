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
from config import SECRET_KEY, JWT_SECRET_KEY, SQLALCHEMY_DATABASE_URI
from datetime import datetime
from copy import copy


# App
app = Flask(__name__)

app.config['SECRET_KEY'] = SECRET_KEY
app.config['JWT_SECRET_KEY'] = JWT_SECRET_KEY
app.config['JWT_TOKEN_LOCATION'] = ['cookies']
# app.config['JWT_COOKIE_CSRF_PROTECT'] = True
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=5)
app.config['JWT_COOKIE_SAMESITE'] = 'None'
app.config['JWT_COOKIE_SECURE'] = True
app.config['JWT_COOKIE_CSRF_PROTECT'] = False


# CORS
CORS(app, supports_credentials=True, resources={r"/*": {"origins": "https://course-work-meetingsmanager-e9466b.edu-gitlab.ru/"}})

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

    organizations = db.relationship('UserOrganization', cascade="all, delete-orphan")
    owned_organizations = db.relationship('Organizations', cascade="all, delete-orphan")
    owned_meetings = db.relationship('Meetings', cascade="all, delete-orphan")
    invitations = db.relationship('Invitations', cascade="all, delete-orphan")
    

class Organizations(db.Model):
    __tablename__ = 'organizations'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    owner = db.Column(db.Integer, db.ForeignKey('users.id'))

    meetings = db.relationship('Meetings', cascade="all, delete-orphan")
    members = db.relationship('UserOrganization', cascade="all, delete-orphan")


class Meetings(db.Model):
    __tablename__ = 'meetings'
    id = db.Column(db.Integer, primary_key=True)
    organizer_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    organization_id = db.Column(db.Integer, db.ForeignKey('organizations.id'))
    title = db.Column(db.Text, nullable=False)
    place = db.Column(db.Text, nullable=False)
    description = db.Column(db.Text, nullable=True)
    time = db.Column(db.String(10), nullable=False)
    date = db.Column(db.String(), nullable=False)


# Associations
class UserOrganization(db.Model):
    __tablename__ = 'user_organization'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    organization_id = db.Column(db.Integer, db.ForeignKey('organizations.id'))


class Invitations(db.Model):
    __tablename__ = 'invitations'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    organization_id = db.Column(db.Integer, db.ForeignKey('organizations.id'), nullable=False)


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
admin.add_view(ModelView(Meetings, db.session))
admin.add_view(ModelView(UserOrganization, db.session))
admin.add_view(ModelView(Invitations, db.session))


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
        
        new_user = Users(
            email=str(data['email']),
            password=generate_password_hash(str(data['password'])),
            name=str(data['name']),
            lastname=str(data['lastname']),
            fathername=str(data['fathername']),
        )
        try:
            db.session.add(new_user)
            db.session.commit()
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
                access_token = create_access_token(identity=str(user.id))
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
            organizations = []
            for e in user.organizations:
                current_org = db.session.get(Organizations, e.organization_id)
                organizations.append({
                    'id': current_org.id,
                    'name': current_org.name,
                    'owned': (current_org.owner == user.id)
                })

            invitations = []
            for inv in user.invitations:
                target_org = db.session.get(Organizations, inv.organization_id)
                invitations.append({
                    'id': inv.id,
                    'organization': target_org.name
                })

            return {
                'id': user.id,
                'email': user.email,
                'name': user.name,
                'lastname': user.lastname,
                'fathername': user.fathername,
                'organizations': organizations,
                'invitations': invitations,
            }, 200
        else:
            return '', 401
         
        
# @auth_api.route('/remove')
# class RemoveUser(Resource):
#     @jwt_required(optional=True)
#     def post(self):
#         user = db.session.get(Users, get_jwt_identity())
#         if (user):
#             try:
#                 db.session.delete(user)
#                 db.session.commit()
#                 response = make_response()
#                 unset_jwt_cookies(response)
#                 return response
#             except:
#                 return '', 500
#         else:
#             return '', 401


# Act API
@act_api.route('/get_org/<int:id>')
class GetOrg(Resource):
    @jwt_required(optional=True)
    def get(self, id):
        user = db.session.get(Users, get_jwt_identity())
        if (user):
            org = db.session.get(Organizations, id)
            if (org):
                members = []
                for e in org.members:
                    member = db.session.get(Users, e.user_id)
                    members.append({
                        'id': member.id,
                        'email': member.email,
                        'fullName': member.lastname + member.name + member.fathername,
                    })
                meetings = []
                for m in org.meetings:
                    date_of_m = datetime.strptime(m.date, "%Y-%m-%d").date()
                    today = datetime.today().date()
                    if date_of_m >= today:
                        organizer = db.session.get(Users, m.organizer_id)
                        meetings.append({
                            'id': m.id,
                            'organizerName': f'{organizer.lastname} {organizer.name} {organizer.fathername}',
                            'title': m.title,
                            'place': m.place,
                            'description': m.description,
                            'time': m.time,
                            'date': m.date
                        })
                return {
                    'id': org.id,
                    'name': org.name,
                    'owner': org.owner,
                    'members': members,
                    'meetings': meetings,
                }, 200
            else:
                return '', 404
        else:
            return '', 401
        

@act_api.route('/create_org')
class CreateOrg(Resource):
    @jwt_required(optional=True)
    def post(self):
        user = db.session.get(Users, get_jwt_identity())

        if (user):
            data = request.json
            try:
                new_org = Organizations(
                        name=data['name'],
                        owner=user.id
                )
                db.session.add(new_org)
                db.session.flush()
                
                new_membership = UserOrganization(
                    user_id=user.id,
                    organization_id=new_org.id
                )

                db.session.add(new_membership)
                db.session.commit()
                return {
                    'id': new_org.id,
                    'name': new_org.name,
                    'owner': new_org.owner
                }, 200
            except Exception as e:
                print(e)
                return '', 500
        else:
            return '', 401
         

@act_api.route('/create_inv')
class CreateInv(Resource):
    @jwt_required(optional=True)
    def post(self):
        user = db.session.get(Users, get_jwt_identity())

        if (user):
            to_user = request.json['to_user']
            existing_user = Users.query.filter_by(email=to_user).first()
            if (existing_user is None):
                return {
                    'error': 'Такого пользователя не существует'
                }, 400
            else:
                to_org = request.json['to_org']
                existing_org = db.session.get(Organizations, to_org)


                existing_invitation = Invitations.query.filter_by(
                    user_id=existing_user.id,
                    organization_id=to_org
                ).first()

                if (existing_invitation is not None):
                    return {
                        'error': 'Приглашение этому пользователю уже существует'
                    }, 400
                else:
                    existing_membership = UserOrganization.query.filter_by(
                        user_id=existing_user.id,
                        organization_id=to_org
                    ).first()

                    if (existing_membership is not None):
                        return {
                            'error': 'Пользователь уже в организации'
                        }, 400
                    else:
                        if ((existing_org is not None) and (user.id == existing_org.owner) and (existing_membership is None)):
                            try:
                                new_invitation = Invitations(
                                    user_id=existing_user.id,
                                    organization_id=to_org
                                )
                                db.session.add(new_invitation)
                                db.session.commit()
                                return '', 204
                            except:
                                return '', 500
                        else:
                            return {
                                'error': 'Ошибка на сервере'
                            }, 400
        else:
            return '', 401


@act_api.route('/accept_inv/<int:id>')
class AcceptInv(Resource):
    @jwt_required(optional=True)
    def post(self, id):
        user = db.session.get(Users, get_jwt_identity())

        if (user):
            inv = db.session.get(Invitations, id)

            if ((inv is not None) and (inv.user_id == user.id)):
                try:
                    new_member = UserOrganization(
                        user_id=inv.user_id,
                        organization_id=inv.organization_id
                    )
                    db.session.add(new_member)
                    db.session.flush()
                    db.session.delete(inv)
                    db.session.commit()
                    org = db.session.get(Organizations, new_member.organization_id)
                    return {
                        'id': org.id,
                        'name': org.name,
                        'owned': (org.owner == user.id)
                    }, 200
                except:
                    return '', 500
            else:
                return '', 400
        else:
            return '', 401


@act_api.route('/reject_inv/<int:id>')
class RejectInv(Resource):
    @jwt_required(optional=True)
    def post(self, id):
        user = db.session.get(Users, get_jwt_identity())

        if (user):
            inv = db.session.get(Invitations, id)

            if ((inv is not None) and (inv.user_id == user.id)):
                try:
                    db.session.delete(inv)
                    db.session.commit()
                    return '', 204
                except:
                    return '', 500
            else:
                return '', 400
        else:
            return '', 401


@act_api.route('/create_meeting')
class CreateMeeting(Resource):
    @jwt_required(optional=True)
    def post(self):
        user = db.session.get(Users, get_jwt_identity())

        if (user):
            data = request.json
            new_meeting = Meetings(
                organizer_id=user.id,
                organization_id=data['organization_id'],
                title=data['title'],
                place=data['place'],
                description=data['description'],
                time=data['time'],
                date=data['date']
            )

            try:
                db.session.add(new_meeting)
                db.session.commit()
                return {
                    'id': new_meeting.id,
                    'organizerName': f'{user.lastname} {user.name} {user.fathername}',
                    'title': new_meeting.title,
                    'place': new_meeting.place,
                    'description': new_meeting.description,
                    'time': new_meeting.time,
                    'date': new_meeting.date
                }, 200
            except:
                return '', 500
        else:
            return '', 401
        

@act_api.route('/remove_member')
class RemoveMember(Resource):
    @jwt_required(optional=True)
    def delete(self):
        user = db.session.get(Users, get_jwt_identity())
        if (user):
            data = request.json
            membership = UserOrganization.query.filter_by(
                    user_id=data['user_id'],
                    organization_id=data['organization_id']
                ).first()
            if (membership is None):
                return {
                    'orgs_to_remove': []
                }, 200
            else:
                user_meetings_owner = Meetings.query.filter_by(
                    organizer_id=data['user_id'],
                    organization_id=data['organization_id']
                ).all()

                result = []
                for i in user_meetings_owner:
                    result.append(copy(i.id))
                try:
                    for i in user_meetings_owner:
                        db.session.delete(i)
                        db.session.flush()
                    db.session.delete(membership)
                    db.session.commit()
                    return {
                        'orgs_to_remove': result
                    }, 200
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