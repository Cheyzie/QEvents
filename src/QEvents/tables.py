
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.sql.functions import user
from datetime import datetime


Base = declarative_base()


class EmailVerificationToken(Base):
    __tablename__ = 'email_verification_tokens'

    id = sa.Column(sa.Integer, primary_key=True)
    user_id = sa.Column(sa.Integer)
    token = sa.Column(sa.String)

class refreshSession(Base):
    __tablename__ = 'refresh_sessions'
    
    id = sa.Column(sa.Integer, primary_key=True)
    user_id = sa.Column(sa.Integer, sa.ForeignKey('users.id', ondelete="CASCADE"))
    refresh_token = sa.Column(sa.String, nullable=False)
    expires_in = sa.Column(sa.DateTime)
    created_at = sa.Column(sa.DateTime, default=datetime.utcnow)

class Event(Base):
    __tablename__ = 'events'

    id = sa.Column(sa.Integer, primary_key=True)
    name = sa.Column(sa.String)
    description = sa.Column(sa.Text)
    is_public = sa.Column(sa.Boolean, default=False)

    members = sa.orm.relationship(
        'User', 
        secondary='memberships'
    )


class User(Base):
    __tablename__ = 'users'

    id = sa.Column(sa.Integer, primary_key=True)
    email = sa.Column(sa.Text, unique=True)
    username = sa.Column(sa.Text, unique=True)
    password_hash = sa.Column(sa.Text)
    is_active = sa.Column(sa.Boolean, default=False)

    events = sa.orm.relationship(
        Event, 
        secondary='memberships',
        overlaps='members',
    )
class Membership(Base):
    __tablename__ = 'memberships'

    id = sa.Column(sa.Integer, primary_key=True)
    user_id = sa.Column(sa.Integer, sa.ForeignKey('users.id'))
    event_id = sa.Column(sa.Integer, sa.ForeignKey('events.id'))
    is_admin = sa.Column(sa.Boolean, default=False)


class Friendship(Base):
    __tablename__ = 'friendships'

    id = sa.Column(sa.Integer, primary_key=True)
    user_id_1 = sa.Column(sa.Integer, sa.ForeignKey('users.id'), primary_key=True)
    user_id_2 = sa.Column(sa.Integer, sa.ForeignKey('users.id'), primary_key=True)
