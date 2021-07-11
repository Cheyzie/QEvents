from os import name
from time import time
import sqlalchemy as sa
from sqlalchemy.ext.declarative import declarative_base


Base = declarative_base()


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

    events = sa.orm.relationship(
        Event, 
        secondary='memberships'
    )
class Membership(Base):
    __tablename__ = 'memberships'

    id = sa.Column(sa.Integer, primary_key=True)
    user_id = sa.Column(sa.Integer, sa.ForeignKey('users.id'))
    event_id = sa.Column(sa.Integer, sa.ForeignKey('events.id'))
    is_admin = sa.Column(sa.Boolean, default=False)

    user = sa.orm.relationship(User, backref=sa.orm.backref('users_assoc'))
    event = sa.orm.relationship(Event, backref=sa.orm.backref('events_assoc'))

class Friendship(Base):
    __tablename__ = 'friendships'

    id = sa.Column(sa.Integer, primary_key=True)
    user_id_1 = sa.Column(sa.Integer, sa.ForeignKey('users.id'), primary_key=True)
    user_id_2 = sa.Column(sa.Integer, sa.ForeignKey('users.id'), primary_key=True)
