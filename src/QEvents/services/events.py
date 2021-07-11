from os import name
from typing import List
from ..database import get_session
from ..models.auth import User, UserDetail
from ..models.events import Event, EventCreate, EventDetail
from .. import tables

from sqlalchemy.orm import Session
from fastapi import Depends


class EventsService:
    def __init__(self, session: Session = Depends(get_session)) -> None:
        self.session = session

    def get_my_events(self, user: User) -> List[Event]:
        return UserDetail.from_orm(
            self.session
            .query(tables.User)
            .filter(tables.User.email == user.email)
            .first()
        ).events

    def get_public_events(self) -> List[Event]:
        events = (
            self.session
            .query(tables.Event)
            .filter(tables.Event.is_public)
            .all()
        )
        return [Event.from_orm(event) for event in events]

    def create_new_event(self, user: User, event_data: EventCreate) -> EventDetail:
        event = tables.Event(
            name = event_data.name,
            description = event_data.description,
            is_public = event_data.is_public,
        )
        self.session.add(event)
        self.session.commit()
        self.session.refresh(event)
        membership = tables.Membership(
            user_id=user.id, 
            event_id=event.id,
            is_admin=True,
        )
        self.session.add(membership)
        self.session.commit()
        self.session.refresh(event)
        return EventDetail.from_orm(event)