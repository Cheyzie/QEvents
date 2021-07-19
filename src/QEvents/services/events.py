from os import name
from typing import List
from ..database import get_session
from ..models.auth import User, UserDetail
from ..models.events import Event, EventCreate, EventDetail
from .. import tables


from sqlalchemy.orm import Session
from fastapi import Depends, HTTPException, status


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

    def get_users_public_events(self, username: str) -> List[Event]:
        events = UserDetail.from_orm(
            self.session
            .query(tables.User)
            .filter(tables.User.username == username)
            .first()
        ).events
        return [event for event in events if event.is_public]
        

    def get_event_by_id(self, event_id: int, user: User) -> Event:
        exception = HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
        )
        if (not event_id in [event.id for event in self.get_my_events(user)] 
            or not event_id in [event.id for event in self.get_public_events()]):
            raise exception

        else:
            event = (
                self.session
                .query(tables.Event)
                .filter(tables.Event.id == event_id)
                .first()
            )
            return EventDetail.from_orm(event)


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