from typing import List, Optional
from pydantic import BaseModel


class BaseEvent(BaseModel):
    name: str
    description: str
    is_public: Optional[bool] = False

    class Config:
        orm_mode = True


class EventCreate(BaseEvent):
    pass






class Event(BaseEvent):
    id: int


from .auth import User


class EventDetail(Event):
    members: List[User]


class BaseMembership(BaseModel):
    user_id: int
    event_id: int
    is_admin: Optional[bool] = False


    class Config:
        orm_mode = True


class MembershipCreate(BaseMembership):
    pass


class Membership(BaseMembership):
    id: int
    user: User
    event: Event