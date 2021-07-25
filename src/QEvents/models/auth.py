
from typing import List
from pydantic import BaseModel

class BaseUser(BaseModel):
    email: str
    username: str

class UserCreate(BaseUser):
    password: str



class User(BaseUser):
    id: int

    class Config:
        orm_mode = True


from .events import Event


class UserDetail(User):
    events: List[Event]


class RefreshToken(BaseModel):
    refresh_token: str
    fingerprint: str

class BaseEmailVerificationToken(BaseModel):
    token: str
class EmailVerificationToken(BaseEmailVerificationToken):
    id: int
    user_id: int
    