from fastapi import APIRouter, Depends
from ..services.users import UsersService
from ..services.events import EventsService
from ..services.auth import get_current_user
from ..models.auth import User

router = APIRouter(prefix='/users')

@router.get('/{username}')
def get_user(username: str, service: UsersService = Depends()):
    return service.get_user_by_username(username)

@router.get('/{username}/events')
def get_users_public_events(username: str, service: EventsService = Depends(), user: User = Depends(get_current_user)):
    return service.get_users_public_events(username)