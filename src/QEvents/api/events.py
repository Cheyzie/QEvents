from fastapi import APIRouter
from fastapi import Depends


from ..models.events import EventCreate
from ..models.auth import User
from ..services.auth import get_current_user
from ..services.events import EventsService

router = APIRouter(
    prefix='/events',
)

@router.get('/')
def get_public_events(service: EventsService = Depends(), user: User = Depends(get_current_user)):
    return service.get_public_events()

@router.get('/my')
def get_my_events(service: EventsService = Depends(), user: User = Depends(get_current_user)):
    return service.get_my_events(user=user)

@router.post('/')
def create_event(event_data: EventCreate, service: EventsService = Depends(), user: User = Depends(get_current_user)):
    return service.create_new_event(user, event_data)