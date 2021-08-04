from ..services.auth import AuthService, get_current_user
from fastapi import APIRouter, Depends, UploadFile, Form, File
from fastapi.security import OAuth2PasswordRequestForm
from typing import Optional

from ..models.auth import (
    RefreshToken,
    UserCreate,
    User,
    BaseEmailVerificationToken
)

router = APIRouter(
    prefix='/auth',
)

@router.post('/sign-up')
def sign_up(
    user_data: UserCreate,
    service: AuthService = Depends(),
):
    user = service.register_new_user(user_data)
    return {'message': 'verify your email: {}'.format(user.email)}

@router.post('/verify')
def verify_email(
    verification_token: BaseEmailVerificationToken,
    service: AuthService = Depends()
):
    return service.verify_email(verification_token=verification_token.token)
@router.post('/sign-in')
def sign_in(
    form_data: OAuth2PasswordRequestForm = Depends(),
    service: AuthService = Depends(),
):
    return service.authentificate_user(
        form_data.username,
        form_data.password,
        form_data.client_id
    )

@router.post('/refresh')
def refresh(token: RefreshToken, service: AuthService = Depends()):
    return service.refresh_token(token)

@router.get('/user', response_model=User)
def get_user(user: User = Depends(get_current_user)):
    return user

@router.get('/check_username_unique')
def check_username_unique(username: str, service: AuthService = Depends()):
    return {'is_username_unique': service.check_username_unique(username)}

@router.get('/check_email_unique')
def check_email_unique(email: str, service: AuthService = Depends()):
    return {'is_username_unique': service.check_email_unique(email)}

@router.put('/user', response_model=User)
def update_user(
    image: Optional[UploadFile] = File(...),
    username: Optional[str] = Form(...), 
    user: User = Depends(get_current_user),
    service: AuthService = Depends()
):
    return service.edit_user(username, image, user)