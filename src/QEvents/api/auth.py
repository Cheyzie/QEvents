from ..services.auth import AuthService, get_current_user
from fastapi import APIRouter, Depends
from fastapi.security import OAuth2PasswordRequestForm

from ..models.auth import (
    UserCreate,
    User,
    Token,
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
@router.post('/sign-in', response_model=Token)
def sign_in(
    form_data: OAuth2PasswordRequestForm = Depends(),
    service: AuthService = Depends(),
):
    return service.authentificate_user(
        form_data.username,
        form_data.password
    )

@router.get('/user', response_model=User)
def get_user(user: User = Depends(get_current_user)):
    return user