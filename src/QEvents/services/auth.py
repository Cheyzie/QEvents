from datetime import datetime, timedelta
from fastapi import HTTPException, status
from fastapi.param_functions import Depends
from fastapi.security import OAuth2PasswordBearer
from pydantic import ValidationError

from jose import jwt
from jose.exceptions import JWTError
from passlib.hash import bcrypt

from sqlalchemy.orm import Session

from .. import tables
from ..database import get_session
from ..models.auth import User, Token, UserCreate
from ..settings import settings
from string import digits, ascii_uppercase
from random import choice

oauth2_scheme = OAuth2PasswordBearer(tokenUrl='/api/auth/sign-in')


def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
    return AuthService.validate_token(token)
    


class AuthService:

    @classmethod
    def create_verification_token(cls, length: int = 6) -> str:
        chars = ascii_uppercase + digits
        return ''.join(choice(chars) for _ in range(length))
   
    @classmethod
    def verify_password(cls, plain_password: str, hashed_password: str) -> bool:
        return bcrypt.verify(plain_password, hashed_password)

    @classmethod
    def hash_password(cls, password: str) -> str:
        return bcrypt.hash(password)

    @classmethod
    def validate_token(cls, token: str) -> User:
        exception = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Could not validate credentionals.',
            headers={
                'WWW_Authenticate': 'Bearer'
            },
        )
        try:
            payload = jwt.decode(
                token,
                settings.jwt_secret,
                algorithms=[settings.jwt_algorithm],
            )
        except JWTError:
            raise exception from None

        user_data = payload.get('user')

        try:
            user = User.parse_obj(user_data)
        except ValidationError:
            raise exception from None
        
        return user
    
    @classmethod
    def create_token(cls, user: tables.User) -> Token:
        user_data = User.from_orm(user)

        now = datetime.utcnow()
        payload = {
            'iat': now,
            'nbf': now,
            'exp': now + timedelta(seconds=settings.jwt_expiration),
            'sub': str(user_data.id),
            'user': user_data.dict(),
        }
        token = jwt.encode(
            payload,
            settings.jwt_secret,
            settings.jwt_algorithm
        )

        return Token(access_token=token)

    def __init__(self, session: Session = Depends(get_session)):
        self.session = session

    def _get_user(self, user_id: int) -> tables.User:
        return (
            self.session
            .query(tables.User)
            .filter(tables.User.id == user_id)
            .first()
        )

    def _get_user_by_username(self, username: str) -> tables.User:
        return (
            self.session
            .query(tables.User)
            .filter(tables.User.username == username)
            .first()
        )

    def register_new_user(self, user_data: UserCreate) -> User:
        if self.session.query(tables.User).filter(tables.User.username == user_data.username).count() > 0\
            or self.session.query(tables.User).filter(tables.User.email == user_data.email).count() > 0:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail='Username has already used.',
                headers={
                    'WWW_Authenticate': 'Bearer'
                },
            )
        user = tables.User(
            email=user_data.email,
            username=user_data.username,
            password_hash=self.hash_password(user_data.password),
        )
        
        self.session.add(user)
        self.session.commit()
        self.session.refresh(user)
        email_verification_token = tables.EmailVerificationToken(
            user_id = user.id,
            token = self.create_verification_token()
        )
        print(email_verification_token.token)
        self.session.add(email_verification_token)
        self.session.commit()

        return User.from_orm(user)

    def verify_email(self, verification_token: str) -> Token:
        exception = HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail='Not valid verification code.'
        )

        token = (self.session
                .query(tables.EmailVerificationToken)
                .filter(tables.EmailVerificationToken.token == verification_token)
                .first()
            )

        if not token:
            raise exception
        
        user = self._get_user(token.user_id)
        user.is_active = True
        self.session.delete(token)
        self.session.commit()
        
        return self.create_token(user=user)
        

    def authentificate_user(self, username: str, password: str) -> Token:
        exception = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Could not validate credentionals.',
            headers={
                'WWW_Authenticate': 'Bearer'
            },
        )

        user = self._get_user_by_username(username)

        if not user: 
            raise exception
        
        if not self.verify_password(password, user.password_hash):
            raise exception
        
        if not user.is_active:
            raise exception

        return self.create_token(user=user)
