from sqlalchemy.orm import Session
from fastapi import Depends, HTTPException,status
from ..database import get_session
from ..models.auth import User
from .. import tables


class UsersService:

    def __init__(self, session: Session = Depends(get_session)) -> None:
        self.session = session

    def get_user_by_email(self, email: str) -> User:
        return User.from_orm(
            self.session
            .query(tables.User)
            .filter(tables.User.email == email)
            .first()
        )
    
    def get_user_by_username(self, username: str) -> User:
        try:
            user = User.from_orm(
                self.session
                .query(tables.User)
                .filter(tables.User.username == username)
                .first()
            )
        except:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
        return user

    def get_user_by_id(self, user_id: int) -> User:
        try:
            user = User.from_orm(
                self.session
                .query(tables.User)
                .filter(tables.User.id == user_id)
                .first()
            )
        except:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
        return user