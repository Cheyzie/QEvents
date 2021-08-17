from jose import jwt
from pydantic import BaseSettings

class Settings(BaseSettings):
    server_host: str = '127.0.0.1'
    server_port: int = 8000
    database_url: str = 'sqlite:///./database.sqlite3'

    jwt_secret: str
    jwt_algorithm: str = 'HS256'
    jwt_expiration: int = 3600
    refresh_expiration: int = 7

    mail_username: str
    mail_password: str
    mail_from: str
    mail_port: int
    mail_server: str

settings = Settings(
    _env_file='.env',
    _env_file_encoding='utf-8',
)