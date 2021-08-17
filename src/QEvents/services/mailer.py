from pathlib import Path
from ..settings import settings
from fastapi_mail import FastMail, MessageSchema,ConnectionConfig
from typing import List
from pydantic import EmailStr
import ssl


class MailService():

    def __init__(self) -> None:
        conf = ConnectionConfig(
            MAIL_USERNAME = settings.mail_username,
            MAIL_PASSWORD = settings.mail_password,
            MAIL_FROM = settings.mail_from,
            MAIL_PORT = settings.mail_port,
            MAIL_SERVER = settings.mail_server,
            MAIL_TLS = True,
            MAIL_SSL = False,
            USE_CREDENTIALS = True,
            TEMPLATE_FOLDER = Path(__file__).parent.parent.parent.parent / 'static' / 'templates' / 'email'
        )
        self.fm = FastMail(conf)


    async def send_email_verification_message(self, emails: List[EmailStr], username: str, verification_token: str) -> None:
        body = {
            'username': username,
            'verification_token': verification_token,
        }
        print(body)
        message = MessageSchema(
            subject="Email verification.",
            recipients=emails,  # List of recipients, as many as you can pass 
            template_body=body,
            subtype="html"
            )

        await self.fm.send_message(message, template_name='verification_mail.html') 