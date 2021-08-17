from typing import Optional, List
from fastapi import FastAPI, File, Form, UploadFile, HTTPException, status, Depends
from fastapi.responses import FileResponse, JSONResponse
from typing import Optional
from .api import router
import os
from .services.mailer import MailService
from fastapi_mail import MessageSchema,ConnectionConfig
from fastapi_mail.email_utils import DefaultChecker
from pydantic import EmailStr, BaseModel

class EmailSchema(BaseModel):
    email: List[EmailStr]

app = FastAPI()
app.include_router(router)

@app.get('/')
def index(name: Optional[str] = 'Semen', mailer: MailService = Depends()):
    return {'message': 'Hello, {}!'.format(name.capitalize())}



@app.get('/img/{filename}', response_class=FileResponse)
def get_file(filename: str):
    static_path = '../static/img/'
    if os.path.exists(os.path.join(static_path, filename)):
        file = FileResponse(os.path.join(static_path, filename))
    else:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    return file

    