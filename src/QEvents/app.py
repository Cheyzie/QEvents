from typing import Optional, List
from fastapi import FastAPI, File, Form, UploadFile, HTTPException, status
from fastapi.responses import FileResponse
from typing import Optional
from .api import router
import uuid, os

app = FastAPI()
app.include_router(router)

@app.get('/')
def index(name: Optional[str] = 'Semen'):
    return {'message': 'Hello, {}!'.format(name.capitalize())}


@app.get('/img/{filename}', response_class=FileResponse)
def get_file(filename: str):
    if os.path.exists(f'../static/img/{filename}'):
        file = FileResponse(f'../static/img/{filename}')
    else:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    return file

    