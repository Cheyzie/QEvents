from typing import Optional, List
from fastapi import FastAPI, File, Form, UploadFile, HTTPException, status
from fastapi.responses import FileResponse
from typing import Optional
from .api import router
import os

app = FastAPI()
app.include_router(router)

@app.get('/')
def index(name: Optional[str] = 'Semen'):
    return {'message': 'Hello, {}!'.format(name.capitalize())}


@app.get('/img/{filename}', response_class=FileResponse)
def get_file(filename: str):
    static_path = '../static/img/'
    if os.path.exists(os.path.join(static_path, filename)):
        file = FileResponse(os.path.join(static_path, filename))
    else:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    return file

    