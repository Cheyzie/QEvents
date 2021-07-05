from typing import Optional
from fastapi import FastAPI
from typing import Optional
from .api import router

app = FastAPI()
app.include_router(router)

@app.get('/')
def index(name: Optional[str] = 'Semen'):
    return {'message': 'Hello, {}!'.format(name.capitalize())}