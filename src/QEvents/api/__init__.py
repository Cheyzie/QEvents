from fastapi import APIRouter

from .auth import router as auth_router
from .events import router as events_router

router = APIRouter(prefix='/api')
router.include_router(auth_router)
router.include_router(events_router)