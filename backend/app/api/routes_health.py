from fastapi import APIRouter
from fastapi.responses import JSONResponse

router = APIRouter()


@router.get("/health")
async def health_check():
    return {"status": "ok", "service": "PII Log Leak Detector"}
