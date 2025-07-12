from models import profile
from models.profile import Profile
from fastapi import APIRouter, HTTPException, Path, Depends
from sqlalchemy.orm import Session
from database import get_db
from crud.profile import create_profile, get_profile_by_id, get_profile_all, delete_profile
from schemas.profileSchema import ProfileSchema
from schemas.schemaGeneric import ResponseGet, Response

from crud.user import get_user_disable_current
from typing import Optional, Tuple

router = APIRouter()

@router.get('/profiles')
def get_profiles(db: Session = Depends(get_db), current_user_info: Tuple[str, str] = Depends(get_user_disable_current), limit: int = 25, offset: int = 0):
    email_user, expiration_time = current_user_info
    # Se valida la expiracion del token
    if expiration_time is None:
        return Response(code="401", message="token-exp", result=[])

    result = get_profile_all(db, limit, offset)
    return ResponseGet(code="200", result=result, limit= limit, offset = offset, count = 3).model_dump()

@router.get("/profile/{id}")
def get_profile(id: int, db: Session = Depends(get_db), current_user_info: Tuple[str, str] = Depends(get_user_disable_current)):
    name_user, expiration_time = current_user_info
    # Se valida la expiracion del token
    if expiration_time is None:
        return Response(code="401", message="token-exp", result=[])

    result = get_profile_by_id(db, id)
    if result is None:
        raise HTTPException(status_code=404, detail="Perfil no encontrado")

    return ResponseGet(code="200", result=result, limit=0, offset=0, count=0).model_dump()

@router.post('/profile')
def create(request: ProfileSchema, db: Session = Depends(get_db)):
    name_user, expiration_time = 1, True #current_user_info
    # Se valida la expiracion del token
    if expiration_time is None:
        return Response(code="401", message="token-exp", result=[])

    if(len(request.name) == 0):
        return  Response(code = "400", message = "Nombre no valido", result = [])

    _profile = create_profile(db, request)
    return Response(code = "201", message = "Perfil creado", result = _profile).model_dump()

@router.delete('/profile/{id}')
def delete(id: int, db: Session = Depends(get_db), current_user_info: Tuple[str, str] = Depends(get_user_disable_current)):
    name_user, expiration_time = current_user_info
    # Se valida la expiracion del token
    if expiration_time is None:
        return Response(code="401", message="token-exp", result=[])

    _profile = delete_profile(db, id)
    return Response(code = "201", message = f"Perfil con id {id} eliminado", result = _profile).model_dump()