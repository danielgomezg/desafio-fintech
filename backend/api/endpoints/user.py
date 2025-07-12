from models import user
from models.user import Usuario
from fastapi import APIRouter, HTTPException, Path, Depends, status
from sqlalchemy.orm import Session
from database import get_db
from crud.user import (create_user, get_user_all, get_user_email, authenticate_user, create_access_token,
                       get_user_disable_current, get_user_by_id, delete_user, generate_score_from_rut, get_user_rut)
from schemas.userSchema import UserSchema, UserSchemaLogin
from schemas.schemaGeneric import Response, ResponseGet
import re
from typing import Tuple
import json
# login
from datetime import datetime, timedelta
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from crud.profile import get_profile_by_id
from decouple import config
from datetime import datetime

router = APIRouter()
oauth2_scheme = OAuth2PasswordBearer("/token")

# Variables

SECRET_KEY = config("SECRET_KEY")
ALGORITHM = config("ALGORITHM", default="HS256")


@router.get("/user/{id}")
def get_user(id: int, db: Session = Depends(get_db),
             current_user_info: Tuple[str, str] = Depends(get_user_disable_current)):
    email_user, expiration_time = current_user_info
    # Se valida la expiracion del token
    if expiration_time is None:
        return Response(code="401", message="token-exp", result=[])

    result = get_user_by_id(db, id)
    if result is None:
        return Response(code="404", result=[], message="Usuario no encontrado").model_dump()
    return Response(code="200", message="Usuario encontrado", result=result).model_dump()


@router.get('/users')
def get_users(db: Session = Depends(get_db), current_user_info: Tuple[str, str] = Depends(get_user_disable_current),
              limit: int = 300, offset: int = 0):
    name_user, expiration_time = current_user_info
    # Se valida la expiracion del token
    if expiration_time is None:
        return Response(code="401", message="token-exp", result=[])

    result, count = get_user_all(db, limit, offset)
    if not result:
        return ResponseGet(code="404", result=[], limit=limit, offset=offset, count=0).model_dump()
    return ResponseGet(code="200", result=result, limit=limit, offset=offset, count=count).model_dump()

@router.post('/user')
def create(request: UserSchema, db: Session = Depends(get_db) ):
    #name_user, expiration_time = current_user_info
    # Se valida la expiracion del token
    #if expiration_time is None:
     #   return Response(code="401", message="token-exp", result=[])

    patron = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    email = str(request.email)
    if (re.match(patron, email) is None):
        return Response(code="400", message="Correo inválido", result=[])

    # valida si el mail ya esta registrado
    existeEmail = get_user_email(db, email)
    if (existeEmail):
        return Response(code="400", message="Correo ya registrado", result=[])

    patron_rut = r'^\d{1,8}-[\dkK]$'
    rut = str(request.rut.replace(".", ""))

    if not re.match(patron_rut, rut):
        return Response(code="400", message="Rut inválido", result=[])

    user_rut = get_user_rut(db, request.rut)
    if user_rut:
        return Response(code="400", message="Rut ya registrado", result=[])

    id_perfil = get_profile_by_id(db, request.profile_id)
    if (not id_perfil):
        return Response(code="400", message="id perfil no valido", result=[])

    _user = create_user(db, request)
    return Response(code="201", message=f"Usuario {_user.email} creado", result=_user).model_dump()

@router.delete('/user/{id}')
def delete(id: int, db: Session = Depends(get_db),
           current_user_info: Tuple[str, str] = Depends(get_user_disable_current)):
    name_user, expiration_time = current_user_info
    # Se valida la expiracion del token
    if expiration_time is None:
        return Response(code="401", message="token-exp", result=[])

    _user = delete_user(db, id)
    return Response(code="201", message=f"Usuario con id {id} eliminado", result=_user).model_dump()


@router.post('/login')
def login_access(request: UserSchemaLogin, db: Session = Depends(get_db)):
    _user = authenticate_user(request.email, request.password, db)
    if (_user):
        access_token_expires = timedelta(minutes=480)
        user_id = str(_user.id)

        additional_info = {
            "email": _user.email,
            "rut": _user.rut,
            "id": _user.id,
            "profile_id": _user.profile_id,
        }

        access_token = create_access_token(data={"sub": user_id, "profile": _user.profile_id, "user": additional_info},
                                           expires_delta=access_token_expires)

        expire_seconds = access_token_expires.total_seconds()

        return JSONResponse(
            content=Response(
                code="201",
                message="Usuario loggeado correctamente",
                result={
                    "access_token": access_token,
                    "token_type": "bearer",
                    "expire_token": expire_seconds,
                    "user": additional_info
                },
            ).model_dump(),
            status_code=201,
        )
    else:
        return Response(code="401", message="Usuario incorrecto", result=[])


@router.post('/token')
def login_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    _user = authenticate_user(form_data.username, form_data.password, db)
    if (_user):
        access_token_expires = timedelta(minutes=480)
        user_id = str(_user.id)

        additional_info = {
            "email": _user.email,
            "rut": _user.rut,
            "id": _user.id,
            "profile_id": _user.profile_id,
        }

        access_token = create_access_token(data={"sub": user_id, "profile": _user.profile_id, "user": additional_info},
                                           expires_delta=access_token_expires)

        # NEW
        expire_seconds = access_token_expires.total_seconds()

        return {"access_token": access_token, "token_type": "bearer", "expire_token": expire_seconds}
    else:
        raise HTTPException(status_code=401, detail="Usuario incorrecto")

#score
@router.get("/score/{rut}")
def get_score(rut: str, current_user_info: Tuple[str, str] = Depends(get_user_disable_current)):
    date_user = current_user_info[0].split(" ")
    user_rut = date_user[1]
    profile_id = int(date_user[2])

    # Si no es admin, solo puede consultar su propio RUT
    if profile_id != 1 and rut != user_rut:
        print(date_user)
        raise HTTPException(status_code=403, detail="No tienes permisos para ver este RUT")

    score = generate_score_from_rut(rut)
    return {
        "rut": rut,
        "score": score,
        "fecha": datetime.utcnow().isoformat() + "Z"
    }
