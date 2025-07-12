from sqlalchemy.orm import Session, joinedload, load_only
from schemas.userSchema import UserSchema
from models.user import Usuario
from fastapi import HTTPException, status, Depends

# login
from datetime import datetime, timedelta

# impornaciones current user
from fastapi.security import OAuth2PasswordBearer
from typing import Optional, Tuple
from jose import jwt, JWTError

from passlib.hash import bcrypt
from decouple import config

import hashlib

# Variables
SECRET_KEY = config("SECRET_KEY")
ALGORITHM = config("ALGORITHM", default="HS256")

def get_user_by_id(db: Session, user_id: int):
    try:
        result = db.query(Usuario).filter(Usuario.id == user_id).first()
        return result
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"Error al buscar usuario {e}")


# funciones
def get_user_email(db: Session, email: str):
    try:
        result = db.query(Usuario).filter(Usuario.email == email).first()
        return result
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"Error al obtener user por email {e}")


def get_user_rut(db: Session, rut: str):
    try:
        result = db.query(Usuario).filter(Usuario.rut == rut).first()
        return result
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"Error al obtener user por rut {e}")


def get_user_all(db: Session, limit: int = 100, offset: int = 0):
    try:
        result = (db.query(Usuario).offset(offset).limit(limit).all())
        count = db.query(Usuario).count()
        return result, count
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"Error al obtener usuarios {e}")

def create_user(db: Session, user: UserSchema):
    try:
        _user = Usuario(
            email=user.email,
            password=user.password,
            rut=user.rut,
            profile_id=user.profile_id
        )

        db.add(_user)
        db.commit()
        db.refresh(_user)

        return _user
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"Error creando user {e}")


def delete_user(db: Session, user_id: int):
    try:
        user_to_delete = db.query(Usuario).filter(Usuario.id == user_id).first()
        if user_to_delete:
            db.commit()

            return user_id
        else:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                                detail=f"Ususario con id {user_id} no encontrada")
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Error eliminando usuario: {e}")


def authenticate_user(email: str, password: str, db: Session):
    try:
        userExist = get_user_email(db, email)
        if (userExist):
            passwordValid = Usuario.verify_password(password, userExist.password)
            if (passwordValid):
                return userExist
            else:
                return False
        return False
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"Error al autenticar usuario {e}")


def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()

    if expires_delta:
        expire = (datetime.utcnow() + expires_delta).timestamp()
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)

    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, key=SECRET_KEY, algorithm=ALGORITHM)

    return encoded_jwt


oauth2_scheme = OAuth2PasswordBearer("/token")


# Obtener usuario actual con el token
def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Credenciales no validas",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, key=SECRET_KEY, algorithms=[ALGORITHM])
        additional_info = payload["user"]
        user = additional_info["email"] + " " + additional_info["rut"] + " " + str(additional_info["profile_id"])
        # print(name_user)
        id_user = payload.get("sub")

        # Obtener el tiempo de expiración (exp) del token
        expiration_time = payload['exp']

        if id_user is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    return user, expiration_time


def get_user_disable_current(current_user_info: Tuple[str, Optional[str]] = Depends(get_current_user)):
    # Obtener la fecha y hora actual
    current_time = datetime.utcnow().timestamp()
    user, expiration_time = current_user_info
    # Validar si el token ha expirado
    if int(expiration_time) > int(current_time):
        print("El token no ha expirado aún.")
        return user, expiration_time
    else:
        print("El token ha expirado.")
        return (None, None)

def generate_score_from_rut(rut: str) -> int:
    hash_object = hashlib.sha256(rut.encode())
    hex_dig = hash_object.hexdigest()
    score = int(hex_dig[:6], 16) % 101  # 0 a 100
    return score
