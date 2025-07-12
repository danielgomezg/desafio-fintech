from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.security import OAuth2AuthorizationCodeBearer
from jose import JWTError, jwt
import json
from fastapi.responses import JSONResponse

from api.endpoints import (user, profile)

#cors
from fastapi.middleware.cors import CORSMiddleware

#DB
from sqlalchemy.orm import Session
from database import get_db, engine, SessionLocal

# models
import re

from models import user as user_model
from models import profile as profile_model

from decouple import config

SECRET_KEY = config("SECRET_KEY")
ALGORITHM = config("ALGORITHM", default="HS256")

user_model.Base.metadata.create_all(bind=engine)
#secuenciaVT.Base.metadata.create_all(bind=engine)

app = FastAPI()

# Configurar CORS
origins = [
    "http://localhost:5173",
    "http://192.168.100.8:5173",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins= origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

#print("main")  # Añade esta línea
app.include_router(user.router)
app.include_router(profile.router)
