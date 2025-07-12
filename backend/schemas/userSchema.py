from typing import TypeVar, Optional
from pydantic import BaseModel

T = TypeVar('T')

class UserSchema(BaseModel):
    #id: Optional[int] = None
    email: str
    password: str
    rut: str = None
    profile_id: int

class UserSchemaLogin(BaseModel):
    email: str
    password: str

