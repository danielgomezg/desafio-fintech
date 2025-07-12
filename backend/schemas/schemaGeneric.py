from typing import Generic, TypeVar, Optional
from pydantic import BaseModel

T = TypeVar('T')

class Response(BaseModel, Generic[T]):
    code: str
    message: str
    result: Optional[T]

class ResponseGet(BaseModel, Generic[T]):
    code: str
    result: Optional[T]
    count: int
    limit: int
    offset: int