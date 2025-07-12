from typing import Generic, TypeVar, Optional
from pydantic import BaseModel, Field

T = TypeVar('T')


class ProfileSchema(BaseModel):
   # id: Optional[int] = None
    name: str
    description: str
