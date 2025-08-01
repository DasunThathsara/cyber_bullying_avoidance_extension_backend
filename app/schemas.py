from pydantic import BaseModel
from typing import List, Optional
import datetime

class BlockedSearchBase(BaseModel):
    search_query: str

class BlockedSearchCreate(BlockedSearchBase):
    child_username: str

class BlockedSearch(BlockedSearchBase):
    id: int
    timestamp: datetime.datetime
    child_id: int

    class Config:
        orm_mode = True

class UserBase(BaseModel):
    username: str

class UserCreate(UserBase):
    password: str

class ChildCreate(UserCreate):
    pass

class ParentCreate(UserCreate):
    pass

class User(UserBase):
    id: int
    role: str
    parent_id: Optional[int] = None
    searches: List[BlockedSearch] = []

    class Config:
        orm_mode = True

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None