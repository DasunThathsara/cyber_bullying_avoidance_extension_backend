from pydantic import BaseModel
from typing import List, Optional
import datetime

class BlockedSearchBase(BaseModel):
    search_query: str

class BlockedSearchCreate(BlockedSearchBase):
    child_username: str

class BlockedSearch(BlockedSearchBase):
    id: str
    timestamp: datetime.datetime
    child_id: str

    class Config:
        from_attributes = True

class UserBase(BaseModel):
    username: str

class UserCreate(UserBase):
    password: str

class ChildCreate(UserCreate):
    pass

class ParentCreate(UserCreate):
    pass

class User(UserBase):
    id: str
    role: str
    parent_id: Optional[str] = None
    searches: List[BlockedSearch] = []

    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

class ParentLogoutVerification(BaseModel):
    child_username: str
    parent_password: str