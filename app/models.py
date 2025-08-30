from sqlalchemy import Boolean, Column, Integer, String, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from .firebase import Base
import datetime

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    role = Column(String, default="child")
    
    parent_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    
    parent = relationship("User", remote_side=[id], back_populates="children")
    children = relationship("User", back_populates="parent")
    searches = relationship("BlockedSearch", back_populates="child")


class BlockedSearch(Base):
    __tablename__ = "blocked_searches"

    id = Column(Integer, primary_key=True, index=True)
    search_query = Column(String, index=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    
    child_id = Column(Integer, ForeignKey("users.id"))
    child = relationship("User", back_populates="searches")
