from sqlalchemy.orm import Session
from . import models, schemas, security

# User CRUD
def get_user(db: Session, user_id: int):
    return db.query(models.User).filter(models.User.id == user_id).first()

def get_user_by_username(db: Session, username: str):
    return db.query(models.User).filter(models.User.username == username).first()

def create_parent_user(db: Session, user: schemas.ParentCreate):
    hashed_password = security.get_password_hash(user.password)
    db_user = models.User(username=user.username, hashed_password=hashed_password, role="parent")
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

def create_child_user(db: Session, child: schemas.ChildCreate, parent_id: int):
    hashed_password = security.get_password_hash(child.password)
    db_child = models.User(username=child.username, hashed_password=hashed_password, role="child", parent_id=parent_id)
    db.add(db_child)
    db.commit()
    db.refresh(db_child)
    return db_child

def get_children_by_parent(db: Session, parent_id: int):
    return db.query(models.User).filter(models.User.parent_id == parent_id).all()

# BlockedSearch CRUD
def create_blocked_search(db: Session, search: schemas.BlockedSearchCreate):
    child = get_user_by_username(db, username=search.child_username)
    if not child:
        return None
    db_search = models.BlockedSearch(search_query=search.search_query, child_id=child.id)
    db.add(db_search)
    db.commit()
    db.refresh(db_search)
    return db_search

def get_searches_by_child(db: Session, child_id: int):
    return db.query(models.BlockedSearch).filter(models.BlockedSearch.child_id == child_id).order_by(models.BlockedSearch.timestamp.desc()).all()