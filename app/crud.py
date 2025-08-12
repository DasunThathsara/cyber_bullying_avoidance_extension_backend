from . import schemas, security
from .firebase import db
from datetime import datetime
from firebase_admin import firestore

def _user_to_dict(user: schemas.UserBase, password: str = None):
    data = {"username": user.username}
    if password:
        data["hashed_password"] = security.get_password_hash(password)
    return data

def get_user(user_id: str):
    doc_ref = db.collection("users").document(user_id)
    doc = doc_ref.get()
    if doc.exists:
        return {"id": doc.id, **doc.to_dict()}
    return None

def get_user_by_username(username: str):
    query = db.collection("users").where("username", "==", username).limit(1)
    docs = query.stream()
    for doc in docs:
        return {"id": doc.id, **doc.to_dict()}
    return None

def create_parent_user(user: schemas.ParentCreate):
    user_data = _user_to_dict(user, user.password) | {
        "role": "parent",
        "parent_id": None
    }
    _, doc_ref = db.collection("users").add(user_data)
    return {"id": doc_ref.id, **user_data}

def create_child_user(child: schemas.ChildCreate, parent_id: str):
    user_data = _user_to_dict(child, child.password) | {
        "role": "child",
        "parent_id": parent_id
    }
    _, doc_ref = db.collection("users").add(user_data)
    return {"id": doc_ref.id, **user_data}

def get_children_by_parent(parent_id: str):
    query = db.collection("users").where("parent_id", "==", parent_id)
    docs = query.stream()
    return [{"id": doc.id, **doc.to_dict()} for doc in docs]

def create_blocked_search(search: schemas.BlockedSearchCreate):
    child = get_user_by_username(search.child_username)
    if not child:
        return None
    search_data = {
        "search_query": search.search_query,
        "child_id": child["id"],
        "timestamp": datetime.utcnow()
    }
    _, doc_ref = db.collection("searches").add(search_data)
    return {"id": doc_ref.id, **search_data}

def get_searches_by_child(child_id: str):
    docs = db.collection("searches").where("child_id", "==", child_id).stream()
    results = [{"id": doc.id, **doc.to_dict()} for doc in docs]
    results.sort(key=lambda x: x.get("timestamp", datetime.min), reverse=True)
    return results
