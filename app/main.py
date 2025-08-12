from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from datetime import timedelta
from . import crud, schemas, security

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

async def get_current_user(token: str = Depends(security.oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = security.jwt.decode(token, security.SECRET_KEY, algorithms=[security.ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except security.JWTError:
        raise credentials_exception
    user = crud.get_user_by_username(username)
    if user is None:
        raise credentials_exception
    return user

async def get_current_active_parent(current_user: dict = Depends(get_current_user)):
    if current_user.get("role") != "parent":
        raise HTTPException(status_code=403, detail="Not a parent account!")
    return current_user

@app.post("/token", response_model=schemas.Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = crud.get_user_by_username(form_data.username)
    if not user or not security.verify_password(form_data.password, user.get("hashed_password", "")):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=security.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = security.create_access_token(
        data={"sub": user["username"]}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/users/register", response_model=schemas.User, status_code=status.HTTP_201_CREATED)
def create_parent(user: schemas.ParentCreate):
    db_user = crud.get_user_by_username(user.username)
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    return crud.create_parent_user(user)

@app.get("/users/me", response_model=schemas.User)
async def read_users_me(current_user: dict = Depends(get_current_active_parent)):
    return current_user

@app.post("/children/", response_model=schemas.User, status_code=status.HTTP_201_CREATED)
def create_child_for_parent(
    child: schemas.ChildCreate, 
    current_user: dict = Depends(get_current_active_parent)
):
    db_child = crud.get_user_by_username(child.username)
    if db_child:
        raise HTTPException(status_code=400, detail="Username already registered")
    return crud.create_child_user(child, current_user["id"])

@app.get("/children/", response_model=list[schemas.User])
def read_children_for_parent(current_user: dict = Depends(get_current_active_parent)):
    return crud.get_children_by_parent(current_user["id"])

@app.post("/searches/log", response_model=schemas.BlockedSearch, status_code=status.HTTP_201_CREATED)
def log_blocked_search(search: schemas.BlockedSearchCreate):
    logged_search = crud.create_blocked_search(search)
    if not logged_search:
        raise HTTPException(status_code=404, detail="Child user not found")
    return logged_search

@app.get("/searches/{child_id}", response_model=list[schemas.BlockedSearch])
def read_searches_for_child(
    child_id: str, 
    current_user: dict = Depends(get_current_active_parent)
):
    child = crud.get_user(child_id)
    if not child or child.get("parent_id") != current_user["id"]:
        raise HTTPException(status_code=403, detail="Not authorized to view this child's data")
    return crud.get_searches_by_child(child_id)
