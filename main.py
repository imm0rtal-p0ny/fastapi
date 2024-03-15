from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel, EmailStr
from typing import List
from datetime import datetime, timedelta
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, MetaData
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from hashlib import sha256
from cachetools import TTLCache

app = FastAPI()

SECRET_KEY = "your_secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

DATABASE_URL = "mysql+aiomysql://user:password@localhost/database"

engine = create_engine(DATABASE_URL, echo=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

cache = TTLCache(maxsize=1000, ttl=300)  # 5-minute TTL


class User(BaseModel):
    email: EmailStr


class UserInDB(User):
    hashed_password: str


class Post(BaseModel):
    text: str


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    email: str


# User model
class UserModel(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)

    posts = relationship("PostModel", back_populates="owner")


class PostModel(Base):
    __tablename__ = "posts"

    id = Column(Integer, primary_key=True, index=True)
    text = Column(String)
    owner_id = Column(Integer, ForeignKey("users.id"))

    owner = relationship("UserModel", back_populates="posts")


def verify_password(plain_password, hashed_password):
    return sha256(plain_password.encode()).hexdigest() == hashed_password


def get_user(email: str, db: Session):
    return db.query(UserModel).filter(UserModel.email == email).first()


async def authenticate_user(email: str, password: str, db: Session):
    user = get_user(email, db)
    if not user or not verify_password(password, user.hashed_password):
        return False
    return user


def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=401, detail="Could not validate credentials"
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
        token_data = TokenData(email=email)
    except JWTError:
        raise credentials_exception
    return token_data


@app.post("/signup/", response_model=Token)
async def signup(email: str, password: str, db: Session = Depends(SessionLocal)):
    db_user = get_user(email, db)
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    hashed_password = sha256(password.encode()).hexdigest()
    db_user = UserModel(email=email, hashed_password=hashed_password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": email}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


@app.post("/login/", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(SessionLocal)):
    user = await authenticate_user(form_data.username, form_data.password, db)
    if not user:
        raise HTTPException(status_code=401, detail="Incorrect email or password")
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


@app.post("/addPost/", response_model=str)
async def add_post(post: Post, current_user: TokenData = Depends(get_current_user), db: Session = Depends(SessionLocal)):
    if len(post.text) > 1024 * 1024:
        raise HTTPException(status_code=400, detail="Payload size too large")
    db_post = PostModel(text=post.text, owner_id=current_user.email)
    db.add(db_post)
    db.commit()
    db.refresh(db_post)
    return db_post.id


@app.get("/getPosts/", response_model=List[Post])
async def get_posts(current_user: TokenData = Depends(get_current_user), db: Session = Depends(SessionLocal)):
    if current_user.email in cache:
        return cache[current_user.email]
    db_user = get_user(current_user.email, db)
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")
    user_posts = db_user.posts
    posts = [Post(text=post.text) for post in user_posts]
    cache[current_user.email] = posts
    return posts


@app.delete("/deletePost/", response_model=str)
async def delete_post(post_id: int, current_user: TokenData = Depends(get_current_user), db: Session = Depends(SessionLocal)):
    db_post = db.query(PostModel).filter(PostModel.id == post_id).first()
    if not db_post or db_post.owner_id != current_user.email:
        raise HTTPException(status_code=404, detail="Post not found or unauthorized")
    db.delete(db_post)
    db.commit()
    return "Post deleted successfully"
