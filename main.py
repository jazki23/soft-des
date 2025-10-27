import os
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from sqlalchemy import or_
from datetime import datetime, timedelta, timezone
from typing import Annotated
from dotenv import load_dotenv

# Password Hashing
from passlib.context import CryptContext

# JWT
from jose import JWTError, jwt

# Import all our modules
import models, schemas
from database import engine, get_db

# --- Configuration ---

# Load environment variables
load_dotenv()

# 1. Create database tables
models.Base.metadata.create_all(bind=engine)

# 2. Security Configuration
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# 3. JWT Configuration
SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    raise ValueError("No SECRET_KEY set in environment variables. Please create a .env file.")

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


# --- FastAPI App ---
app = FastAPI()

# --- CORS Middleware ---
# (This allows your frontend to talk to your backend)
origins = ["*"] # Allows all origins

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"], # Allows all methods (GET, POST, etc.)
    allow_headers=["*"], # Allows all headers
)


# --- Security Helper Functions ---

def verify_password(plain_password, hashed_password):
    """Checks if the plain password matches the hashed password."""
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    """Generates a hash for a plain password."""
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    """Creates a new JWT access token."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)

    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# --- Database Helper Functions ---

def get_user(db: Session, username: str):
    """Fetches a user from the database by their username."""
    return db.query(models.User).filter(models.User.username == username).first()

# --- Dependency ---

# THIS IS THE CRITICAL FIX
# This is now a 'def' (sync) function, not 'async def'.
# This tells FastAPI to run it in a threadpool, which prevents the deadlock.
def get_current_user(
    token: Annotated[str, Depends(oauth2_scheme)], 
    db: Annotated[Session, Depends(get_db)]
):
    """
    Dependency to get the current user from a token.
    This is used to protect endpoints.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = schemas.TokenData(username=username)
    except JWTError:
        raise credentials_exception

    user = get_user(db, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user


# --- API Endpoints ---

@app.post("/signup", response_model=schemas.UserPublic)
def signup(user: schemas.UserCreate, db: Session = Depends(get_db)):
    """
    Sign-up endpoint.
    Creates a new user in the database.
    """
    # Check if user already exists
    db_user = db.query(models.User).filter(
        or_(models.User.email == user.email, models.User.username == user.username)
    ).first()

    if db_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, 
            detail="Email or username already registered"
        )

    # Hash the password (and truncate to 72 bytes)
    hashed_password = get_password_hash(user.password[:72])

    # Create the new user object
    db_user = models.User(
        username=user.username, 
        email=user.email, 
        hashed_password=hashed_password
    )

    # Add to database and commit
    db.add(db_user)
    db.commit()
    db.refresh(db_user)

    return db_user


@app.post("/login", response_model=schemas.Token)
async def login(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: Annotated[Session, Depends(get_db)]
):
    """
    Login endpoint.
    Takes username and password from form data.
    Returns a JWT access token.
    """
    # Authenticate the user
    user = get_user(db, form_data.username)
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Create the access token
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )

    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/users/me", response_model=schemas.UserPublic)
async def read_users_me(
    current_user: Annotated[models.User, Depends(get_current_user)]
):
    """
    Protected endpoint.
    Returns the data for the currently authenticated user.
    """
    return current_user

# --- Static HTML Page Endpoints ---
# (These routes serve your HTML files)

@app.get("/", response_class=FileResponse)
async def read_index():
    """Serves the main login page."""
    return "index.html"

@app.get("/register.html", response_class=FileResponse)
async def read_register():
    """Serves the registration page."""
    return "register.html"

@app.get("/dashboard.html", response_class=FileResponse)
async def read_dashboard():
    """Serves the main protected dashboard page."""
    return "dashboard.html"
