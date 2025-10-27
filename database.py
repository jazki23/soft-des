import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, DeclarativeBase
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Get the Database URL from the environment variable
DATABASE_URL = os.getenv("DATABASE_URL")

if not DATABASE_URL:
    raise ValueError("No DATABASE_URL set in environment variables. Please create a .env file.")

# Create the SQLAlchemy engine
engine = create_engine(DATABASE_URL)

# Create a sessionmaker to manage database sessions.
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Create a base class for our declarative models.
class Base(DeclarativeBase):
    pass

# Dependency function to get a database session.
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
