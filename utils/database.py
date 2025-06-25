from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
import dotenv
import os

# Load environment variables from .env file
dotenv.load_dotenv()

DATABASE_URL = "postgresql://{POSTGRES_USER}:{POSTGRES_PASSWORD}@{POSTGRES_HOST}:{POSTGRES_PORT}/{POSTGRES_DB}".format(
    POSTGRES_USER=os.getenv("POSTGRES_USER"),
    POSTGRES_PASSWORD=os.getenv("POSTGRES_PASSWORD"),
    POSTGRES_HOST=os.getenv("POSTGRES_HOST"),
    POSTGRES_PORT=os.getenv("POSTGRES_PORT"),
    POSTGRES_DB=os.getenv("POSTGRES_DB"),
)

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()
