from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
import dotenv
import os

# Load environment variables from .env file
dotenv.load_dotenv()

# Try to get DATABASE_URL first, then construct from individual vars
DATABASE_URL = os.getenv("DATABASE_URL")

if not DATABASE_URL:
    DATABASE_URL = "postgresql://{POSTGRES_USER}:{POSTGRES_PASSWORD}@{POSTGRES_HOST}:{POSTGRES_PORT}/{POSTGRES_DB}".format(
        POSTGRES_USER=os.getenv("POSTGRES_USER"),
        POSTGRES_PASSWORD=os.getenv("POSTGRES_PASSWORD"),
        POSTGRES_HOST=os.getenv("POSTGRES_HOST"),
        POSTGRES_PORT=os.getenv("POSTGRES_PORT"),
        POSTGRES_DB=os.getenv("POSTGRES_DB"),
    )

# Add connection parameters for better reliability
engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    pool_recycle=300,
    connect_args={
        "connect_timeout": 30,
        "application_name": "comot-api"
    }
)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()
