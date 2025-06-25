from sqlalchemy import Column, Integer, String, DateTime
from utils.database import Base
import datetime

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    password = Column(String) 
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

class BlacklistedToken(Base):
    __tablename__ = "blacklisted_tokens"
    id = Column(Integer, primary_key=True, index=True)
    token = Column(String, unique=True, index=True)
    blacklisted_on = Column(DateTime, default=datetime.datetime.utcnow)
    expires_at = Column(DateTime)  # Untuk cleanup otomatis token yang sudah expired
