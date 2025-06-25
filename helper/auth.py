from fastapi import HTTPException
from jose import jwt, JWTError
from passlib.hash import bcrypt
import datetime
import os
import dotenv

# Load environment variables
dotenv.load_dotenv()

SECRET_KEY = os.getenv("JWT_SECRET_KEY", "your_secret_key_please_change_this")
ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
EXPIRE_HOURS = int(os.getenv("JWT_EXPIRE_HOURS", "24"))

def hash_password(password: str):
    return bcrypt.hash(password)

def verify_password(plain_password, hashed_password):
    return bcrypt.verify(plain_password, hashed_password)

def create_access_token(data: dict):
    expire = datetime.datetime.utcnow() + datetime.timedelta(hours=EXPIRE_HOURS)
    data.update({"exp": expire})
    return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)

def decode_token(token: str):
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
