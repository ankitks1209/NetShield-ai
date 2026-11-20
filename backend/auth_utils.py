import hashlib
from datetime import datetime, timedelta, timezone
from jose import jwt
from passlib.context import CryptContext
from config import settings

pwd_context = CryptContext(schemes=['bcrypt'], deprecated='auto')

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return pwd_context.verify(plain_password, hashed_password)
    except (ValueError, TypeError):
        return False

def password_version(hashed_password):
    return hashlib.sha256(hashed_password.encode()).hexdigest()

def create_access_token(data: dict) -> str:
    now = datetime.now(timezone.utc)
    return jwt.encode({**data, 'iat': now, 'exp': now + timedelta(minutes=settings.token_minutes)}, settings.jwt_secret, algorithm='HS256')

def decode_access_token(token: str) -> dict:
    return jwt.decode(token, settings.jwt_secret, algorithms=['HS256'], options={'require_exp': True, 'require_sub': True})
