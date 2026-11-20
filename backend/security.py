import secrets
from fastapi import Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError
from sqlalchemy.orm import Session
from auth_utils import decode_access_token, password_version
from database import get_db
from models import User

oauth2_scheme = OAuth2PasswordBearer(tokenUrl='/api/auth/login', auto_error=False)

def normalize_role(role):
    return {'admin': 'administrator', 'admin (lead)': 'administrator', 'security analyst': 'analyst'}.get(role.strip().lower(), role.strip().lower())

def authenticate_token(token, db):
    unauthorized = HTTPException(401, 'Invalid or expired credentials', headers={'WWW-Authenticate': 'Bearer'})
    if not token:
        raise unauthorized
    try:
        payload = decode_access_token(token)
        subject = payload.get('sub', '')
        if not isinstance(subject, str) or not subject.isdecimal():
            raise unauthorized
        user = db.query(User).filter(User.id == int(subject)).first()
        if not user or not user.is_active:
            raise unauthorized
        if not secrets.compare_digest(str(payload.get('pv', '')), password_version(user.hashed_password)):
            raise unauthorized
        if normalize_role(user.role) not in {'analyst', 'administrator'}:
            raise unauthorized
        return user
    except (JWTError, ValueError, TypeError):
        raise unauthorized

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    return authenticate_token(token, db)

def require_admin(user: User = Depends(get_current_user)):
    if normalize_role(user.role) != 'administrator':
        raise HTTPException(403, 'Administrator permission required')
    return user
