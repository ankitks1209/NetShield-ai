"""Explicit local administrator provisioning; never exposed as a public API."""
import argparse
from getpass import getpass

from pydantic import TypeAdapter, EmailStr
from auth_utils import hash_password
from database import Base, engine, SessionLocal
from models import AuditLog, User
from schemas import validate_password


def main():
    parser = argparse.ArgumentParser(description='Create or promote a NetShield administrator')
    parser.add_argument('--email', required=True)
    parser.add_argument('--username', required=True)
    parser.add_argument('--name', required=True)
    args = parser.parse_args()
    email = str(TypeAdapter(EmailStr).validate_python(args.email)).lower()
    password = validate_password(getpass('Administrator password (12+ characters): '))
    if password != getpass('Confirm password: '):
        raise SystemExit('Passwords do not match')
    Base.metadata.create_all(bind=engine)
    with SessionLocal() as db:
        user = db.query(User).filter(User.email == email).first()
        if not user:
            user = User(email=email, username=args.username, full_name=args.name)
            db.add(user)
        user.hashed_password = hash_password(password)
        user.role = 'administrator'
        user.is_active = True
        db.flush()
        db.add(AuditLog(user_id=user.id, action='ADMIN_PROVISIONED', target=user.email,
                        details='Explicit local provisioning command; existing tokens invalidated'))
        db.commit()
    print('Administrator provisioned. Sign in through the application.')


if __name__ == '__main__':
    main()
