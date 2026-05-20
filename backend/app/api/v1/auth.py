from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException

from app.core.constants import ALLOWED_ROLES
from app.core.security import (
    create_access_token,
    get_current_user,
    hash_password,
    verify_password,
)
from app.db.mongodb import users
from app.schemas.auth import LoginUser, RegisterUser

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/register")
def create_user(user: RegisterUser):
    email = user.email.lower().strip()
    role = user.role.lower().strip() if user.role else "viewer"
    if role not in ALLOWED_ROLES:
        raise HTTPException(status_code=400, detail="Invalid role")
    if users.find_one({"email": email}):
        raise HTTPException(status_code=400, detail="Email already registered")

    users.insert_one(
        {
            "name": user.name,
            "email": email,
            "password_hash": hash_password(user.password),
            "role": role,
            "created_at": datetime.now(timezone.utc),
        }
    )
    return {"message": "user registered successfully"}


@router.post("/login")
def login(user: LoginUser):
    email = user.email.lower().strip()
    db_user = users.find_one({"email": email})
    if not db_user or not verify_password(user.password, db_user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    token = create_access_token(
        {
            "sub": db_user["email"],
            "role": db_user.get("role", "viewer"),
            "name": db_user.get("name", ""),
        }
    )

    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "name": db_user.get("name", ""),
            "email": db_user["email"],
            "role": db_user.get("role", "viewer"),
        },
    }


@router.get("/me")
def me(current_user=Depends(get_current_user)):
    return current_user
