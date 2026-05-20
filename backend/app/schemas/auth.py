from pydantic import BaseModel, EmailStr, Field


class RegisterUser(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=256)
    role: str = Field(default="viewer", max_length=32)


class LoginUser(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=1, max_length=256)
