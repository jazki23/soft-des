from pydantic import BaseModel, EmailStr, Field

# --- User Schemas ---

# Base schema for a User
class UserBase(BaseModel):
    username: str
    email: EmailStr

# Schema for user creation (sign-up)
# This includes the password with validation rules.
class UserCreate(UserBase):
    password: str = Field(..., min_length=8, max_length=72)

# Schema for reading user data (public)
# This inherits from UserBase and adds the 'id' and 'is_active'.
# It does *not* include the password.
class UserPublic(UserBase):
    id: int
    is_active: bool

    # This config allows Pydantic to read data from ORM models.
    class Config:
        from_attributes = True

# --- Token Schemas ---

# Schema for the JWT access token
class Token(BaseModel):
    access_token: str
    token_type: str

# Schema for the data encoded in the JWT
class TokenData(BaseModel):
    username: str | None = None
