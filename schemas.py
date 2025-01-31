from pydantic import BaseModel, EmailStr

# Model for user creation
class UserCreate(BaseModel):
    name: str
    email: EmailStr  # Validates proper email format
    password: str
    confirm_password: str

# Model for login requests
class LoginRequest(BaseModel):
    email: EmailStr  # Validates proper email format
    password: str

# Model for user response
class UserResponse(BaseModel):
    id: int
    name: str
    email: str

    class Config:
        orm_mode = True
class ResetPassword(BaseModel):
    email: EmailStr
    new_password: str

# ✅ Schema for requesting a reset link
class EmailSchema(BaseModel):
    email: EmailStr

# ✅ Schema for resetting password
class ResetPasswordSchema(BaseModel):
    token: str
    new_password: str