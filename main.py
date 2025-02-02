from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session
import models, schemas, utils
from database import engine, get_db
from models import User
from utils import create_access_token, hash_password,verify_reset_token,verify_password
import re
from email_service import send_reset_email

app = FastAPI()

# Add CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins, change "*" to specific origins for security
    allow_credentials=True,
    allow_methods=["*"],  # Allows all HTTP methods like GET, POST, etc.
    allow_headers=["*"],  # Allows all headers
)

# Create database tables
models.Base.metadata.create_all(bind=engine)

# Hardcoded admin credentials
ADMIN_EMAIL = "admin@example.com"
ADMIN_PASSWORD = "admin123"

# Define a new request model for login
class LoginRequest(BaseModel):
    email: str
    password: str

class AdminLoginRequest(BaseModel):
    email: EmailStr
    password: str

# Define a schema for the request body
class DeleteUserRequest(BaseModel):
    user_id: int

def validate_password(password: str):
    """Ensure the password meets complexity requirements."""
    if len(password) < 8:
        return "Password must be at least 8 characters long"
    if not re.search(r"[A-Z]", password):
        return "Password must contain at least one uppercase letter"
    if not re.search(r"\d", password):
        return "Password must contain at least one number"
    return None


@app.post("/signup")
def signup(user_data: schemas.UserCreate, db: Session = Depends(get_db)):
    # ✅ Check if passwords match
    if user_data.password != user_data.confirm_password:
        raise HTTPException(status_code=400, detail="Passwords do not match")

    # ✅ Validate password strength
    password_error = validate_password(user_data.password)
    if password_error:
        raise HTTPException(status_code=400, detail=password_error)

    # ✅ Check if email ends with @gmail.com only
    email_pattern = r"^[a-zA-Z0-9._%+-]+@gmail\.com$"  # Regex for @gmail.com only
    if not re.match(email_pattern, user_data.email):
        raise HTTPException(status_code=400, detail="Only @gmail.com emails are allowed")

    # ✅ Check if email already exists
    existing_user = db.query(models.User).filter(models.User.email == user_data.email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")

    # ✅ Hash password and save the user
    hashed_pwd = hash_password(user_data.password)
    new_user = models.User(name=user_data.name, email=user_data.email, hashed_password=hashed_pwd)
    
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return {"message": "User registered successfully"}

@app.post("/login")
def login(request: schemas.LoginRequest, db: Session = Depends(get_db)):
    # Special case: If user logs in with 123@gmal.com and ###
    if request.email == "123@gmail.com" and request.password == "###":
        access_token = create_access_token(data={"sub": request.email})
        return {
            "message": "Special user logged in successfully!",
            "access_token": access_token,
            "token_type": "bearer",
            "status": "Admin"
        }

    # Find user in the database
    user = db.query(models.User).filter(models.User.email == request.email).first()

    # Validate email & password
    if not user or not verify_password(request.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    # Generate JWT Token
    access_token = create_access_token(data={"sub": user.email})

    # Return token + user's name
    return {
        "message": "Login successful",
        "access_token": access_token,
        "token_type": "bearer",
        "name": user.name
    }

@app.post("/request-password-reset")
def request_password_reset(email: schemas.EmailSchema, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.email == email.email).first()
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if send_reset_email(email.email):
        return {"message": "Password reset link sent to your email"}
    else:
        raise HTTPException(status_code=500, detail="Error sending email")
    
@app.post("/reset-password")
def reset_password(data: schemas.ResetPasswordSchema, db: Session = Depends(get_db)):
    email = verify_reset_token(data.token)
    
    if not email:
        raise HTTPException(status_code=400, detail="Invalid or expired token")
    
    user = db.query(models.User).filter(models.User.email == email).first()
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.hashed_password = hash_password(data.new_password)
    db.commit()
    
    return {"message": "Password reset successful"}

# Retrieve all login records
@app.get("/user_logins", response_model=list[schemas.UserResponse])
def get_all_logins(db: Session = Depends(get_db)):
    # Query all users from the database
    users = db.query(models.User).all()
    if not users:
        raise HTTPException(status_code=404, detail="No users found")
    return users

# API to delete a user by ID (passed in the body)
@app.delete("/del-users", status_code=200)
def delete_user(request: DeleteUserRequest, db: Session = Depends(get_db)):
    # Query the user from the database
    user = db.query(models.User).filter(models.User.id == request.user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail=f"User with ID {request.user_id} not found")
    
    # Delete the user
    db.delete(user)
    db.commit()
    return {"message": f"User with ID {request.user_id} deleted successfully"}