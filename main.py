from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session
import models, schemas, utils
from database import engine, get_db
from models import User
from utils import create_access_token, hash_password

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
@app.post("/signup")
def signup(user_data: schemas.UserCreate, db: Session = Depends(get_db)):
    # Check if email already exists
    existing_user = db.query(models.User).filter(models.User.email == user_data.email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")

    # Hash password before storing
    hashed_pwd = hash_password(user_data.password)
    
    # Create a new user
    new_user = models.User(
        name=user_data.name,
        email=user_data.email,
        hashed_password=hashed_pwd  # Store hashed password
    )
    
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    return {"message": "User registered successfully"}
from utils import verify_password, create_access_token

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

@app.post("/admin/login")
def admin_login(request: AdminLoginRequest):
    # Validate admin credentials
    if request.email == ADMIN_EMAIL and request.password == ADMIN_PASSWORD:
        return {"message": "Admin login successful!"}
    else:
        raise HTTPException(
            status_code=401, detail="Invalid admin credentials"
        )
# Retrieve all login records
@app.get("/user_logins", response_model=list[schemas.UserResponse])
def get_all_logins(db: Session = Depends(get_db)):
    # Query all users from the database
    users = db.query(models.User).all()
    if not users:
        raise HTTPException(status_code=404, detail="No users found")
    return users

# API to delete a user by ID (passed in the body)
@app.delete("/users", status_code=200)
def delete_user(request: DeleteUserRequest, db: Session = Depends(get_db)):
    # Query the user from the database
    user = db.query(models.User).filter(models.User.id == request.user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail=f"User with ID {request.user_id} not found")
    
    # Delete the user
    db.delete(user)
    db.commit()
    return {"message": f"User with ID {request.user_id} deleted successfully"}