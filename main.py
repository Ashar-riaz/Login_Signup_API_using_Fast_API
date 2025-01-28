from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session
import models, schemas, utils
from database import engine, get_db
from models import User

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
def signup(user: schemas.UserCreate, db: Session = Depends(get_db)):
    # Validate password confirmation
    if user.password != user.confirm_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Passwords do not match",
        )

    # Check if email already exists
    existing_user = db.query(User).filter(User.email == user.email).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email is already registered",
        )

    # Hash the password
    hashed_password = utils.hash_password(user.password)

    # Create the new user in the database
    new_user = User(name=user.name, email=user.email, hashed_password=hashed_password)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    # Return a success message instead of the user data
    return {"message": "User successfully created!"}


@app.post("/login")
def login(user: schemas.LoginRequest, db: Session = Depends(get_db)):
    # Verify email and password
    user_record = db.query(User).filter(User.email == user.email).first()
    if not user_record or not utils.verify_password(user.password, user_record.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    return {"message": "Login successful!"}

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