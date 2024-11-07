from fastapi import FastAPI, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session
import models, schemas, utils
from database import engine, get_db
from models import User

app = FastAPI()

# Create database tables
models.Base.metadata.create_all(bind=engine)

# Define a new request model for login
class LoginRequest(BaseModel):
    email: str
    password: str

@app.post("/signup")
def signup(user: schemas.UserCreate, db: Session = Depends(get_db)):
    if user.password != user.confirm_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Passwords do not match",
        )
    
    existing_user = db.query(User).filter(User.email == user.email).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email is already registered",
        )
    
    hashed_password = utils.hash_password(user.password)
    new_user = User(name=user.name, email=user.email, hashed_password=hashed_password)
    db.add(new_user)
    db.commit()
    
    # No user data is returned, just a success message
    return {"message": "User registered successfully!"}


@app.post("/login")
def login(user: LoginRequest, db: Session = Depends(get_db)):
    # Verify email and password
    user_record = db.query(User).filter(User.email == user.email).first()
    if not user_record or not utils.verify_password(user.password, user_record.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )
    
    return {"message": "Login successful!"}
