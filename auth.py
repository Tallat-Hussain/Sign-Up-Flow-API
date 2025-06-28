from fastapi import APIRouter, HTTPException, Depends, status
from sqlalchemy.orm import Session
#from .. import schemas, models, hashing, database
import schemas
import models
import hashing
import database
import jwt_token
import token as token_handler
from datetime import timedelta
from typing import List
import oauth2
from fastapi.security import OAuth2PasswordRequestForm

router = APIRouter(
    tags = ["Authentication"]
)

def get_db():
    db = database.SessionLocal()
    try:
        yield db
    finally:
        db.close()

@router.post("/signup", response_model=schemas.ResponseUser, status_code=status.HTTP_201_CREATED)
def signup(request: schemas.CreateUser, db: Session = Depends(database.get_db)):
    if len(request.password) < 8:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,detail='Password is too short')
    if db.query(models.User).filter(models.User.email == request.email).first():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered")
    
    if db.query(models.User).filter(models.User.username == request.username).first():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username already taken")
    
    hashed_password = hashing.Hash.bcrypt(request.password)
    new_user = models.User(
        username=request.username,
        email=request.email,
        password=hashed_password
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

@router.post('/login', response_model = schemas.Token)
def Login(request : OAuth2PasswordRequestForm = Depends(), db : Session = Depends(database.get_db)):
    user = db.query(models.User).filter(models.User.email == request.username).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid Credentials")
    if not hashing.Hash.verify(request.password, user.password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid Credentials")
    
    access_toke = jwt_token.create_access_token(data={'sub':user.email})
    return {'access_token':access_toke, 'token_type':'bearer'}


@router.post('/forgot-password')
def forgot_password(request: schemas.ForgotPassword, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.email == request.email).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    
    reset_token = jwt_token.create_access_token(
        data= {'sub':user.email}
    )

    reset_link = f"token={reset_token}"
    return {
        "message": "Password reset link generated",
        "reset_link": reset_link
    }

@router.post("/reset-password")
def reset_password(request: schemas.ResetPassword, db: Session = Depends(get_db)):
    payload = jwt_token.verify_token(request.token)
    if not payload:
        raise HTTPException(status_code=400, detail="Invalid or expired token")

    email = payload.get("sub")
    user = db.query(models.User).filter(models.User.email == email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.password = hashing.Hash.bcrypt(request.new_password)
    db.commit()

    return {"message": "Password has been reset successfully"}


@router.get('/all-user', response_model=List[schemas.ShowUser])
def all(db: Session = Depends(database.get_db),
        current_user: models.User = Depends(oauth2.get_current_user)):
    users = db.query(models.User).all()
    return users