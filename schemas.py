from pydantic import BaseModel, EmailStr, Field
from typing import List

class CreateUser(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=128)

class ResponseUser(BaseModel):
    id: int
    username: str
    email: EmailStr

    class Config:
        orm_mode = True


class Login(BaseModel):
    email : EmailStr
    password :str

class Token(BaseModel):
    access_token: str
    token_type : str  ='bearer'


class ForgotPassword(BaseModel):
    email : str


class ResetPassword(BaseModel):
    token :str
    new_password:str = Field(..., min_length=8)

class ShowUser(BaseModel):
    id: int
    username: str
    email: EmailStr
    class Config():
        orm_mode = True