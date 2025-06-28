from fastapi import Depends, HTTPException, status
import jwt_token 
from fastapi.security import OAuth2PasswordBearer



oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

def get_current_user(token_str:str =Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    return jwt_token.verify_token(token_str)