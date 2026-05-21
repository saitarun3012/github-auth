from jose import JWTError, jwt
from datetime import datetime, timedelta
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from database import AsyncSessionLocal
from fastapi import Depends, HTTPException, status, Request
from models import UserModel
import os
from dotenv import load_dotenv

load_dotenv()

SECRET_KEY = "secret key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_SECRET_KEY = "ref"
REFRESH_SECRET_KEY_EXPIRY = 7
token_extractor = OAuth2PasswordBearer(tokenUrl="/login")    #OAuth2PasswordBearer is a class from FastAPIs security library which extreacts token and tokenUrl="/login" tells the location , where the token is created
def create_token(data: dict):                                                   # dict is the type of data
    to_encode = data.copy()                                                      #copy data so original data remains safe
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)  #expiry time=time now+ACCESS_TOKEN_EXPIRE_MINUTES(30)
    to_encode.update({"exp": expire})                                            #include calculated expiry time
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)   #scrimbles the data into token
    return encoded_jwt

async def gets_current_user(
    token:str=Depends(token_extractor),
):
    credentials_error=HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,    #lets create error block related to invalid tokens so i can use this block whereever i need to display the error
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try: 
        payload=jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email:str=payload.get("sub")
    
        if email is None:
            raise credentials_error    #display error message if email not found
            

    except JWTError:
        raise credentials_error         #display error message if token expired or invalid or tampered token

    async with AsyncSessionLocal() as db:
        result=await db.execute(
            select(UserModel).where(UserModel.email == email) #sql
        )
        user=result.scalar_one_or_none()


    if user is None:                      #display error message if email not found in database
        raise credentials_error
    return user


def refresh_token(data: dict):                                                   # dict is the type of data
    to_encode = data.copy()                                                      #copy data so original data remains safe
    expire = datetime.utcnow() + timedelta(days=REFRESH_SECRET_KEY_EXPIRY)  #expiry time=time now+ACCESS_TOKEN_EXPIRE_MINUTES(30)
    to_encode.update({"exp": expire})                                            #include calculated expiry time
    encoded_jwt = jwt.encode(to_encode, REFRESH_SECRET_KEY, algorithm=ALGORITHM)   #scrimbles the data into token
    return encoded_jwt

