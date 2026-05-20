from jose import JWTError, jwt
from datetime import datetime, timedelta
from fastapi.security import OAuth2PasswordBearer
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


def refresh_token(data: dict):                                                   # dict is the type of data
    to_encode = data.copy()                                                      #copy data so original data remains safe
    expire = datetime.utcnow() + timedelta(days=REFRESH_SECRET_KEY_EXPIRY)  #expiry time=time now+ACCESS_TOKEN_EXPIRE_MINUTES(30)
    to_encode.update({"exp": expire})                                            #include calculated expiry time
    encoded_jwt = jwt.encode(to_encode, REFRESH_SECRET_KEY, algorithm=ALGORITHM)   #scrimbles the data into token
    return encoded_jwt

