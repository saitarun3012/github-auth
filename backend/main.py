from fastapi import FastAPI, Depends, Response
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from database import AsyncSessionLocal, engine, Base
from models import UserModel
from user import User
from auth import create_token, refresh_token
import bcrypt

app=FastAPI()

async def get_db():                                     #this method is used to connect to database
    async with AsyncSessionLocal() as session:          #AsyncSessionLocal() connects to database as fresh session
        yield session                                    #yeild hands session to route so route can use whenever its necessary

@app.on_event("startup")
async def startup():
    async with engine.begin() as connection:                    #connects to PostgreSQL using engine from database.py and reads UserModel from models.py and creates user table if only it dosen't exist
        await connection.run_sync(Base.metadata.create_all)

@app.post("/register")
async def register(
    name: str,
    email: str,
    password: str,                           #checks name, email, password is string, if not returns error
    db: AsyncSession = Depends(get_db)       #here we call a fresh session
):
    result = await db.execute(
        select(UserModel).where(UserModel.email == email) #(sql)# SELECT * FROM users WHERE email = email
    )
    existing_user = result.scalar_one_or_none()    #result.scalar_one_or_none()  handles the type of result we want, in this case we want a single email if exist or return none if not found

    if existing_user:
        return {"error": "Email already exists"}  #user exist so can't allow user to register once again

    user_obj = User(name, email, password)    #stores the new users name, email, password with the help of user class in user.py

    new_user = UserModel(
        name=name,
        email=email,
        hashed_password=user_obj.password.decode("utf-8")  #PostgreSQL doesnot understand bytes so decode it(not bringing back the original password just converting bytes format to string so no one knows the password except the user)
    )

    db.add(new_user)    #add new user to database
    await db.commit()

    return {"message": f"Welcome {user_obj.get_user()}"}

@app.post("/login")                             #same process as register just allow only registered user or return user not found
async def login(
    response: Response,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: AsyncSession = Depends(get_db)      
):
    result = await db.execute(
        select(UserModel).where(UserModel.email == form_data.username) 
    )
    existing_user = result.scalar_one_or_none()  
    
     
    
    if not existing_user:
        return {"error": "User not found"}

    is_valid=bcrypt.checkpw(
        form_data.password.encode("utf-8"),                  #here checking if the entered password matches the actual password
        existing_user.hashed_password.encode("utf-8")     
    )

    if not is_valid:
        return {"error": "Wrong password"}
    
    access_token = create_token(data={"sub": existing_user.email})
    refresh_access = refresh_token(data={"sub": existing_user.email})

    response.set_cookie(
        key="refresh_token",
        value=refresh_access,
        httponly=True,
        max_age=7 * 24 * 60 * 60,
        samesite="lax"
    )
    return {"access_token": access_token, "token_type": "bearer"}
                       

