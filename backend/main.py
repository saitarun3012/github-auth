from fastapi import FastAPI, Depends, Response
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from database import AsyncSessionLocal, engine, Base
from models import UserModel
from user import User
from auth import create_token, refresh_token, gets_current_user, current_user_from_refresh, GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET
import bcrypt
from fastapi.responses import RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
import httpx
import os
from pydantic import BaseModel

class RegisterRequest(BaseModel):
    name: str
    email: str
    password: str

app=FastAPI()


app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],  #React frontend
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

async def get_db():                                     #this method is used to connect to database
    async with AsyncSessionLocal() as session:          #AsyncSessionLocal() connects to database as fresh session
        yield session                                    #yeild hands session to route so route can use whenever its necessary

@app.on_event("startup")
async def startup():
    async with engine.begin() as connection:                    #connects to PostgreSQL using engine from database.py and reads UserModel from models.py and creates user table if only it dosen't exist
        await connection.run_sync(Base.metadata.create_all)

@app.post("/register")
async def register(
    data: RegisterRequest,
    db: AsyncSession = Depends(get_db)
):
    result = await db.execute(
        select(UserModel).where(UserModel.email == data.email) #(sql)# SELECT * FROM users WHERE email = email
    )
    existing_user = result.scalar_one_or_none()    #result.scalar_one_or_none()  handles the type of result we want, in this case we want a single email if exist or return none if not found

    if existing_user:
        return {"error": "Email already exists"}  #user exist so can't allow user to register once again

    user_obj = User(data.name, data.email, data.password)    #stores the new users name, email, password with the help of user class in user.py

    new_user = UserModel(
        name=data.name,
        email=data.email,
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
    result=await db.execute(
        select(UserModel).where(UserModel.email == form_data.username)
    )
    db_user=result.scalar_one_or_none()

    if not db_user:
        return {"error": "User not found"}

    is_valid=bcrypt.checkpw(
        form_data.password.encode("utf-8"),                  #here checking if the entered password matches the actual password
        db_user.hashed_password.encode("utf-8")     
    )

    if not is_valid:
        return {"error": "Wrong password"}

    access_token=create_token(data={"sub":db_user.email})
    refresh_access=refresh_token(data={"sub":db_user.email})

    response.set_cookie(
        key="refresh_token",
        value=refresh_access,
        httponly=True,          
        max_age=7 * 24 * 60 * 60, 
        samesite="lax" 
    )                       
    return {"access_token":access_token, "token_type": "bearer"}

@app.get("/me")
async def get_me(current_user: UserModel=Depends(gets_current_user)):
    return {
        "name":current_user.name,
        "email":current_user.email
    }

@app.put("/me/update")
async def update_me(
    new_name: str,
    current_user: UserModel = Depends(gets_current_user),
    db: AsyncSession = Depends(get_db)
):
    current_user.name = new_name
    db.add(current_user)
    await db.commit()
    return {"message": f"Name updated to {new_name}"}

@app.delete("/me/delete")
async def delete_me(
    current_user: UserModel = Depends(gets_current_user),
    db: AsyncSession = Depends(get_db)
):
    await db.delete(current_user)
    await db.commit()
    return {"message": "Account deleted"}

@app.post("/refresh")
async def refresh(response: Response, user: UserModel = Depends(current_user_from_refresh)):
    new_access_token = create_token(data={"sub": user.email})
    return {"access_token": new_access_token, "token_type": "bearer"}

@app.post("/logout")
async def logout(response: Response):
    response.delete_cookie("refresh_token")
    return {"message": "Logged out"}


@app.get("/auth/github")
async def github_login():
    return RedirectResponse(
        f"https://github.com/login/oauth/authorize?client_id={GITHUB_CLIENT_ID}&scope=user:email"
    )

@app.get("/auth/github/callback")
async def github_callback(code: str, response: Response, db: AsyncSession = Depends(get_db)):
    
    async with httpx.AsyncClient() as client:
        token_response = await client.post(
            "https://github.com/login/oauth/access_token",
            data={
                "client_id": GITHUB_CLIENT_ID,
                "client_secret": GITHUB_CLIENT_SECRET,
                "code": code
            },
            headers={"Accept": "application/json"}
        )
    
    github_token = token_response.json().get("access_token")

    async with httpx.AsyncClient() as client:
        user_response = await client.get(
            "https://api.github.com/user/emails",
            headers={"Authorization": f"Bearer {github_token}"}
        )
    
    emails = user_response.json()
    email = next(e["email"] for e in emails if e["primary"])

    result = await db.execute(select(UserModel).where(UserModel.email == email))
    user = result.scalar_one_or_none()

    if not user:
        user = UserModel(name=email.split("@")[0], email=email, hashed_password="github_oauth")
        db.add(user)
        await db.commit()

    access_token = create_token(data={"sub": user.email})
    refresh_access = refresh_token(data={"sub": user.email})

    response.set_cookie(
        key="refresh_token",
        value=refresh_access,
        httponly=True,
        max_age=7 * 24 * 60 * 60,
        samesite="lax"
    )
    return RedirectResponse(
    f"http://localhost:5173?token={access_token}"
)