# github-auth

A full stack authentication system built with FastAPI, React, and PostgreSQL, featuring JWT-based auth, refresh tokens, and GitHub OAuth2 login.

## Why I Built This
I wanted to understand how authentication actually works under the hood — not just use a library, but build the entire flow from scratch. This project covers password hashing, JWT token creation, refresh token rotation, and OAuth2 with GitHub.

## Tech Stack
**Backend:** FastAPI, PostgreSQL, SQLAlchemy, bcrypt, python-jose  
**Frontend:** React, Vite  
**DevOps:** Docker, Docker Compose

## Features
- Email/password registration and login
- JWT access tokens (30 min) + refresh tokens (7 days via httponly cookie)
- GitHub OAuth2 login
- Protected routes (/me, /me/update, /me/delete)
- Automated API tests with Pytest and HTTPX
- Fully containerized with Docker

## Run with Docker
```bash
docker compose up
```
Frontend → http://localhost:80  
Backend docs → http://localhost:8000/docs

## Run Locally
```bash
# Backend
cd backend
pip install -r requirements.txt
uvicorn main:app --reload

# Frontend
cd frontend
npm install
npm run dev
```

## API Endpoints

- `POST /register` — create a new account
- `POST /login` — login with email and password, returns access token
- `GET /me` — get current logged in user (protected)
- `PUT /me/update` — update your name (protected)
- `DELETE /me/delete` — delete your account (protected)
- `POST /refresh` — get a new access token using refresh cookie
- `POST /logout` — clears the refresh token cookie
- `GET /auth/github` — start GitHub OAuth login flow

## What I Learned
Building this taught me why two tokens are better than one — a short-lived access token means a stolen token expires in 30 minutes. Storing the refresh token in an httponly cookie instead of localStorage was a deliberate security choice to prevent XSS attacks. Docker made me understand how services communicate in isolated containers.
