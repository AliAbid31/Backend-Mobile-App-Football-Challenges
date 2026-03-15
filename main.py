from fastapi import FastAPI, HTTPException, status, Header
from fastapi.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, EmailStr
import bcrypt
from datetime import datetime
import secrets
import time
import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Optional
from fastapi.responses import HTMLResponse
import os
from dotenv import load_dotenv

load_dotenv()

# --- CONFIGURATION (Vérifie bien ces noms sur Vercel !) ---
MONGODB_URI = os.getenv("MONGODB_URI") 
EMAIL_USER = os.getenv("EMAIL_USER")
EMAIL_PASS = os.getenv("EMAIL_PASS")
BACKEND_URL = os.getenv("BACKEND_URL") 

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Base de données
client = AsyncIOMotorClient(MONGODB_URI)
db = client.ali
users_collection = db.footballchallenges
password_reset_collection = db.passwordresets

# Models
class newUser(BaseModel):
    username: str
    email: EmailStr
    password: str

class User(BaseModel):
    username: str
    password: str

class ForgotPasswordRequest(BaseModel):
    email: EmailStr

class ResetPassword(BaseModel):
    new_password: str

class Scoreload(BaseModel):
    score: int
    type: str

def get_password_hash(password: str):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(10)).decode('utf-8')

def verify_password(plain_password: str, hashed_password: str):
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))

@app.get("/")
async def root():
    return {"message": "API is Live"}

@app.post("/register")
async def register(user: newUser):
    if await users_collection.find_one({"username": user.username}):
        raise HTTPException(status_code=400, detail="Username exists")
    new_user = {
        "username": user.username, "email": user.email.lower(),
        "password": get_password_hash(user.password),
        "goalsScore": 0, "assistsScore": 0, "trophiesScore": 0,
        "created_at": datetime.utcnow()
    }
    await users_collection.insert_one(new_user)
    return {"message": "Registered"}

@app.post("/login")
async def login(user: User):
    db_user = await users_collection.find_one({"username": user.username})
    if not db_user or not verify_password(user.password, db_user["password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = secrets.token_hex(32)
    await users_collection.update_one({"_id": db_user["_id"]}, {"$set": {"token": token}})
    return {"token": token, "username": db_user["username"]}

@app.get("/open-app/{token}", response_class=HTMLResponse)
async def open_app_redirect(token: str):
    app_link = f"footballchallenges://reset-password/{token}"
    return f"<html><body style='text-align:center;padding-top:50px;'><h2>Redirecting...</h2><script>window.location.href = '{app_link}';</script></body></html>"

@app.post("/forgot-password")
async def forgot_password(request: ForgotPasswordRequest):
    try:
        email = request.email.lower().strip()
        user = await users_collection.find_one({"email": email})
        
        if not user:
            return {"message": "Email sent if account exists"}

        token = secrets.token_hex(20)
        expires = int(time.time() * 1000) + 3600000 
        await password_reset_collection.insert_one({"email": email, "token": token, "expires": expires})

        # Sécurité : Si BACKEND_URL est vide, on évite le crash
        base_url = BACKEND_URL if BACKEND_URL else "https://votre-app.vercel.app"
        redirect_link = f"{base_url}/open-app/{token}"

        msg = MIMEMultipart("alternative")
        msg["Subject"] = "Reset Password - Football Challenges"
        msg["From"] = f"Football Challenges <{EMAIL_USER}>"
        msg["To"] = email
        
        html = f"<html><body style='text-align:center;'><h2>Password Reset</h2><p>Click below:</p><a href='{redirect_link}' style='background:#007bff;color:white;padding:12px;text-decoration:none;border-radius:5px;'>RESET PASSWORD</a></body></html>"
        msg.attach(MIMEText(html, "html"))

        # ENVOI DIRECT (Plus fiable sur Vercel)
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as server:
            server.login(EMAIL_USER, EMAIL_PASS)
            server.sendmail(EMAIL_USER, email, msg.as_string())

        return {"message": "Email sent"}

    except Exception as error:
        # On renvoie l'erreur réelle dans le log Vercel pour pouvoir la lire
        print(f"CRASH LOG: {str(error)}")
        raise HTTPException(status_code=500, detail=str(error))

@app.post("/reset-password/{token}")
async def reset_password(token: str, request: ResetPassword):
    current_time = int(time.time() * 1000)
    reset_request = await password_reset_collection.find_one({"token": token, "expires": {"$gt": current_time}})
    if not reset_request:
        raise HTTPException(status_code=400, detail="Invalid token")
    
    await users_collection.update_one(
        {"email": reset_request["email"]},
        {"$set": {"password": get_password_hash(request.new_password)}}
    )
    await password_reset_collection.delete_one({"token": token})
    return {"message": "Success"}

@app.put("/challenges/score")
async def update_score(scoreload: Scoreload, authorization: Optional[str] = Header(None)):
    if not authorization: raise HTTPException(status_code=401)
    token = authorization.split(" ")[1]
    user = await users_collection.find_one({"token": token})
    if not user: raise HTTPException(status_code=401)

    field = f"{scoreload.type}Score"
    await users_collection.update_one({"_id": user["_id"]}, {"$set": {field: scoreload.score}})
    return {"message": "Updated"}

@app.get("/leaderboard/{challenge_type}")
async def get_leaderboard(challenge_type: str):
    field = f"{challenge_type}Score"
    top_users = await users_collection.find().sort(field, -1).to_list(3)
    return [{"username": u["username"], "score": u.get(field, 0)} for u in top_users]