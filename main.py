from fastapi import FastAPI, HTTPException, status, Header
from fastapi.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, EmailStr
import bcrypt
from datetime import datetime
import secrets
import time
import asyncio  # <--- CRUCIAL : Importé ici
import smtplib  # <--- CRUCIAL : Importé ici
import ssl      # <--- CRUCIAL : Importé ici
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Optional
from fastapi.responses import HTMLResponse
import os
from dotenv import load_dotenv

# 1. CONFIGURATION
load_dotenv()
MONGODB_URL = os.getenv("MONGODB_URL")
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

# 2. MODELS
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

# 3. BASE DE DONNÉES
client = AsyncIOMotorClient(MONGODB_URL)
db = client.ali
users_collection = db.footballchallenges
password_reset_collection = db.passwordresets

# 4. UTILS
def get_password_hash(password: str):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(10)).decode('utf-8')

def verify_password(plain_password: str, hashed_password: str):
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))

# 5. ROUTES
@app.get("/")
async def root():
    return {"message": "API is Live"}

@app.post("/register")
async def register(user: newUser):
    if await users_collection.find_one({"username": user.username}):
        raise HTTPException(status_code=400, detail="Username already exists")
    new_user = {
        "username": user.username,
        "email": user.email.lower(),
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
    return f"""
    <html>
        <body style="text-align:center;padding-top:50px;font-family:sans-serif;">
            <h2>Redirecting to Football Challenges...</h2>
            <p>If the app doesn't open, <a href="{app_link}">click here</a>.</p>
            <script>window.location.href = "{app_link}";</script>
        </body>
    </html>
    """

# --- FONCTION D'ENVOI SYNCHRONE (DANS UN THREAD) ---
def send_gmail_sync(to_email, username, redirect_link):
    msg = MIMEMultipart("alternative")
    msg["Subject"] = "Password Reset - Football Challenges"
    msg["From"] = f"Football Challenges <{EMAIL_USER}>"
    msg["To"] = to_email

    html_content = f"""
    <html>
      <body style="text-align: center; font-family: Arial; padding: 20px;">
        <h2>Reset Password</h2>
        <p>Hello {username}, click the button below to reset your password:</p>
        <a href="{redirect_link}" style="display:inline-block; padding:15px 25px; background-color:#007bff; color:white; text-decoration:none; border-radius:8px; font-weight:bold;">
            RESET PASSWORD
        </a>
      </body>
    </html>
    """
    msg.attach(MIMEText(html_content, "html"))

    # Config SSL identique à ton code Node.js (rejectUnauthorized: false)
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context, timeout=15) as server:
        server.login(EMAIL_USER, EMAIL_PASS)
        server.sendmail(EMAIL_USER, to_email, msg.as_string())

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

        redirect_link = f"{BACKEND_URL}/open-app/{token}"

        # On lance l'envoi dans un thread asyncio pour ne pas bloquer le serveur
        await asyncio.to_thread(send_gmail_sync, email, user['username'], redirect_link)
        
        return {"message": "Email sent"}

    except Exception as error:
        print(f"❌ Gmail Error: {error}")
        raise HTTPException(status_code=500, detail="Mail server error")

@app.post("/reset-password/{token}")
async def reset_password(token: str, request: ResetPassword):
    current_time = int(time.time() * 1000)
    reset_request = await password_reset_collection.find_one({"token": token, "expires": {"$gt": current_time}})
    if not reset_request:
        raise HTTPException(status_code=400, detail="Invalid or expired token")
    
    await users_collection.update_one(
        {"email": reset_request["email"]},
        {"$set": {"password": get_password_hash(request.new_password)}}
    )
    await password_reset_collection.delete_one({"token": token})
    return {"message": "Success"}