from fastapi import FastAPI, HTTPException, status, Header
from fastapi.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, EmailStr
import bcrypt
from datetime import datetime
import secrets
import time
from typing import Optional
from fastapi.responses import HTMLResponse
import os
from dotenv import load_dotenv
import aiosmtplib

# 1. CONFIGURATION
load_dotenv()
resend.api_key = os.getenv("RESEND_API_KEY")
MONGODB_URL = os.getenv("MONGODB_URL")
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
    return {"message": "Football Challenges API is Live!"}

@app.post("/register")
async def register(user: newUser):
    if await users_collection.find_one({"username": user.username}):
        raise HTTPException(status_code=400, detail="Username already exists")
    if await users_collection.find_one({"email": user.email.lower()}):
        raise HTTPException(status_code=400, detail="Email already exists")
    
    new_user = {
        "username": user.username,
        "email": user.email.lower(),
        "password": get_password_hash(user.password),
        "goalsScore": 0,
        "assistsScore": 0,
        "trophiesScore": 0,
        "created_at": datetime.utcnow(),
    }
    await users_collection.insert_one(new_user)
    return {"message": "User registered successfully"}

@app.post("/login")
async def login(user: User):
    db_user = await users_collection.find_one({"username": user.username})
    if not db_user or not verify_password(user.password, db_user["password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    token = secrets.token_hex(32)
    await users_collection.update_one({"_id": db_user["_id"]}, {"$set": {"token": token}})
    return {"message": "Login successful", "token": token, "username": db_user["username"]}

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

        msg = MIMEMultipart("alternative")
        msg["Subject"] = "Password Reset - Football Challenges"
        msg["From"] = f"Football Challenges <{EMAIL_USER}>"
        msg["To"] = email

        html_content = f"""
        <html>
          <body style="text-align: center; font-family: Arial; padding: 20px;">
            <h2>Reset Password</h2>
            <p>Hello {user['username']}, click the button below to reset your password:</p>
            <a href="{redirect_link}" style="display:inline-block; padding:15px 25px; background-color:#007bff; color:white; text-decoration:none; border-radius:8px; font-weight:bold;">
                RESET PASSWORD
            </a>
          </body>
        </html>
        """
        msg.attach(MIMEText(html_content, "html"))

        # --- ENVOI VIA GMAIL PORT 465 (SSL) ---
        await aiosmtplib.send(
            msg,
            hostname="smtp.gmail.com",
            port=465,
            use_tls=True, # Utilise SSL directement
            username=EMAIL_USER,
            password=EMAIL_PASS,
        )

        print(f"✅ Email envoyé avec succès à {email}")
        return {"message": "Email sent"}

    except Exception as error:
        print(f"❌ Erreur Gmail SMTP: {str(error)}")
        raise HTTPException(status_code=500, detail="Le serveur de mail ne répond pas.")

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
    return {"message": "Password updated successfully"}

@app.put("/challenges/score")
async def update_score(scoreload: Scoreload, authorization: Optional[str] = Header(None)):
    if not authorization: raise HTTPException(status_code=401)
    token = authorization.split(" ")[1]
    user = await users_collection.find_one({"token": token})
    if not user: raise HTTPException(status_code=401)

    field = f"{scoreload.type}Score"
    thresholds = {"goals": 100000, "assists": 10000, "trophies": 1000}
    
    if scoreload.score >= thresholds.get(scoreload.type, 0) and scoreload.score > user.get(field, 0):
        await users_collection.update_one({"_id": user["_id"]}, {"$set": {field: scoreload.score}})
        return {"message": "Score updated"}
    return {"message": "Score too low or invalid"}

@app.get("/leaderboard/{challenge_type}")
async def get_leaderboard(challenge_type: str):
    field = f"{challenge_type}Score"
    top_users = await users_collection.find().sort(field, -1).to_list(3)
    return [{"username": u["username"], "score": u.get(field, 0)} for u in top_users]
