import logging
import smtplib
import string
import uuid
from datetime import datetime, timedelta
import random
from email.mime.text import MIMEText
from typing import Optional

from dateutil.parser import parse
from fastapi import HTTPException
from passlib.context import CryptContext
from motor.motor_asyncio import AsyncIOMotorClient
import schemas
from dotenv import load_dotenv
import os

load_dotenv()

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Setup MongoDB client (consider using environment variables for sensitive information)
MONGO_URI = os.getenv("MONGO_URI")
client = AsyncIOMotorClient(MONGO_URI)
db = client["NNBBA"]
users_collection = db["users"]
otp_collection = db["otp_tokens"]

EMAIL_HOST = os.getenv("EMAIL_HOST")
EMAIL_PORT = os.getenv("EMAIL_PORT")
EMAIL_ADDRESS = os.getenv("EMAIL_ADDRESS")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")
# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

print("EMAIL_HOST:", EMAIL_HOST)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    print(f"plain {plain_password}")
    print(f"hash {hashed_password}")
    print(f"hello 1 {pwd_context.verify(plain_password, hashed_password)}")
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def safe_fromisoformat(date_str: Optional[str]) -> Optional[datetime]:
    if isinstance(date_str, str):
        try:
            return parse(date_str)
        except (ValueError, TypeError):
            return None
    return None


async def get_user(email: str) -> Optional[schemas.ResponseSignup]:
    user = await users_collection.find_one({"email_address": email})
    if user:
        logger.info(f"User found: {user['email_address']}")
        return schemas.ResponseSignup(
            uuid=user.get("uuid"),
            full_name=user.get("full_name"),
            email_address=user.get("email_address"),
            date_of_birth=safe_fromisoformat(user.get("date_of_birth")),
            address=user.get("address"),
            phone_number=user.get("phone_number"),
            gender=user.get("gender"),
            signup_date=safe_fromisoformat(user.get("signup_date")),
            is_banned=user.get("is_banned"),
            password=user.get("password"),
            subscription_status=user.get("subscription_status"),
            last_payment_date=safe_fromisoformat(user.get("last_payment_date")),
            payment_history=user.get("payment_history")
        )
    logger.warning("User not found")
    return None


async def authenticate_user(email: str, password: str) -> Optional[schemas.ResponseSignup]:
    user = await get_user(email)
    print(user)
    print(f"111{email}, ")
    print(f"111{password}, {user.password}")
    if user:
        print(f"{password}, {user.password}")
        if verify_password(password, user.password):
            logger.info("Password verified successfully")
            return user
        else:
            logger.warning("Password verification failed")
    return None


async def check_credentials(email: str) -> bool:
    user = await users_collection.find_one({"email_address": email})
    return user is None


async def create_user(user: schemas.Signup) -> schemas.ResponseSignup:
    try:
        user_uuid = str(uuid.uuid4())
        hashed_password = get_password_hash(user.password)

        if await check_credentials(user.email_address):
            user_data = {
                "uuid": user_uuid,
                "full_name": user.full_name,
                "email_address": user.email_address,
                "date_of_birth": user.date_of_birth.isoformat(),
                "address": user.address,
                "phone_number": user.phone_number,
                "gender": user.gender,
                "password": hashed_password,
                "signup_date": datetime.utcnow().isoformat(),
                "is_banned": False,
                "subscription_status": False,
                "last_payment_date": None,
                "payment_history": []
            }
            await users_collection.insert_one(user_data)
            logger.info(f"User created successfully: {user_uuid}")
            return schemas.ResponseSignup(**user_data)
        else:
            logger.warning(f"Email address already exists: {user.email_address}")
            raise HTTPException(status_code=400, detail="Email address already exists")
    except Exception as e:
        logger.error(f"Error in create_user: {e}")
        raise HTTPException(status_code=500, detail="An error occurred while creating the user")


def generate_otp(length=6):
    return ''.join(random.choices(string.digits, k=length))


def send_otp_email(email: str, otp: str):
    msg = MIMEText(f"Your OTP code is {otp}. It will expire in 5 minutes.")
    msg['Subject'] = "Your OTP Code"
    msg['From'] = EMAIL_ADDRESS
    msg['To'] = email

    try:
        with smtplib.SMTP_SSL(EMAIL_HOST, EMAIL_PORT) as server:
            server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            server.sendmail(EMAIL_ADDRESS, email, msg.as_string())
    except smtplib.SMTPException as e:
        raise HTTPException(status_code=500, detail=f"Failed to send email: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail="Internal server error")


def save_otp_to_db(email, otp):
    expiration_time = datetime.utcnow() + timedelta(minutes=5)
    otp_data = schemas.OTPModel(email=email, otp=otp, expiration_time=expiration_time)
    otp_collection.insert_one(otp_data.dict())


async def verify_otp(email: str, otp: str):
    # Fetch the OTP record from the database
    otp_record = await db["otp_collection"].find_one({"email": email})  # Ensure you await the async call

    # Now otp_record is a dictionary, so you can access its keys
    if otp_record and otp_record["otp"] == otp:
        # Verify if OTP is still valid
        expiration_time = otp_record["expires_at"]
        if datetime.utcnow() < expiration_time:
            return True
    return False
