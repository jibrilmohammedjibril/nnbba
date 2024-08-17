from datetime import date, datetime
from pydantic import BaseModel, EmailStr
from typing import Optional, List
from enum import Enum


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: Optional[str] = None


class User(BaseModel):
    uuid: Optional[str]
    full_name: str
    email_address: str
    date_of_birth: Optional[date]
    address: Optional[str]
    phone_number: Optional[str]
    gender: Optional[str]
    signup_date: Optional[datetime]
    is_banned: bool
    subscription_status: bool
    last_payment_date: Optional[datetime]
    payment_history: Optional[List['PaymentHistory']]  # Forward reference


class UserInDB(User):
    hashed_password: str


class PaymentStatus(str, Enum):
    successful = "successful"
    failed = "failed"
    pending = "pending"


class PaymentHistory(BaseModel):
    payment_date: datetime
    amount: float
    status: PaymentStatus


class Signup(BaseModel):
    uuid: Optional[str] = None
    full_name: str
    email_address: EmailStr
    date_of_birth: date
    address: str
    phone_number: str
    gender: str
    password: str
    signup_date: Optional[datetime] = None
    is_banned: bool = False
    subscription_status: bool = False
    last_payment_date: Optional[datetime] = None
    payment_history: Optional[List[PaymentHistory]] = []


class ResponseSignup(BaseModel):
    uuid: Optional[str] = None
    full_name: Optional[str] = None
    email_address: Optional[str] = None
    date_of_birth: Optional[date] = None
    address: Optional[str] = None
    phone_number: Optional[str] = None
    gender: Optional[str] = None
    password: Optional[str] = None
    signup_date: Optional[datetime] = None
    is_banned: Optional[bool] = None
    subscription_status: Optional[bool] = None
    last_payment_date: Optional[datetime] = None
    payment_history: Optional[List[PaymentHistory]] = []


class OTPModel(BaseModel):
    email: EmailStr
    otp: str
    expiration_time: datetime


class ForgotPasswordRequest(BaseModel):
    email: EmailStr

class ResetPasswordRequest(BaseModel):
    email: EmailStr
    otp: str
    new_password: str
