from fastapi import FastAPI, Depends, HTTPException, status, Form, UploadFile, File
from fastapi.security import OAuth2PasswordRequestForm
from datetime import timedelta
from pydantic import ValidationError
import crud
import schemas
from schemas import Token, User
from crud import authenticate_user
from authentication import create_access_token, get_current_active_user, ACCESS_TOKEN_EXPIRE_MINUTES, get_current_user

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = await authenticate_user(form_data.username, form_data.password)
    print(user)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email_address}, expires_delta=access_token_expires)
    return {"access_token": access_token, "token_type": "bearer"}


@app.post("/signup/", response_model=schemas.ResponseSignup)
async def signup(user: schemas.Signup):
    try:
        db_user = await crud.create_user(user=user)
        if db_user:
            return db_user
        else:
            raise HTTPException(status_code=400, detail="Email address already exists")
    except ValidationError as ve:
        raise HTTPException(status_code=422, detail=f"Validation error: {ve}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"An error occurred: {str(e)}")


@app.get("/active_users/", response_model=User)
async def active_user(current_user: User = Depends(get_current_user)):
    return current_user


@app.post("/forgot-password/")
async def forgot_password(request: schemas.ForgotPasswordRequest):
    # Check if user exists
    user = crud.db["users"].find_one({"email": request.email})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Generate and send OTP
    otp = crud.generate_otp()
    crud.send_otp_email(request.email, otp)
    crud.save_otp_to_db(request.email, otp)

    return {"msg": "OTP has been sent to your email"}


@app.post("/reset-password/")
async def reset_password(request: schemas.ResetPasswordRequest):
    # Verify OTP
    if not crud.verify_otp(request.email, request.otp):
        raise HTTPException(status_code=400, detail="Invalid or expired OTP")

    # Hash the new password
    hashed_password = crud.pwd_context.hash(request.new_password)

    # Update the password in the database
    crud.db["users"].update_one({"email": request.email}, {"$set": {"password": hashed_password}})

    # Optionally, delete the OTP from the database after successful password reset
    crud.otp_collection.delete_one({"email": request.email})

    return {"msg": "Password has been successfully reset"}
