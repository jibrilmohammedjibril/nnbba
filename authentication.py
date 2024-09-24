from datetime import datetime, timedelta
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
import schemas
from schemas import TokenData, User
from crud import get_user

SECRET_KEY = "f67t8ygh87t85tyigv76fg76rty778hg679oip9p8"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 3

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


async def get_current_user(token: str = Depends(oauth2_scheme)) -> schemas.ResponseSignup:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        # Decode the JWT token
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception

    # Fetch user from the database
    user = await get_user(email=token_data.username)  # Ensure get_user is an async function
    if user is None:
        raise credentials_exception
    return user


async def get_current_active_user(
        current_user: schemas.ResponseSignup = Depends(get_current_user)) -> schemas.ResponseSignup:
    if current_user.is_banned:
        raise HTTPException(status_code=400, detail="Banned user")
    if not current_user.subscription_status:
        raise HTTPException(status_code=400, detail="Subscription inactive")
    return current_user
