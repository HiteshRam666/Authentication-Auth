from datetime import datetime, timedelta, timezone 
import hashlib
import token
from typing import Annotated, Union
from uu import encode
from typing_extensions import deprecated 

from fastapi import FastAPI, Depends, HTTPException, status 
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel 
from passlib.context import CryptContext 

from jose import JWTError, jwt

# 1. Configuration & Constants 
# Security Configuration 
SECRET_KEY = "YOUR_SECRET_KEY_GOES_HERE"
ALGORITHM = "HS256" 
ACCESS_TOKEN_EXPIRE_MINUTES = 30 

# Password Hashing context (Using bcrypt) 
pwd_context = CryptContext(schemes=["bcrypt"], deprecated = 'auto')

# OAuth2 Scheme definition
# The tokenURL specifies the endpoint where the client can get a token (login) 
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# 2. Data Models (Pydantic) 

class Token(BaseModel):
    """
    The shape of the response when a token is successfully issued.
    """
    access_token: str 
    token_type: str = "bearer" 

class TokenData(BaseModel):
    """
    The data we expect to find inside the jwt payload.
    """
    username: Union[str, None] = None 

class User(BaseModel):
    """
    The public user profile model.
    """
    username: str 
    full_name: Union[str, None] = None 
    email: Union[str, None] = None 

class UserInDB(BaseModel):
    """
    The user model including the hashed password (never exposed).
    """
    username: str
    full_name: Union[str, None] = None
    email: Union[str, None] = None
    hashed_password: str

# 3. DB function & Utility functions
# Fake db for demo 

def hashed_password(password: str) -> str:
    # Step 1: Reduce to fixed 32 bytes
    sha = hashlib.sha256(password.encode("utf-8")).hexdigest()
    # Step 2: bcrypt hash
    return pwd_context.hash(sha)
 
# def get_password_hashed(password):
#     return pwd_context.hash(password)

FAKE_HASHED_PASSWORD = hashed_password("admin123")

fake_user_db = {
    "testuser": {
        "username": "testuser", 
        "full_name": "Test User", 
        "email": "test@example.com", 
        "hashed_password": FAKE_HASHED_PASSWORD
    }
}

def verify_password(plain_password, hashed_passowrd):
    """
    Verifies the plain-text password against stored hash.
    """
    sha = hashlib.sha256(plain_password.encode("utf-8")).hexdigest()
    return pwd_context.verify(sha, hashed_passowrd) 

def get_user(db: dict, username: str) -> Union[UserInDB, None]:
    """
    Retrieves a user from the fake database.
    """
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)

def authenticate_user(db: dict, username: str, password: str) -> Union[UserInDB, bool]:
    """
    Authenticates a user by checking username and password 
    """
    user = get_user(db, username) 
    if not user:
        return False 
    if not verify_password(password, user.hashed_password):
        return False 
    return user 

# 4. JWT Token Generation and decoding 
def create_access_token(data: dict, expires_delta: Union[timedelta, None] = None):
    """
    Creates an encoded jwt token
    """ 
    to_encode = data.copy() 
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    # Add the experiation time to payload 
    to_encode.update({"exp": expire})

    # Encode the Jwt 
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt 

async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]) -> User:
    """
    Dependency to decode and validate the JWT from the authorization header. 
    This function is run on every protected route. 
    """
    credentials_expection = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED, 
        detail = "Could not validate credentials", 
        headers = {"WWW-Authenticate", "Bearer"}, 
    )

    try:
        # Decode the token 
        payload = jwt.decode(token, SECRET_KEY, algorithms=ALGORITHM) 

        # Extract the subject (Username) 
        username: str = payload.get("sub")

        if username is None:
            raise credentials_expection
        
        token_data = TokenData(username = username) 
    except JWTError:
        raise credentials_expection

    # Look up the user in db (Optional, but recommend for authorization checks) 
    user = get_user(fake_user_db, username=token_data.username) 
    if user is None:
        raise credentials_expection 

    # Return the user object (Excluding password hash) 
    return User(username = user.username, full_name=user.full_name, email = user.email) 

def get_current_active_user(
    current_user: Annotated[User, Depends(get_current_user)]
):
    return current_user 

# 5. FastAPI application and endpoints

app = FastAPI(
    title = "FastAPI JWT Auth Demo", 
    description="Demonstrates OAuth2 Password flow with JWTs for secure access"
) 

@app.post("/token", response_model=Token, tags = ["Authentication"])
async def login_for_access_token(
    # This dependency parses the username and password from form data
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()] 
):
    """
    Endpoint for user login
    It checks credentials and returns JWT access token 
    """
    user = authenticate_user(fake_user_db, form_data.username, form_data.password) 

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail = "Incorrect username and password", 
            headers = {"WWW-Authenticate": "Bearer"}, 
        )

    # Define the token expiration time 
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES) 

    # Create the token, using the username as the JWT subject ("sub")
    access_token = create_access_token(
        data = {"sub": user.username}, 
        expires_delta=access_token_expires 
    )

    return {"access_token": access_token, "token_type": "bearer"} 

@app.get("/", tags=["Public"])
async def read_root():
    """
    A public, unprotected endpoint
    """
    return {"message": "Welcome! Access / docs to try the authentication flow"} 

@app.get("/users/me", response_model=User, tags = ["User"])
async def read_users_me(
    # By using dependency, this route is protected 
    current_user: Annotated[User, Depends(get_current_active_user)]
):
    """
    A protected endpoint that returns the current authenticated user's details.
    """
    return current_user 

@app.get("/protected-data/", tags = ["Data"])
async def read_protected_data(
    current_user: Annotated[User, Depends(get_current_active_user)]
):
    """
    A protected endpoint demonstrating access to sensitive information.
    """
    return {
        "data": f"Hello, {current_user.full_name}! You successfully accessed protected data.", 
        "user_id": current_user.username 
    }