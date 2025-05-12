# /home/ubuntu/flowvault_backend_fastapi/auth.py

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import jwt
from jwt.exceptions import PyJWTError
import os
from sqlalchemy.orm import Session
from models import User, SessionLocal # Assuming User model might still be used for structure
import logging

# Configure logging
logger = logging.getLogger(__name__)

# Clerk authentication configuration
CLERK_PEM_PUBLIC_KEY = os.environ.get("CLERK_PEM_PUBLIC_KEY", """
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxcIKMFLcJpgKFD9vFXeX
eXULQXwGgxPGgpzRHqHORlMUhcmkfYDFQ9JhXZYxXHisJUUPGUmUGIjY2JYyd6KR
yCgNNKQzMnis/G7jD+y9iJm1FjfNSBjLG9Pf/KbmyZ9+1ReDyQmgVWmRdOBvNrwc
JyBUoGPBlJbgwRD0+A5EM4PiyFxGMI6wJhONdL8ySIZ0YiVJjYHFYQqQVgDd8fNB
EXAMPLE_KEY_REPLACE_WITH_REAL_ONE_IN_PRODUCTION
-----END PUBLIC KEY-----
""")

# Security scheme for Swagger UI
security = HTTPBearer()

def get_db():
    """Get database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
) -> User:
    """
    Validate JWT token from Clerk and return the corresponding user.
    Creates user in database if they don't exist yet.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        # Extract token
        token = credentials.credentials
        
        # Verify and decode JWT
        # In production, use the actual Clerk public key
        # You would also set your correct audience and ensure verify_signature is True
        payload = jwt.decode(
            token, 
            CLERK_PEM_PUBLIC_KEY, 
            algorithms=["RS256"],
            # audience="your-clerk-instance-id.clerk.accounts.dev", # Replace with your actual Clerk Instance ID or frontend API URL
            options={"verify_signature": False}  # IMPORTANT: Set to True in production after configuring audience and key correctly
        )
        
        # Extract user info from token
        user_id = payload.get("sub") # Clerk uses 'sub' for user ID
        if user_id is None:
            logger.error("User ID (sub) not found in token payload.")
            raise credentials_exception
        
        # Get user from database or create if not exists
        user = db.query(User).filter(User.id == user_id).first()
        
        if not user:
            # Create new user from JWT claims
            # Ensure these claim names match what Clerk provides in your token
            email = payload.get("email", "") 
            name = payload.get("name", payload.get("firstName", "") + " " + payload.get("lastName", "")).strip()
            if not name: # if name, firstName, lastName are all empty
                name = "User " + user_id[:8] # Fallback name
            
            user = User(
                id=user_id,
                email=email,
                name=name
            )
            db.add(user)
            db.commit()
            db.refresh(user)
            logger.info(f"Created new user: {user_id}")
        
        return user
        
    except PyJWTError as e:
        logger.error(f"JWT validation error: {e}")
        raise credentials_exception
    except Exception as e:
        logger.error(f"An unexpected error occurred during user authentication: {e}")
        raise credentials_exception

async def get_admin_user(
    current_user: User = Depends(get_current_user)
) -> User:
    """Check if user is an admin."""
    # This is a placeholder. Implement your actual admin check logic.
    # For example, check a 'role' attribute in the User model or a claim in the JWT.
    # For FlowVault, we might check if the user's email is in a list of admin emails
    # or if they have an 'admin' role set in Clerk custom claims.
    # For now, let's assume an admin email for demo purposes.
    # IMPORTANT: Replace this with actual admin role checking in production.
    if not current_user.email or not current_user.email.endswith("@flowvaultadmin.com"): # Example admin email domain
        logger.warning(f"Admin access denied for user: {current_user.email}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions. Admin access required."
        )
    logger.info(f"Admin access granted for user: {current_user.email}")
    return current_user

# Example usage in routers:
# from auth import get_current_user, get_admin_user
#
# @router.get("/protected")
# async def protected_route(current_user: User = Depends(get_current_user)):
#     return {"message": f"Hello, {current_user.name}!"}
#
# @router.get("/admin-only")
# async def admin_route(admin_user: User = Depends(get_admin_user)):
#     return {"message": "Admin access granted"}

