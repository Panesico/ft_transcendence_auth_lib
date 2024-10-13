import jwt
import datetime
from django.conf import settings

def create_jwt_token(user):
    """Generates a JWT token containing user information."""
    payload = {
        'user_id': user.id,            # Store the user ID
        'username': user.username,     # Store the username if needed
        'exp': datetime.datetime.now(datetime.UTC) + settings.JWT_EXPIRATION_DELTA,
        'iat': datetime.datetime.now(datetime.UTC),
    }
    token = jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
    return token

def decode_jwt_token(token):
    """Decodes a JWT token and returns the payload if valid, otherwise returns None."""
    try:
        payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        return None  # Token has expired
    except jwt.InvalidTokenError:
        return None  # Invalid token
1