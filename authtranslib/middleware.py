import jwt
from django.conf import settings
from django.utils.deprecation import MiddlewareMixin
from django.http import JsonResponse
from django.contrib.auth import get_user_model
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError
from django.core.exceptions import ObjectDoesNotExist
from datetime import datetime, timedelta

# Import your custom user model
User = get_user_model()

class GuestUser:
    """A simple class to represent a guest user."""
    def __init__(self):
        self.user_id = 0
        self.is_authenticated = False

    def __str__(self):
        return 'Guest User'

class JWTAuthenticationMiddleware(MiddlewareMixin):
    def process_request(self, request):
        auth_header = request.headers.get('Authorization')

        if not auth_header or not auth_header.startswith('Bearer '):
            # No token or incorrect Authorization header -> Treat as guest user
            request.user = self.create_guest_user()
            return
        
        token = auth_header.split('Bearer ')[1]

        try:
            decoded_data = jwt.decode(
                token,
                settings.SECRET_KEY,
                algorithms=["HS256"]
            )
            user = User.objects.get(pk=decoded_data['user_id'])
            request.user = user  # Assign the authenticated user to the request

        except (ExpiredSignatureError, InvalidTokenError, ObjectDoesNotExist):
            # Token is expired or invalid or user doesn't exist -> Treat as guest user
            request.user = self.create_guest_user()

    def process_response(self, request, response):
        """If the user is a guest, generate a JWT token for guest users."""
        if isinstance(request.user, GuestUser):
            guest_token = self.generate_guest_token()
            response['Authorization'] = f'Bearer {guest_token}'
            response.set_cookie('jwt_token', guest_token, httponly=True, secure=True, samesite='Lax')
        return response

    def create_guest_user(self):
        """Create a GuestUser instance with user_id = 0."""
        return GuestUser()

    def generate_guest_token(self):
        """Generate a JWT token for the guest user (user_id = 0)."""
        guest_payload = {
            'user_id': 0,
            'exp': datetime.utcnow() + timedelta(hours=24),  # Guest token expires in 24 hours
            'iat': datetime.utcnow(),
            'role': 'guest'
        }
        return jwt.encode(guest_payload, settings.SECRET_KEY, algorithm='HS256')


from functools import wraps
from django.http import JsonResponse


def login_required(view_func):
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        if not request.user:
            return JsonResponse({'error': 'Authentication credentials were not provided.'}, status=401)
        return view_func(request, *args, **kwargs)

    return _wrapped_view

def generate_jwt_token(user):
    """Generate a JWT token for a given user."""
    payload = {
        'user_id': user.id,
        'exp': datetime.utcnow() + timedelta(hours=24),  # Token expiration (24 hours)
        'iat': datetime.utcnow(),  # Issued at time
        'role': 'guest' if user.id == 0 else 'user'
    }
    token = jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256')
    return token