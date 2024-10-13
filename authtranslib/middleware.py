import jwt
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError
from django.conf import settings
from django.contrib.auth import get_user_model
from django.utils.deprecation import MiddlewareMixin
from datetime import datetime, timedelta
from django.core.exceptions import ObjectDoesNotExist
from django.http import JsonResponse
import logging

logger = logging.getLogger(__name__)


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
        logger.debug('------------------------------- KILLOOO SI QUIERA ENTRAS AQUI???? -------------------------------------------------------------------')
        """Process every request and ensure that a valid JWT token is available."""
        auth_header = request.headers.get('Authorization')

        if not auth_header or not auth_header.startswith('Bearer '):
            # No token provided, treat the user as a guest and generate a guest token
            request.user = self.create_guest_user()
            return

        token = auth_header.split('Bearer ')[1]

        try:
            # Decode the token
            decoded_data = jwt.decode(
                token,
                settings.SECRET_KEY,
                algorithms=["HS256"]
            )
            # Retrieve the user by user_id
            user = User.objects.get(pk=decoded_data['user_id'])
            request.user = user  # Authenticated user is set in request

        except (ExpiredSignatureError, InvalidTokenError, ObjectDoesNotExist):
            # If token is expired, invalid, or user doesn't exist, treat as guest user
            request.user = self.create_guest_user()

    def process_response(self, request, response):
        """Ensure a valid token is always in the response, especially for guest users."""
        if not hasattr(request, 'user') or isinstance(request.user, GuestUser):
            # If user is a guest or user is missing, generate guest token
            guest_token = self.generate_guest_token()
            response['Authorization'] = f'Bearer {guest_token}'
            response.set_cookie('jwt_token', guest_token, httponly=True, secure=True, samesite='Lax')
        return response

    def create_guest_user(self):
        """Create a guest user (user_id=0)."""
        return GuestUser()

    def generate_guest_token(self):
        """Generate a JWT for the guest user."""
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
        # If user is not authenticated, respond with an error
        if isinstance(request.user, GuestUser):
            return JsonResponse({'error': 'Authentication required.'}, status=401)
        return view_func(request, *args, **kwargs)
    return _wrapped_view
