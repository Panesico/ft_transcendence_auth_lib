import jwt
from django.conf import settings
from django.utils.deprecation import MiddlewareMixin
from django.http import JsonResponse
from django.contrib.auth import get_user_model
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError
from django.core.exceptions import ObjectDoesNotExist

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
        """Process incoming requests to validate JWT tokens."""
        auth_header = request.headers.get('Authorization')

        # If there's no token, treat the user as a guest
        if not auth_header or not auth_header.startswith('Bearer '):
            request.user = GuestUser()
            return

        # Extract the JWT token from the Authorization header
        token = auth_header.split('Bearer ')[1]

        try:
            # Decode the JWT token using the secret key and HS256 algorithm
            decoded_data = jwt.decode(
                token,
                settings.SECRET_KEY,
                algorithms=["HS256"]
            )
            # Get the user from the database using the user_id from the JWT
            user = User.objects.get(pk=decoded_data['user_id'])
            # Assign the authenticated user to request.user
            request.user = user

        except (ExpiredSignatureError, InvalidTokenError, ObjectDoesNotExist):
            # Handle expired, invalid token, or non-existent user (guest user)
            request.user = GuestUser()

    def process_response(self, request, response):
        """Ensure that responses always include a valid token for guest users."""
        if isinstance(request.user, GuestUser):
            guest_token = self.generate_guest_token()
            response['Authorization'] = f'Bearer {guest_token}'

        return response

    def generate_guest_token(self):
        """Generate a JWT for the guest user with user_id = 0."""
        guest_payload = {
            'user_id': 0,
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
