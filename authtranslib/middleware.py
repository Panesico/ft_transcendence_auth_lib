import jwt
from django.conf import settings
from django.utils.deprecation import MiddlewareMixin
from django.http import JsonResponse
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError

class GuestUser:
    def __init__(self):
        self.user_id = 0
        self.is_authenticated = False
        self.role = 'guest'

class JWTAuthenticationMiddleware(MiddlewareMixin):
    def process_request(self, request):
        # Extract the JWT token from the Authorization header
        auth_header = request.headers.get('Authorization')

        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split('Bearer ')[1]

            try:
                # Decode the token using the secret key and algorithm
                decoded_data = jwt.decode(
                    token,
                    settings.SECRET_KEY,
                    algorithms=["HS256"]
                )
                decoded_data['is_authenticated'] = True
                request.user = decoded_data  # For authenticated users, set the user info

            except (ExpiredSignatureError, InvalidTokenError):
                # Token is invalid or expired, treat as guest
                request.user = GuestUser()
        else:
            # No valid token, treat as guest
            request.user = GuestUser()

    def process_response(self, request, response):
        # Automatically issue a guest token if no valid token was provided
        if isinstance(request.user, GuestUser):
            guest_token = self.generate_guest_token()
            response['Authorization'] = f'Bearer {guest_token}'
        
        return response

    def generate_guest_token(self):
        # Generate a JWT for a guest user with user_id = 0
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
