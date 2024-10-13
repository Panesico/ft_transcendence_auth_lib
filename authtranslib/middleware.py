import jwt
from django.conf import settings
from django.utils.deprecation import MiddlewareMixin
from django.http import JsonResponse
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError

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

                # Populate request.user with the decoded information
                request.user = decoded_data

            except ExpiredSignatureError:
                return JsonResponse(
                    {'error': 'Token has expired'},
                    status=401
                )
            except InvalidTokenError:
                return JsonResponse(
                    {'error': 'Invalid token'},
                    status=401
                )
        else:
            request.user = None

        # If no token is provided or the token is invalid, request.user will remain None

    def process_response(self, request, response):
        return response


from functools import wraps
from django.http import JsonResponse


def login_required(view_func):
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        if not request.user:
            return JsonResponse({'error': 'Authentication credentials were not provided.'}, status=401)
        return view_func(request, *args, **kwargs)

    return _wrapped_view

class AdminSessionMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.path.startswith('/admin/'):
            from django.contrib.sessions.middleware import SessionMiddleware
            session_middleware = SessionMiddleware(self.get_response)
            return session_middleware(request)
        return self.get_response(request)
