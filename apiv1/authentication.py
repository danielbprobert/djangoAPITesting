from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth.models import User
from .models import APIKeys

class CustomTokenAuthentication(BaseAuthentication):
    """
    Custom authentication class that verifies tokens from the APIKeys model.
    """

    def authenticate(self, request):
        # Get the token from the 'Authorization' header
        auth_header = request.headers.get("Authorization")
        if not auth_header:
            return None  # No token provided, let other authentication classes handle it.

        try:
            prefix, token = auth_header.split()
            if prefix.lower() != "token":
                raise AuthenticationFailed("Invalid token prefix. Use 'Token <your_token>'")
        except ValueError:
            raise AuthenticationFailed("Authorization header must be in format 'Token <your_token>'")

        # Validate token
        try:
            api_key = APIKeys.objects.get(key=token)
        except APIKeys.DoesNotExist:
            raise AuthenticationFailed("Invalid or expired token.")

        return (api_key.user, token)  # Return user and token
