from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import InvalidToken
from .models import UserToken


class SingleSessionJWTAuthentication(JWTAuthentication):
   
    def authenticate(self, request):
        result = super().authenticate(request)
        
        if result is None:
            return None
        
        user, validated_token = result
        
        try:
            UserToken.objects.get(user=user)
        except UserToken.DoesNotExist:
            raise InvalidToken("No active session found. Please log in again.")
        
        return (user, validated_token)
