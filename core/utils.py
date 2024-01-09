from rest_framework.response import Response
from rest_framework import status
from django.conf import settings
from .models import generate_token_for_user


def generate_access_refresh_token_response(user):
    access_refresh_token = generate_token_for_user(user)
    response = Response({
        "access": access_refresh_token["access"]
    }, status=status.HTTP_200_OK)

    same_site = "None" if settings.DEBUG else "strict"
    response.set_cookie(
        "refresh_token", access_refresh_token["refresh"], max_age=86400,
        httponly=True, samesite=same_site, secure=True)

    return response
