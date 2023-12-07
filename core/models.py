from django.contrib.auth.models import AbstractUser
from django.db import models
from rest_framework_simplejwt.tokens import RefreshToken


class User(AbstractUser):
    USERNAME_FIELD = "email"
    email = models.EmailField(unique=True)
    username = models.CharField(blank=True, max_length=150,unique=True)
    REQUIRED_FIELDS = []


def generate_token_for_user(user):
    refresh = RefreshToken.for_user(user)
    refresh['first_name'] = user.first_name
    refresh['username'] = user.username

    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }
