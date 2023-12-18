from django.contrib.auth.models import AbstractUser
from django.db import models
from rest_framework_simplejwt.tokens import RefreshToken


class User(AbstractUser):
    USERNAME_FIELD = "email"
    email = models.EmailField(unique=True)
    username = models.CharField(blank=True, max_length=150,unique=True)
    REQUIRED_FIELDS = []

    @staticmethod
    def create_dummy_user():
        return User.objects.create_user(
            username='johndoe', email='johndoe@example.com', password='password123$',
            first_name='john', last_name='doe')


def generate_token_for_user(user):
    refresh = RefreshToken.for_user(user)
    refresh['first_name'] = user.first_name
    refresh['username'] = user.username

    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }
