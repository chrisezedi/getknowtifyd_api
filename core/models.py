from django.contrib.auth.models import AbstractUser
from django.db import models


class User(AbstractUser):
    USERNAME_FIELD = "email"
    email = models.EmailField(unique=True)
    username = models.CharField(blank=True, max_length=150)
    REQUIRED_FIELDS = []
