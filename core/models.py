from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.db import models
from rest_framework_simplejwt.tokens import RefreshToken


class CustomUserManager(BaseUserManager):
    """
    Custom user model manager where email is the unique identifiers for authentication instead of usernames.
    """

    def create_user(self, email, password, **extra_fields):
        """
        Create and save a user with the given email and password.
        """
        if not email:
            raise ValueError("The Email must be set")
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save()
        return user

    def create_superuser(self, email, password, **extra_fields):
        """
        Create and save a SuperUser with the given email and password.
        """
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("is_active", True)

        if extra_fields.get("is_staff") is not True:
            raise ValueError(_("Superuser must have is_staff=True."))
        if extra_fields.get("is_superuser") is not True:
            raise ValueError(_("Superuser must have is_superuser=True."))
        return self.create_user(email, password, **extra_fields)


class User(AbstractUser):
    USERNAME_FIELD = "email"
    email = models.EmailField(unique=True)
    username = models.CharField(blank=True, max_length=150, unique=True)
    REQUIRED_FIELDS = []

    objects = CustomUserManager()

    @staticmethod
    def create_dummy_user():
        return User.objects.create_user(email='johndoe@example.com', password='password123$',
                                        first_name='john', last_name='doe', username="johndoe")


def generate_token_for_user(user):
    refresh = RefreshToken.for_user(user)
    refresh['first_name'] = user.first_name
    refresh['username'] = user.username

    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }
