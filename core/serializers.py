from rest_framework import serializers
from .models import User, generate_sys_username


class UserSerializer(serializers.ModelSerializer):
    system_gen_username = generate_sys_username()
    username = serializers.CharField(default=system_gen_username)

    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'email', 'password', 'username', 'is_active']
        read_only = ['is_active']
        extra_kwargs = {
            'password': {'write_only': True},
        }


class ActivateUserSerializer(serializers.Serializer):
    uid = serializers.CharField()
    token = serializers.CharField()


class ResendActivationMailSerializer(serializers.Serializer):
    uid = serializers.CharField()


class UsernameAvailabilitySerializer(serializers.Serializer):
    username = serializers.CharField()


class LoginUserSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField()


class GoogleAuthSerializer(serializers.Serializer):
    code = serializers.CharField()


class ForgotPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()