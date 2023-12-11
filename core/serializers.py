from rest_framework import serializers
from .models import User


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'email', 'username', 'password', 'is_active']
        read_only = ['is_active']


class ActivateUserSerializer(serializers.Serializer):
    uid = serializers.CharField()
    token = serializers.CharField()


class ResendActivationMailSerializer(serializers.Serializer):
    uid = serializers.CharField()


class CheckUsernameAvailability(serializers.Serializer):
    username = serializers.CharField()
