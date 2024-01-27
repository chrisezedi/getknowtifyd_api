import os

import requests

from django.contrib.sites.shortcuts import get_current_site
from django.http import Http404
from django.contrib.auth import get_user_model
from django.shortcuts import get_object_or_404
from django.core.exceptions import ObjectDoesNotExist

from rest_framework import views, status
from rest_framework.generics import CreateAPIView
from rest_framework.response import Response
from rest_framework.request import Request
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.views import TokenRefreshView

from .models import User, generate_sys_username
from .serializers import (UserSerializer, ActivateUserSerializer, ResendActivationMailSerializer,
                          UsernameAvailabilitySerializer, LoginUserSerializer, GoogleAuthSerializer,)
from .utils import generate_access_refresh_token_response, send_activation_mail
from .tokens import token_generator


# Registration View.
class CreateUser(CreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    current_site = None

    def create(self, request, *args, **kwargs):
        try:
            self.current_site = get_current_site(request)
            serializer = self.get_serializer(data=request.data)
            if serializer.is_valid(raise_exception=True):
                properties_to_exclude = ['email', 'password']

                extra_fields = {key: value for key, value in serializer.validated_data.items()
                                if key not in properties_to_exclude}
                user = User.objects.create_user(
                    email=serializer.validated_data["email"],
                    password=serializer.validated_data["password"],
                    **extra_fields)
                if user and send_activation_mail(user, serializer.data) == 1:
                    new_user = serializer.data.copy()
                    new_user.pop("username", None)
                    return Response({'message': 'User created Successfully', "user": new_user},
                                    status=status.HTTP_201_CREATED)

        except ValidationError as e:
            return Response({'message': 'Invalid Request', 'error': str(e)},
                            status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'message': 'Something Went Wrong', 'error': str(e)},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class ActivateUser(views.APIView):
    # noinspection PyMethodMayBeStatic
    def put(self, request):
        generic_response = Response({'message': 'invalid activation link', 'err_type': 'invalid_token'},
                                    status=status.HTTP_400_BAD_REQUEST)
        try:
            serializer = ActivateUserSerializer(data=request.data)
            if serializer.is_valid(raise_exception=True):
                email = serializer.validated_data['uid']
                activation_token = serializer.validated_data['token']

                user = get_object_or_404(User, email=email)
                if token_generator.check_token(user, activation_token):
                    user.is_active = True
                    user.save()
                    return generate_access_refresh_token_response(user)
                else:
                    return generic_response
        except ValidationError:
            return generic_response
        except Http404:
            return generic_response
        except Exception as e:
            return Response({'message': 'Something Went Wrong', 'error': str(e)},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class ResendActivationMail(views.APIView):
    # noinspection PyMethodMayBeStatic
    def post(self, request):
        try:
            serializer = ResendActivationMailSerializer(data=request.data)
            if serializer.is_valid(raise_exception=True):
                email = serializer.validated_data['uid']
                user = get_object_or_404(User, email=email)
                if user.is_active:
                    return Response({'message': 'This account has already been activated', 'redirect': '/'},
                                    status=status.HTTP_200_OK)
                else:
                    send_activation_mail(user, {'email': serializer.validated_data['uid']})

        except ValidationError:
            return Response({'message': 'Invalid Request', 'err_type': 'invalid_request'},
                            status=status.HTTP_400_BAD_REQUEST)
        except Http404:
            return Response({
                'message': 'Invalid activation link',
                'err_type': 'invalid_token'},
                status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'message': 'Something Went Wrong', 'error': str(e)},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response({'message': 'Check your mail, another activation mail has been sent.'},
                        status=status.HTTP_200_OK)


class CustomTokenRefreshView(TokenRefreshView):
    def post(self, request: Request, *args, **kwargs) -> Response:
        if "refresh" not in request.data and request.COOKIES.get("refresh_token"):
            refresh_token = request.COOKIES.get("refresh_token")
            request.data["refresh"] = refresh_token
        return super().post(request, *args, **kwargs)


class CheckUsernameAvailabilityView(views.APIView):
    permission_classes = [IsAuthenticated]

    # noinspection PyMethodMayBeStatic
    def post(self, request):
        try:
            serializer = UsernameAvailabilitySerializer(data=request.data)
            if serializer.is_valid(raise_exception=True):
                validated_username = serializer.validated_data["username"]
                username_available = not User.objects.filter(username=validated_username).exists()
                username = validated_username if username_available else None
                return Response({"usernameAvailable": username_available, "username": username})
        except ValidationError as error:
            return Response({"error": str(error), "message": "Username field is invalid"},
                            status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'message': 'Something Went Wrong', 'error': str(e)},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class SetUsernameView(views.APIView):
    permission_classes = [IsAuthenticated]

    # noinspection PyMethodMayBeStatic
    def post(self, request):
        try:
            serializer = UsernameAvailabilitySerializer(data=request.data)
            if serializer.is_valid(raise_exception=True):
                username = serializer.validated_data["username"]
                username_available = not User.objects.filter(username=username).exists()
                if not username_available:
                    return Response({"message": "This username is not available"}, status=status.HTTP_400_BAD_REQUEST)
                else:
                    user = User.objects.get(email=request.user)
                    user.username = username
                    user.save()
                    return Response({"message": "username set successfully", "username": user.username},
                                    status=status.HTTP_200_OK)

        except ValidationError as error:
            return Response({"error": str(error), "message": "Username field is invalid"},
                            status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'message': 'Something Went Wrong', 'error': str(e)},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class LoginUserView(views.APIView):

    # noinspection PyMethodMayBeStatic

    def post(self, request):
        invalid_response = Response({"message": "Email or Password invalid"}, status=status.HTTP_400_BAD_REQUEST)
        try:
            serializer = LoginUserSerializer(data=request.data)
            if serializer.is_valid(raise_exception=True):
                email = serializer.validated_data["email"]
                password = serializer.validated_data["password"]
                user = get_user_model().objects.get(email=email)

                if not user.check_password(password):
                    return invalid_response
                else:
                    return generate_access_refresh_token_response(user)

        except ValidationError as error:
            return Response({"error": str(error), "message": "Invalid Request"},
                            status=status.HTTP_400_BAD_REQUEST)
        except ObjectDoesNotExist:
            return invalid_response
        except Exception as e:
            return Response({'message': 'Something Went Wrong', 'error': str(e)},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class GoogleAuthView(views.APIView):
    # noinspection PyMethodMayBeStatic

    def post(self, request):
        try:
            serializer = GoogleAuthSerializer(data=request.data)

            if serializer.is_valid(raise_exception=True):
                code = serializer.validated_data["code"]
                data = {
                    "code": code,
                    "client_id": os.environ.get("GOOGLE_OAUTH2_CLIENT_ID"),
                    "client_secret": os.environ.get("GOOGLE_OAUTH2_CLIENT_SECRET"),
                    "redirect_uri": os.environ.get("redirect_uri"),
                    "grant_type": 'authorization_code'
                }

                response = requests.post("https://oauth2.googleapis.com/token", data=data)
                google_error_response = Response({"message": "something went wrong"},
                                                 status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                if not response.ok:
                    return google_error_response
                else:
                    access_token = response.json()["access_token"]
                    response = requests.get("https://www.googleapis.com/oauth2/v3/userinfo",
                                            params={'access_token': access_token})
                    if not response.ok:
                        return google_error_response
                    else:
                        user_data = response.json()
                        profile_data = {
                            'email': user_data['email'],
                            'first_name': user_data.get('given_name', ''),
                            'last_name': user_data.get('family_name', ''),
                            'username': generate_sys_username()
                        }
                        if not User.objects.filter(email=profile_data["email"]).exists():
                            extra_fields = profile_data.copy()
                            extra_fields.pop("email")
                            user = User.objects.create_user(email=profile_data["email"], password=None, is_active=True,
                                                            **extra_fields)
                            if user:
                                return generate_access_refresh_token_response(user)
                        else:
                            existing_user = User.objects.get(email=profile_data["email"])
                            return generate_access_refresh_token_response(existing_user)

                    return Response({"token": access_token}, status=status.HTTP_200_OK)
        except ValidationError as error:
            return Response({"error": str(error), "message": "Code not sent"},
                            status=status.HTTP_400_BAD_REQUEST)


class SendPasswordResetLinkView(views.APIView):
    # noinspection PyMethodMayBeStatic
    def post(self):
        """ --- SEND_PASSWORD_RESET_VIEW ---
            - request for email,
            - send reset link with token (mail inside token)
            ------------------------------------------------
            --- RESET_PASSWORD_VIEW ---
            - verify that token is correct and retrieve email
            - if not valid, token has expired or invalid
            - if valid ask for new password,
            - validate password and update
            - redirect user to login view, where they need to enter new password
        """
        # serializer =
