import os

import requests

import getknowtifyd.settings

from django.core.mail import EmailMultiAlternatives
from django.contrib.sites.shortcuts import get_current_site
from django.http import Http404
from django.template.loader import render_to_string
from django.utils.html import strip_tags
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

from .models import User, generate_token_for_user, generate_sys_username
from .serializers import (UserSerializer, ActivateUserSerializer, ResendActivationMailSerializer,
                          UsernameAvailabilitySerializer, LoginUserSerializer, GoogleAuthSerializer)
from .tokens import token_generator
from .utils import generate_access_refresh_token_response


# Registration View.
def send_activation_mail(instance, data):
    context = {
        'domain': os.environ.get('CLIENT_DOMAIN'),
        'uid': data['email'],
        'token': token_generator.make_token(instance)
    }

    html_template = render_to_string("content/activate.html", context=context)
    plain_message = strip_tags(html_template)
    email = EmailMultiAlternatives(
        subject="Account Activation",
        body=plain_message,
        from_email="notification@getknowtifyd.com",
        to=[data['email']])

    email.attach_alternative(html_template, "text/html")
    mail_sent = email.send()
    return mail_sent


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
                    access_refresh_token = generate_token_for_user(user)
                    response = Response({
                        "message": "User logged in Successfully", "access_token": access_refresh_token["access"]},
                        status=status.HTTP_200_OK)

                    same_site = "None" if getknowtifyd.settings.DEBUG else "strict"
                    response.set_cookie(
                        "refresh_token", access_refresh_token["refresh"], max_age=86400,
                        httponly=True, samesite=same_site, secure=True)
                    return response

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
                    'code': code,
                    'client_id': os.environ.get("GOOGLE_OAUTH2_CLIENT_ID"),
                    'client_secret': os.environ.get("GOOGLE_OAUTH2_CLIENT_SECRET"),
                    'redirect_uri': os.environ.get("redirect_uri"),
                    'grant_type': 'authorization_code'
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
                            'is_active': True,
                            'username': generate_sys_username()
                        }
                        if not User.objects.filter(email=profile_data["email"]).exists():
                            extra_fields = profile_data.copy()
                            extra_fields.pop("email")
                            user = User.objects.create_user(email=profile_data["email"], password=None, **extra_fields)
                            if user:
                                return generate_access_refresh_token_response(user)
                        else:
                            existing_user = User.objects.get(email=profile_data["email"])
                            return generate_access_refresh_token_response(existing_user)

                    return Response({"token": access_token}, status=status.HTTP_200_OK)
        except ValidationError as error:
            return Response({"error": str(error), "message": "Code not sent"},
                            status=status.HTTP_400_BAD_REQUEST)
