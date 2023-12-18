import os
import getknowtifyd.settings

from django.core.mail import EmailMultiAlternatives
from django.contrib.sites.shortcuts import get_current_site
from django.http import Http404
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from rest_framework import views, status
from rest_framework.generics import GenericAPIView
from rest_framework.mixins import CreateModelMixin
from rest_framework.response import Response
from rest_framework.request import Request
from rest_framework.exceptions import ValidationError
from django.shortcuts import get_object_or_404
from .models import User, generate_token_for_user
from .serializers import (UserSerializer, ActivateUserSerializer, ResendActivationMailSerializer,
                          CheckUsernameAvailability)
from .tokens import token_generator
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.views import TokenRefreshView


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
    email.send()


class CreateUser(CreateModelMixin, GenericAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    current_site = ""

    def post(self, request, *args, **kwargs):
        self.current_site = get_current_site(request)
        return self.create(request, *args, **kwargs)

    def perform_create(self, serializer):
        try:
            password = serializer.validated_data['password']
            user = User(**serializer.validated_data)
            user.set_password(password)
            user.is_active = False
            user.save()
            if user:
                send_activation_mail(user, serializer.data)
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
                    access_refresh_token = generate_token_for_user(user)
                    response = Response({
                        "message": "Account Activated Successfully", "access_token": access_refresh_token["access"]},
                        status=status.HTTP_200_OK)
                    same_site = "None" if getknowtifyd.settings.DEBUG else "strict"
                    response.set_cookie(
                        "refresh_token", access_refresh_token["refresh"], max_age=86400,
                        httponly=True, samesite=same_site, secure=True)
                    return response
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
            serializer = CheckUsernameAvailability(data=request.data)
            if serializer.is_valid(raise_exception=True):
                validated_username = serializer.validated_data["username"]
                username_available = not User.objects.filter(username=validated_username).exists()
                username = validated_username if username_available else None
                return Response({"usernameAvailable": username_available, "username": username})
        except ValidationError as error:
            return Response({"error": str(error), "message": "Username field is invalid"},
                            status=status.HTTP_400_BAD_REQUEST)
