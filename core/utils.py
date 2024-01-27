import os
from rest_framework.response import Response
from rest_framework import status
from django.conf import settings
from .models import generate_token_for_user
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.core.mail import EmailMultiAlternatives
from .tokens import token_generator


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
