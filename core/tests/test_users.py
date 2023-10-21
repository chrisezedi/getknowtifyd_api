import pytest
from django.core import mail
from rest_framework import status
from core.models import User
from core.tokens import token_generator


@pytest.mark.django_db
class TestCreateUser:
    def test_invalid_data_returns_400(self, make_api_request):
        response = make_api_request("/auth/signup", {'username': 'johndoe'})

        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_username_or_email_already_exist_returns_400(self, make_api_request):
        User.objects.create_user(username='johndoe', email='johndoe@example.com', password='password123$',
                                 first_name='john', last_name='doe')

        response = make_api_request("/auth/signup", {
            'username': 'johndoe', 'email': 'johndoe@example.com', 'password': 'password123$',
            'first_name': 'john', 'last_name': 'doe'
           })

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.data['email'] is not None
        assert 'unique' == response.data['email'][0].code

    def test_user_created_returns_201(self, make_api_request):
        response = make_api_request("/auth/signup", {
            'username': 'johndoe', 'email': 'johndoe@example.com',
            'password': 'password123$', 'first_name': 'john', 'last_name': 'doe'
        })

        assert response.status_code == status.HTTP_201_CREATED
        assert response.data['is_active'] is False

    def test_send_activation_email(self, make_api_request):
        make_api_request("/auth/signup", {
            'username': 'johndoe', 'email': 'johndoe@example.com',
            'password': 'password123$', 'first_name': 'john', 'last_name': 'doe'
        })

        assert len(mail.outbox) == 1
        assert 'Account Activation' == mail.outbox[0].subject
        assert 'johndoe@example.com' == mail.outbox[0].to[0]


@pytest.mark.django_db
class TestActivateUser:
    def test_invalid_data_returns_400(self, make_put_request):
        response = make_put_request("/auth/activate", {})

        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_user_not_found_returns_404(self, make_put_request):
        response = make_put_request("/auth/activate", {'uid': 'john', 'token': 'test'})

        # send 400 instead of 404, user should not be able to guess the actual issue
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_token_invalid_returns_400(self, make_put_request):
        instance = User.objects.create_user(
            username='johndoe', email='johndoe@example.com', password='password123$',
            first_name='john', last_name='doe')

        response = make_put_request("/auth/activate", {'uid': instance, 'token': 'invalid token'})

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.data['err_type'] == 'invalid_token'

    def test_token_valid_returns_200(self, make_put_request):
        instance = User.objects.create_user(
            username='johndoe', email='johndoe@example.com', password='password123$',
            first_name='john', last_name='doe')

        response = make_put_request("/auth/activate", {'uid': instance, 'token': token_generator.make_token(instance)})

        assert response.status_code == status.HTTP_200_OK


@pytest.mark.django_db
class TestResendActivationMail:
    def test_invalid_data_returns_400(self, make_api_request):
        response = make_api_request("/auth/resendactivationmail", {})
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_user_not_found_returns_404(self, make_api_request):
        response = make_api_request("/auth/resendactivationmail", {'uid': 'john@example.com'})

        # send 400 instead of 404, user should not be able to guess the actual issue
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_user_already_active(self, make_api_request):
        User.objects.create_user(
            username='johndoe', email='johndoe@example.com', password='password123$',
            first_name='john', last_name='doe')

        response = make_api_request("/auth/resendactivationmail", {'uid': 'johndoe@example.com'})

        assert response.status_code == status.HTTP_200_OK
        assert response.data['redirect'] == "/"
