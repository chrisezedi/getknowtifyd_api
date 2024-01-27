import pytest
from django.core import mail
from rest_framework.test import APITestCase
from rest_framework import status
from core.models import User
from core.tokens import token_generator


@pytest.mark.django_db
class TestCreateUserView:
    endpoint = "/auth/signup"
    user = {'username': 'johndoe', 'email': 'johndoe@example.com', 'password': 'password123$',
            'first_name': 'john', 'last_name': 'doe'}

    def test_invalid_data_returns_400(self, make_api_request):
        response = make_api_request(self.endpoint, {'username': 'johndoe'})

        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_username_or_email_already_exist_returns_400(self, make_api_request):
        User.create_dummy_user()

        response = make_api_request(self.endpoint, self.user)
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_user_created_returns_201(self, make_api_request):
        response = make_api_request(self.endpoint, self.user)
        assert response.status_code == status.HTTP_201_CREATED
        assert response.data["user"]["is_active"] is False

    def test_send_activation_email(self, make_api_request):
        make_api_request(self.endpoint, self.user)

        assert len(mail.outbox) == 1
        assert 'Account Activation' == mail.outbox[0].subject
        assert 'johndoe@example.com' == mail.outbox[0].to[0]


@pytest.mark.django_db
class TestActivateUserView:
    endpoint = "/auth/activate"

    def test_invalid_data_returns_400(self, make_put_request):
        response = make_put_request(self.endpoint, {})

        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_user_not_found_returns_404(self, make_put_request):
        response = make_put_request("/auth/activate", {'uid': 'john', 'token': 'test'})

        # send 400 instead of 404, user should not be able to guess the actual issue
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_token_invalid_returns_400(self, make_put_request):
        instance = User.create_dummy_user()

        response = make_put_request("/auth/activate", {'uid': instance, 'token': 'invalid token'})

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.data['err_type'] == 'invalid_token'

    def test_token_valid_returns_200(self, make_put_request):
        instance = User.create_dummy_user()

        response = make_put_request("/auth/activate", {'uid': instance, 'token': token_generator.make_token(instance)})

        assert response.status_code == status.HTTP_200_OK


@pytest.mark.django_db
class TestResendActivationMailView:
    def test_invalid_data_returns_400(self, make_api_request):
        response = make_api_request("/auth/resendactivationmail", {})
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_user_not_found_returns_404(self, make_api_request):
        response = make_api_request("/auth/resendactivationmail", {'uid': 'john@example.com'})

        # send 400 instead of 404, user should not be able to guess the actual issue
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_user_already_active(self, make_api_request):
        User.create_dummy_user()

        response = make_api_request("/auth/resendactivationmail", {'uid': 'johndoe@example.com'})

        assert response.status_code == status.HTTP_200_OK


@pytest.mark.django_db
class TestUsernameAvailabilityView:
    endpoint = "/user/check-username-availability"

    def test_username_field_invalid(self, make_api_request):
        response = make_api_request(self.endpoint, {}, create_user=True)

        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_user_not_authenticated(self, make_api_request):
        response = make_api_request(self.endpoint, {'username': 'johndoe'})

        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_username_not_available(self, make_api_request):
        response = make_api_request(self.endpoint, {'username': 'johndoe'}, create_user=True)

        assert response.status_code == status.HTTP_200_OK
        assert response.data["usernameAvailable"] is False
        assert response.data["username"] is None

    def test_username_available(self, make_api_request):
        response = make_api_request(self.endpoint, {'username': 'johndoe1'}, create_user=True)

        assert response.status_code == status.HTTP_200_OK
        assert response.data["usernameAvailable"] is True
        assert response.data["username"] == "johndoe1"


@pytest.mark.django_db
class TestSetUsernameView:
    endpoint = "/user/set-username"

    def test_username_field_invalid(self, make_api_request):
        response = make_api_request(self.endpoint, {}, create_user=True)

        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_user_not_authenticated(self, make_api_request):
        response = make_api_request(self.endpoint, {'username': 'johndoe'})

        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_username_not_available(self, make_api_request):
        response = make_api_request(self.endpoint, {'username': 'johndoe'}, create_user=True)

        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_username_is_set(self, make_api_request):
        response = make_api_request(self.endpoint, {'username': 'janedoe'}, create_user=True)

        assert response.status_code == status.HTTP_200_OK
        assert response.data["username"] == "janedoe"


@pytest.mark.django_db
class TestUserLoginView:
    endpoint = "/auth/signin"

    def test_login_props_invalid(self, make_api_request):
        response = make_api_request(self.endpoint, {})

        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_user_does_not_exist(self, make_api_request):
        response = make_api_request(self.endpoint, {"email": "johndoe@example.com", "password": "password"})

        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_invalid_signin_password(self, make_api_request):
        response = make_api_request(self.endpoint, {"email": "johndoe@example.com", "password": "password"},
                                    create_user=True)

        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_signin_success(self, make_api_request):
        response = make_api_request(self.endpoint, {"email": "johndoe@example.com", "password": "password123$"},
                                    create_user=True)

        assert response.status_code == status.HTTP_200_OK
        assert "access" in response.data
        assert "refresh_token" in response.cookies


@pytest.mark.django_db
class TestGoogleLoginView:
    endpoint = "/auth/google-auth"

    def test_invalid_request_returns_400(self, make_api_request):
        response = make_api_request(self.endpoint, {})

        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_google_returns_access_token(self, make_api_request):
        data = {
                    "code": code,
                    "client_id": os.environ.get("GOOGLE_OAUTH2_CLIENT_ID"),
                    "client_secret": os.environ.get("GOOGLE_OAUTH2_CLIENT_SECRET"),
                    "redirect_uri": os.environ.get("redirect_uri"),
                    "grant_type": 'authorization_code'
                }