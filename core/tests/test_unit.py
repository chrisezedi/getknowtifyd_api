from django.test import TestCase
from unittest.mock import patch, MagicMock
from core.models import User
from core.utils import generate_access_refresh_token_response, send_activation_mail


class TestUtils(TestCase):
    # mock user instance
    mock_user_instance = MagicMock(spec=User)

    @patch("core.utils.generate_token_for_user")
    def test_generate_access_refresh_token_response(self, mock_generate_token_for_user):

        # stub: mock_generate_token_for_user return value
        mock_generate_token_for_user.return_value = {"access": "mock access token", "refresh": "mock refresh token"}

        response = generate_access_refresh_token_response(self.mock_user_instance)

        mock_generate_token_for_user.assert_called_once_with(self.mock_user_instance)
        self.assertEqual(response.status_code, 200)
        self.assertIn('refresh_token', response.cookies)

    def test_send_activation_mail(self):
        data = {"email": "johndoe@example.com"}
        response = send_activation_mail(self.mock_user_instance, data)
        self.assertEqual(response, 1)
