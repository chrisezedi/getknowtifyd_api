import pytest

from rest_framework.test import APIClient
from core.models import User


@pytest.fixture()
def api_client():
    return APIClient()


@pytest.fixture()
def make_api_request(api_client):
    def do_make_api_request(route, payload, create_user=None):
        if create_user:
            user = User.create_dummy_user()
            api_client.force_authenticate(user=user)
        return api_client.post(route, payload)
    return do_make_api_request


@pytest.fixture()
def make_put_request(api_client):
    def do_make_put_request(route, payload):
        return api_client.put(route, payload)
    return do_make_put_request
