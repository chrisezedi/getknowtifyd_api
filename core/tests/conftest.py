from rest_framework.test import APIClient
import pytest


@pytest.fixture()
def api_client():
    return APIClient()


@pytest.fixture()
def make_api_request(api_client):
    def do_make_api_request(route, payload):
        return api_client.post(route, payload)
    return do_make_api_request


@pytest.fixture()
def make_put_request(api_client):
    def do_make_put_request(route, payload):
        return api_client.put(route, payload)
    return do_make_put_request
