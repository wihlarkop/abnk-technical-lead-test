from django.urls import reverse
from rest_framework.test import APITestCase
from rest_framework import status
from unittest.mock import patch


class MyInfoAuthViewTest(APITestCase):

    @patch("myinfo.client.MyInfoPersonalClientV4.get_authorise_url")
    def test_get_auth_url(self, mock_get_authorise_url):
        mock_get_authorise_url.return_value = "https://test.api.myinfo.gov.sg/auth"

        url = reverse("myinfo-auth")
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data, "https://test.api.myinfo.gov.sg/auth")


class MyInfoCallbackViewTest(APITestCase):

    @patch("myinfo.client.MyInfoPersonalClientV4.retrieve_resource")
    def test_get_person_data_success(self, mock_retrieve_resource):
        mock_retrieve_resource.return_value = {"uinfin": "S1234567D", "name": "John Doe"}

        url = reverse("myinfo-callback")
        response = self.client.get(url, {"code": "valid_auth_code"})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data, {"uinfin": "S1234567D", "name": "John Doe"})

    def test_get_person_data_missing_code(self):
        url = reverse("myinfo-callback")
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data, ["Missing 'code' parameter."])
