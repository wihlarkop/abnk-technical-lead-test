from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.exceptions import ValidationError
from django.utils.crypto import get_random_string
from myinfo.client import MyInfoPersonalClientV4

state = get_random_string(length=16)


class MyInfoAuthView(APIView):

    def get(self, request):
        callback_url = "http://localhost:3001/callback"
        client = MyInfoPersonalClientV4()
        auth_url = client.get_authorise_url(oauth_state=state, callback_url=callback_url)
        return Response(auth_url)


class MyInfoCallbackView(APIView):

    def get(self, request):
        auth_code = request.query_params.get("code")
        callback_url = "http://localhost:3001/callback"

        if not auth_code:
            raise ValidationError("Missing 'code' parameter.")

        client = MyInfoPersonalClientV4()
        person_data = client.retrieve_resource(auth_code, state, callback_url)

        return Response(person_data)
