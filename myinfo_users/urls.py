from django.urls import path

from myinfo_users.views import MyInfoAuthView, MyInfoCallbackView

urlpatterns = [
    path('auth', MyInfoAuthView.as_view(), name='myinfo-auth'),
    path('callback', MyInfoCallbackView.as_view(), name='myinfo-callback'),
]