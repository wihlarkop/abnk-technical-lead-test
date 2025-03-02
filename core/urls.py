from django.urls import path, include

urlpatterns = [
    path('', include('myinfo_users.urls')),
]
