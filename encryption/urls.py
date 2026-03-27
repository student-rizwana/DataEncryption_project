"""
API URL configuration for the encryption app.
"""
from django.urls import path
from . import views

urlpatterns = [
    path('register/', views.api_register, name='api_register'),
    path('login/', views.api_login, name='api_login'),
    path('files/', views.api_files, name='api_files'),
    path('keys/generate/', views.api_generate_keys, name='api_generate_keys'),
]

