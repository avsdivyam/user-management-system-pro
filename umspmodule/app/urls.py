from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name='home'),
    # Add other app-specific URLs here
]

