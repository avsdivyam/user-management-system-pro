from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

router = DefaultRouter()
router.register(r'users', views.UserViewSet)
router.register(r'profiles', views.UserProfileViewSet)
router.register(r'login-history', views.LoginHistoryViewSet, basename='login-history')

urlpatterns = [
    # JWT token endpoints with custom view
    path('token/', views.CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),
    
    # Logout endpoint
    path('logout/', views.LogoutView.as_view(), name='logout'),
    
    # Include router URLs
    path('', include(router.urls)),
]