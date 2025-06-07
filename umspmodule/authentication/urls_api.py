from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views
from django.views.decorators.csrf import csrf_exempt

router = DefaultRouter()
router.register(r'users', views.UserViewSet)
router.register(r'profiles', views.UserProfileViewSet)
router.register(r'login-history', views.LoginHistoryViewSet, basename='login-history')

urlpatterns = [
    # JWT token endpoints with custom view
    path('token/', csrf_exempt(views.CustomTokenObtainPairView.as_view()), name='token_obtain_pair_api'),
    
    # Logout endpoint
    path('logout/', csrf_exempt(views.LogoutView.as_view()), name='logout_api'),
    
    # Include router URLs
    path('', include(router.urls)),
]