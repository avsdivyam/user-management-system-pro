import uuid
import datetime
from django.shortcuts import get_object_or_404, render, redirect
from django.contrib.auth import get_user_model, login, logout
from django.utils import timezone
from django.conf import settings
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.http import JsonResponse
from django.contrib import messages

from rest_framework import viewsets, status, permissions
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.tokens import RefreshToken

from .models import UserProfile, LoginHistory
from .serializers import (
    CustomTokenObtainPairSerializer,
    UserSerializer,
    UserProfileSerializer,
    LoginHistorySerializer,
    PasswordResetRequestSerializer,
    PasswordResetConfirmSerializer,
    EmailVerificationSerializer,
)

User = get_user_model()


@method_decorator(csrf_exempt, name='dispatch')
class CustomTokenObtainPairView(TokenObtainPairView):
    """
    Custom token view that uses our enhanced token serializer
    """
    serializer_class = CustomTokenObtainPairSerializer
    
    def post(self, request, *args, **kwargs):
        print("Login request data:", request.data)
        try:
            response = super().post(request, *args, **kwargs)
            
            if response.status_code == 200:
                # Record successful login
                user = User.objects.get(email=request.data.get('email'))
                
                # Also log in the user for session-based auth (for UI views)
                from django.contrib.auth import login
                login(request, user)
                
                # Get client IP and user agent
                ip_address = self.get_client_ip(request)
                user_agent = request.META.get('HTTP_USER_AGENT', '')
                
                # Create login history entry
                LoginHistory.objects.create(
                    user=user,
                    ip_address=ip_address,
                    user_agent=user_agent,
                    device_type=self.get_device_type(user_agent),
                    success=True
                )
                
                # Update user's last login IP
                user.last_login_ip = ip_address
                user.failed_login_attempts = 0  # Reset failed attempts on successful login
                user.save()
                
                # Add a redirect URL to the response
                response.data['redirect'] = '/dashboard/'
            
            return response
        except Exception as e:
            print("Login error:", str(e))
            return Response(
                {"detail": "Invalid credentials or server error. Please try again."},
                status=status.HTTP_400_BAD_REQUEST
            )
    
    def get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
    
    def get_device_type(self, user_agent):
        if 'Mobile' in user_agent:
            return 'Mobile'
        elif 'Tablet' in user_agent:
            return 'Tablet'
        else:
            return 'Desktop'


@method_decorator(csrf_exempt, name='dispatch')
class UserViewSet(viewsets.ModelViewSet):
    """
    ViewSet for managing users
    """
    queryset = User.objects.all()
    serializer_class = UserSerializer
    
    def get_permissions(self):
        """
        Override permissions based on action
        """
        if self.action == 'create':
            # Allow anyone to register
            permission_classes = [permissions.AllowAny]
        else:
            # Require authentication for other actions
            permission_classes = [permissions.IsAuthenticated]
            
            # For retrieve, update, and destroy, ensure users can only access their own data
            # unless they are staff
            if self.action in ['retrieve', 'update', 'partial_update', 'destroy']:
                permission_classes.append(permissions.IsAdminUser | 
                                          (lambda r: r.user.id == int(r.parser_context['kwargs']['pk'])))
        
        return [permission() for permission in permission_classes]
    
    def create(self, request, *args, **kwargs):
        """Override create to provide better error messages"""
        print("Create user request data:", request.data)
        serializer = self.get_serializer(data=request.data)
        
        if not serializer.is_valid():
            print("Validation errors:", serializer.errors)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            
        user = serializer.save()
        self.send_verification_email(user)
        
        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)
        
    @action(detail=False, methods=['get'], permission_classes=[permissions.IsAuthenticated])
    def me(self, request):
        """Return the current user's details"""
        print(f"User requesting profile: {request.user.email}")
        serializer = self.get_serializer(request.user)
        return Response(serializer.data)
    
    def send_verification_email(self, user):
        """Generate verification token and send email"""
        token = str(uuid.uuid4())
        user.email_verification_token = token
        user.save()
        
        verification_url = f"{settings.FRONTEND_URL}/verify-email/{token}/"
        
        # Send email
        subject = "Verify your email address"
        message = f"Please click the link to verify your email: {verification_url}"
        email_from = settings.DEFAULT_FROM_EMAIL
        recipient_list = [user.email]
        
        try:
            send_mail(subject, message, email_from, recipient_list)
        except Exception as e:
            print(f"Failed to send verification email: {e}")
    
    @method_decorator(csrf_exempt, name='verify_email')
    @action(detail=False, methods=['post'], permission_classes=[permissions.AllowAny])
    def verify_email(self, request):
        """Verify email with token"""
        serializer = EmailVerificationSerializer(data=request.data)
        if serializer.is_valid():
            token = serializer.validated_data['token']
            user = get_object_or_404(User, email_verification_token=token)
            
            user.email_verified = True
            user.email_verification_token = None
            user.save()
            
            return Response({"detail": "Email successfully verified."}, 
                           status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    @method_decorator(csrf_exempt, name='reset_password_request')
    @action(detail=False, methods=['post'], permission_classes=[permissions.AllowAny])
    def reset_password_request(self, request):
        """Request password reset"""
        serializer = PasswordResetRequestSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            user = get_object_or_404(User, email=email)
            
            # Generate token and set expiry
            token = str(uuid.uuid4())
            user.reset_password_token = token
            user.reset_password_expires = timezone.now() + datetime.timedelta(hours=24)
            user.save()
            
            # Send email
            reset_url = f"{settings.FRONTEND_URL}/password-reset/{token}/"
            subject = "Reset your password"
            message = f"Please click the link to reset your password: {reset_url}"
            email_from = settings.DEFAULT_FROM_EMAIL
            recipient_list = [user.email]
            
            try:
                send_mail(subject, message, email_from, recipient_list)
                return Response({"detail": "Password reset email sent."}, 
                               status=status.HTTP_200_OK)
            except Exception as e:
                return Response({"detail": f"Error sending email: {str(e)}"}, 
                               status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    @method_decorator(csrf_exempt, name='reset_password_confirm')
    @action(detail=False, methods=['post'], permission_classes=[permissions.AllowAny])
    def reset_password_confirm(self, request):
        """Confirm password reset with token and new password"""
        serializer = PasswordResetConfirmSerializer(data=request.data)
        if serializer.is_valid():
            token = serializer.validated_data['token']
            password = serializer.validated_data['password']
            
            user = get_object_or_404(User, reset_password_token=token)
            
            # Check if token is expired
            if user.reset_password_expires and user.reset_password_expires < timezone.now():
                return Response({"detail": "Password reset token has expired."}, 
                               status=status.HTTP_400_BAD_REQUEST)
            
            # Reset password
            user.set_password(password)
            user.reset_password_token = None
            user.reset_password_expires = None
            user.save()
            
            return Response({"detail": "Password has been reset successfully."}, 
                           status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    @action(detail=False, methods=['get'], permission_classes=[permissions.IsAuthenticated])
    def me(self, request):
        """Get current user details"""
        serializer = self.get_serializer(request.user)
        return Response(serializer.data)


class UserProfileViewSet(viewsets.ModelViewSet):
    """
    ViewSet for user profiles
    """
    queryset = UserProfile.objects.all()
    serializer_class = UserProfileSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        """Limit non-staff users to their own profile"""
        if self.request.user.is_staff:
            return UserProfile.objects.all()
        return UserProfile.objects.filter(user=self.request.user)
    
    @action(detail=False, methods=['get'])
    def my_profile(self, request):
        """Get current user's profile"""
        profile = get_object_or_404(UserProfile, user=request.user)
        serializer = self.get_serializer(profile)
        return Response(serializer.data)


class LoginHistoryViewSet(viewsets.ReadOnlyModelViewSet):
    """
    ViewSet for login history (read-only)
    """
    serializer_class = LoginHistorySerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        """Limit non-staff users to their own login history"""
        if self.request.user.is_staff:
            return LoginHistory.objects.all()
        return LoginHistory.objects.filter(user=self.request.user)


class LogoutView(APIView):
    """
    View for logging out (blacklisting refresh token)
    """
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request):
        try:
            refresh_token = request.data.get('refresh')
            if refresh_token:
                token = RefreshToken(refresh_token)
                token.blacklist()
                return Response({"detail": "Successfully logged out."}, 
                               status=status.HTTP_200_OK)
            else:
                return Response({"detail": "Refresh token is required."}, 
                               status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"detail": f"Error during logout: {str(e)}"}, 
                           status=status.HTTP_400_BAD_REQUEST)


# UI Views for template rendering

def login_view(request):
    """Render the login page"""
    if request.user.is_authenticated:
        return redirect('dashboard')
    return render(request, 'authentication/login.html')

def register_view(request):
    """Render the registration page"""
    if request.user.is_authenticated:
        return redirect('dashboard')
    return render(request, 'authentication/register.html')

def password_reset_view(request):
    """Render the password reset request page"""
    return render(request, 'authentication/password_reset.html')

def password_reset_confirm_view(request, token):
    """Render the password reset confirmation page"""
    context = {'token': token}
    return render(request, 'authentication/password_reset_confirm.html', context)

def email_verify_view(request, token):
    """Render the email verification page"""
    context = {'token': token}
    return render(request, 'authentication/email_verify.html', context)

def dashboard_view(request):
    """Render the user dashboard"""
    if not request.user.is_authenticated:
        messages.error(request, 'Please login to access the dashboard.')
        return redirect('login')
    return render(request, 'authentication/dashboard.html')

def profile_view(request):
    """Render the user profile page"""
    if not request.user.is_authenticated:
        messages.error(request, 'Please login to access your profile.')
        return redirect('login')
    return render(request, 'authentication/profile.html')

def settings_view(request):
    """Render the settings page"""
    if not request.user.is_authenticated:
        messages.error(request, 'Please login to access settings.')
        return redirect('login')
    return render(request, 'authentication/settings.html')

def logout_view(request):
    """Handle user logout"""
    logout(request)
    messages.success(request, 'You have been successfully logged out.')
    return redirect('login')
