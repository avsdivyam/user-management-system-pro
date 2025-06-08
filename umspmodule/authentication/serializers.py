from rest_framework import serializers
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from .models import UserProfile, LoginHistory

User = get_user_model()


class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    """
    Custom token serializer that adds user details to the token response
    """
    
    def validate(self, attrs):
        data = super().validate(attrs)
        
        # Add custom claims
        data.update({
            'user_id': self.user.id,
            'email': self.user.email,
            'first_name': self.user.first_name,
            'last_name': self.user.last_name,
            'is_staff': self.user.is_staff,
            'is_active': self.user.is_active,
        })
        
        return data


class UserSerializer(serializers.ModelSerializer):
    """
    Serializer for the User model
    """
    # Use a custom password field without the complex validation for demonstration
    password = serializers.CharField(write_only=True, required=True)
    password_confirm = serializers.CharField(write_only=True, required=True)
    
    class Meta:
        model = User
        fields = ('id', 'email', 'first_name', 'last_name', 'password', 'password_confirm', 
                  'phone_number', 'profile_picture', 'bio', 'is_active', 'date_joined')
        read_only_fields = ('id', 'date_joined', 'is_active')
        extra_kwargs = {
            'first_name': {'required': True},
            'last_name': {'required': True},
        }
    
    def validate(self, attrs):
        if attrs.get('password') != attrs.get('password_confirm'):
            raise serializers.ValidationError({"password": "Password fields didn't match."})
        
        # Basic password validation - at least 8 characters
        if len(attrs.get('password', '')) < 8:
            raise serializers.ValidationError({"password": "Password must be at least 8 characters long."})
            
        return attrs
    
    def create(self, validated_data):
        # Remove password_confirm as it's not needed for user creation
        validated_data.pop('password_confirm', None)
        
        # Create the user
        user = User.objects.create_user(
            email=validated_data['email'],
            password=validated_data['password'],
            first_name=validated_data.get('first_name', ''),
            last_name=validated_data.get('last_name', ''),
            phone_number=validated_data.get('phone_number', ''),
            bio=validated_data.get('bio', ''),
            profile_picture=validated_data.get('profile_picture', None),
        )
        
        # Create an empty profile for the user
        UserProfile.objects.create(user=user)
        
        return user
    
    def update(self, instance, validated_data):
        # Handle password separately
        password = validated_data.pop('password', None)
        password_confirm = validated_data.pop('password_confirm', None)
        
        # Update the instance with all other fields
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        
        # Handle password change if provided
        if password and password_confirm and password == password_confirm:
            instance.set_password(password)
        
        instance.save()
        return instance


class UserProfileSerializer(serializers.ModelSerializer):
    """
    Serializer for the UserProfile model
    """
    class Meta:
        model = UserProfile
        fields = ('id', 'user', 'address', 'city', 'state', 'country', 
                  'postal_code', 'birth_date')
        read_only_fields = ('id', 'user')


class LoginHistorySerializer(serializers.ModelSerializer):
    """
    Serializer for the LoginHistory model
    """
    class Meta:
        model = LoginHistory
        fields = ('id', 'user', 'login_datetime', 'ip_address', 
                  'user_agent', 'device_type', 'success')
        read_only_fields = ('id', 'user', 'login_datetime')


class PasswordResetRequestSerializer(serializers.Serializer):
    """
    Serializer for password reset request
    """
    email = serializers.EmailField(required=True)
    
    def validate_email(self, value):
        if not User.objects.filter(email=value).exists():
            raise serializers.ValidationError("User with this email does not exist.")
        return value


class PasswordResetConfirmSerializer(serializers.Serializer):
    """
    Serializer for password reset confirmation
    """
    token = serializers.CharField(required=True)
    password = serializers.CharField(write_only=True, required=True)
    password_confirm = serializers.CharField(write_only=True, required=True)
    
    def validate(self, attrs):
        if attrs.get('password') != attrs.get('password_confirm'):
            raise serializers.ValidationError({"password": "Password fields didn't match."})
            
        # Basic password validation - at least 8 characters
        if len(attrs.get('password', '')) < 8:
            raise serializers.ValidationError({"password": "Password must be at least 8 characters long."})
            
        return attrs


class EmailVerificationSerializer(serializers.Serializer):
    """
    Serializer for email verification
    """
    token = serializers.CharField(required=True)