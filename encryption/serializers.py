"""
REST API serializers for the encryption app.
"""
from rest_framework import serializers
from django.contrib.auth.models import User
from .models import UserProfile, EncryptedFile


class UserSerializer(serializers.ModelSerializer):
    """Serializer for User model."""
    
    class Meta:
        model = User
        fields = ['id', 'username', 'email']


class UserProfileSerializer(serializers.ModelSerializer):
    """Serializer for UserProfile model."""
    user = UserSerializer(read_only=True)
    
    class Meta:
        model = UserProfile
        fields = ['user', 'public_key', 'created_at', 'last_login']


class RegisterSerializer(serializers.ModelSerializer):
    """Serializer for user registration."""
    password = serializers.CharField(write_only=True, min_length=8)
    password_confirm = serializers.CharField(write_only=True)
    public_key = serializers.CharField(write_only=True, required=False)
    
    class Meta:
        model = User
        fields = ['username', 'email', 'password', 'password_confirm', 'public_key']
    
    def validate(self, data):
        if data['password'] != data['password_confirm']:
            raise serializers.ValidationError("Passwords do not match")
        return data
    
    def create(self, validated_data):
        validated_data.pop('password_confirm', None)
        public_key = validated_data.pop('public_key', None)
        
        user = User.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
            password=validated_data['password']
        )
        
        # Create user profile with public key
        UserProfile.objects.create(
            user=user,
            public_key=public_key
        )
        
        return user


class FileUploadSerializer(serializers.Serializer):
    """Serializer for file upload."""
    file = serializers.FileField()
    file_name = serializers.CharField()
    encrypted_aes_key = serializers.CharField()
    iv = serializers.CharField()
    
    class Meta:
        fields = ['file', 'file_name', 'encrypted_aes_key', 'iv']


class EncryptedFileSerializer(serializers.ModelSerializer):
    """Serializer for EncryptedFile model."""
    user = UserSerializer(read_only=True)
    file_size_display = serializers.SerializerMethodField()
    
    class Meta:
        model = EncryptedFile
        fields = [
            'id', 'user', 'file_name', 'original_name', 
            'file_size', 'file_size_display', 'upload_date',
            'encrypted_aes_key', 'iv'
        ]
    
    def get_file_size_display(self, obj):
        return obj.get_file_size_display()


class FileDownloadSerializer(serializers.Serializer):
    """Serializer for file download response."""
    file_data = serializers.CharField()
    file_name = serializers.CharField()
    encrypted_aes_key = serializers.CharField()
    iv = serializers.CharField()

