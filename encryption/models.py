"""
Database models for the Cloud Data Encryption System.
"""
from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone


class UserProfile(models.Model):
    """Extended user profile with encryption keys."""
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    public_key = models.TextField(blank=True, null=True)
    private_key_encrypted = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(default=timezone.now)
    last_login = models.DateTimeField(blank=True, null=True)

    def __str__(self):
        return f"Profile: {self.user.username}"


class EncryptedFile(models.Model):
    """Model for storing encrypted files."""
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='files')
    file_name = models.CharField(max_length=255)
    original_name = models.CharField(max_length=255)
    file_size = models.BigIntegerField(default=0)
    encrypted_file = models.FileField(upload_to='encrypted_files/')
    encrypted_aes_key = models.TextField()
    iv = models.CharField(max_length=64)  # IV for AES-CBC
    upload_date = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ['-upload_date']

    def __str__(self):
        return f"{self.original_name} ({self.user.username})"

    def get_file_size_display(self):
        """Convert file size to human readable format."""
        size = self.file_size
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024.0:
                return f"{size:.2f} {unit}"
            size /= 1024.0
        return f"{size:.2f} PB"

