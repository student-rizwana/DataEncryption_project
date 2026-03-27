"""
Django admin configuration for encryption models.
"""
from django.contrib import admin
from .models import UserProfile, EncryptedFile


@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    list_display = ['user', 'created_at', 'last_login']
    search_fields = ['user__username', 'user__email']
    readonly_fields = ['created_at']


@admin.register(EncryptedFile)
class EncryptedFileAdmin(admin.ModelAdmin):
    list_display = ['original_name', 'user', 'file_size', 'upload_date']
    list_filter = ['upload_date', 'user']
    search_fields = ['original_name', 'file_name', 'user__username']
    readonly_fields = ['upload_date']

