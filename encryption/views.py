"""
Django views for the Cloud Data Encryption System.
"""
import os
import json
import base64
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.contrib import messages
from django.http import JsonResponse, HttpResponse, FileResponse
from django.views.decorators.csrf import csrf_exempt
from django.utils import timezone
from django.conf import settings

from .models import UserProfile, EncryptedFile
from .encryption_utils import encryption_manager
from .serializers import (
    RegisterSerializer, EncryptedFileSerializer, 
    FileDownloadSerializer
)


def index(request):
    """Home page view."""
    if request.user.is_authenticated:
        return redirect('dashboard')
    return render(request, 'index.html')


def register(request):
    """User registration view."""
    if request.user.is_authenticated:
        return redirect('dashboard')
    
    if request.method == 'POST':
        username = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password')
        password_confirm = request.POST.get('password_confirm')
        public_key = request.POST.get('public_key')
        
        # Validation
        if password != password_confirm:
            messages.error(request, "Passwords do not match!")
            return render(request, 'register.html')
        
        if User.objects.filter(username=username).exists():
            messages.error(request, "Username already exists!")
            return render(request, 'register.html')
        
        if User.objects.filter(email=email).exists():
            messages.error(request, "Email already exists!")
            return render(request, 'register.html')
        
        if len(password) < 8:
            messages.error(request, "Password must be at least 8 characters!")
            return render(request, 'register.html')
        
        # Create user
        user = User.objects.create_user(
            username=username,
            email=email,
            password=password
        )
        
        # Create user profile with public key
        UserProfile.objects.create(
            user=user,
            public_key=public_key
        )
        
        messages.success(request, "Registration successful! Please login.")
        return redirect('login')
    
    return render(request, 'register.html')


def user_login(request):
    """User login view."""
    if request.user.is_authenticated:
        return redirect('dashboard')
    
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        
        user = authenticate(request, username=username, password=password)
        
        if user is not None:
            login(request, user)
            
            # Update last login
            try:
                profile = user.profile
                profile.last_login = timezone.now()
                profile.save()
            except UserProfile.DoesNotExist:
                pass
            
            messages.success(request, f"Welcome back, {user.username}!")
            return redirect('dashboard')
        else:
            messages.error(request, "Invalid username or password!")
    
    return render(request, 'login.html')


def user_logout(request):
    """User logout view."""
    logout(request)
    messages.success(request, "You have been logged out successfully!")
    return redirect('index')


@login_required
def dashboard(request):
    """User dashboard view."""
    user_files = EncryptedFile.objects.filter(user=request.user)
    
    total_files = user_files.count()
    total_size = sum(f.file_size for f in user_files)
    
    # Convert to human readable format
    if total_size < 1024:
        storage_used = f"{total_size} B"
    elif total_size < 1024 * 1024:
        storage_used = f"{total_size / 1024:.2f} KB"
    elif total_size < 1024 * 1024 * 1024:
        storage_used = f"{total_size / (1024 * 1024):.2f} MB"
    else:
        storage_used = f"{total_size / (1024 * 1024 * 1024):.2f} GB"
    
    # Get user's public key
    try:
        profile = request.user.profile
        has_keys = bool(profile.public_key)
    except UserProfile.DoesNotExist:
        has_keys = False
        # Create profile if doesn't exist
        profile = UserProfile.objects.create(user=request.user)
    
    context = {
        'total_files': total_files,
        'storage_used': storage_used,
        'recent_files': user_files[:5],
        'has_keys': has_keys,
    }
    
    return render(request, 'dashboard.html', context)


@login_required
def upload_file(request):
    """File upload view with client-side encryption."""
    if request.method == 'POST':
        try:
            # Get the encrypted data from request
            file_data = request.POST.get('file_data')
            file_name = request.POST.get('file_name')
            original_name = request.POST.get('original_name')
            encrypted_aes_key = request.POST.get('encrypted_aes_key')
            iv = request.POST.get('iv')
            
            if not all([file_data, file_name, encrypted_aes_key, iv]):
                return JsonResponse({'error': 'Missing required fields'}, status=400)
            
            # Decode base64 file data
            decoded_file_data = base64.b64decode(file_data)
            
            # Save encrypted file
            file_path = os.path.join(settings.MEDIA_ROOT, 'encrypted_files', file_name)
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            
            with open(file_path, 'wb') as f:
                f.write(decoded_file_data)
            
            # Create database record
            encrypted_file = EncryptedFile.objects.create(
                user=request.user,
                file_name=file_name,
                original_name=original_name,
                file_size=len(decoded_file_data),
                encrypted_file=f'encrypted_files/{file_name}',
                encrypted_aes_key=encrypted_aes_key,
                iv=iv
            )
            
            return JsonResponse({
                'success': True,
                'message': 'File uploaded successfully!',
                'file_id': encrypted_file.id
            })
            
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    
    # Get user's public key for client-side encryption
    try:
        profile = request.user.profile
        public_key = profile.public_key
        if not public_key:
            # Generate RSA key pair
            private_key, public_key = encryption_manager.generate_rsa_keypair()
            private_key_pem = encryption_manager.rsa_private_key_to_pem(private_key)
            public_key_pem_bytes = encryption_manager.rsa_public_key_to_pem(public_key)
            
            # Store keys (in production, encrypt private key with user's password)
            profile.public_key = public_key_pem_bytes.decode('utf-8')
            profile.private_key_encrypted = base64.b64encode(private_key_pem).decode('utf-8')
            profile.save()
            public_key = public_key_pem_bytes.decode('utf-8')
    except UserProfile.DoesNotExist:
        profile = UserProfile.objects.create(user=request.user)
        private_key, public_key = encryption_manager.generate_rsa_keypair()
        private_key_pem = encryption_manager.rsa_private_key_to_pem(private_key)
        public_key_pem_bytes = encryption_manager.rsa_public_key_to_pem(public_key)
        
        profile.public_key = public_key_pem_bytes.decode('utf-8')
        profile.private_key_encrypted = base64.b64encode(private_key_pem).decode('utf-8')
        profile.save()
        public_key = public_key_pem_bytes.decode('utf-8')
    
    # Format public key for JavaScript (replace newlines)
    public_key_formatted = public_key.replace('\n', '\\n')
    
    return render(request, 'upload.html', {'public_key': public_key_formatted})


@login_required
def files_list(request):
    """View to list all user's encrypted files."""
    user_files = EncryptedFile.objects.filter(user=request.user)
    
    return render(request, 'files.html', {'files': user_files})


@login_required
def download_file(request, file_id):
    """View to download and decrypt a file."""
    try:
        encrypted_file = EncryptedFile.objects.get(id=file_id, user=request.user)
    except EncryptedFile.DoesNotExist:
        messages.error(request, "File not found!")
        return redirect('files')
    
    # Get user's private key
    try:
        profile = request.user.profile
        if not profile.private_key_encrypted:
            messages.error(request, "No private key found! Please regenerate keys.")
            return redirect('files')
        
        private_key_pem = base64.b64decode(profile.private_key_encrypted).decode('utf-8')
    except Exception as e:
        messages.error(request, f"Error retrieving private key: {str(e)}")
        return redirect('files')
    
    if request.method == 'POST':
        try:
            # Read encrypted file
            file_path = os.path.join(settings.MEDIA_ROOT, encrypted_file.encrypted_file.path)
            # Server-side decrypt for FileResponse (Option 2 - no client JS)
            with open(file_path, 'rb') as f:
                encrypted_data_bytes = f.read()
            
            aes_key = encryption_manager.decrypt_aes_key(encrypted_file.encrypted_aes_key, private_key_pem)
            iv = base64.b64decode(encrypted_file.iv)
            decrypted_data = encryption_manager.decrypt_aes(encrypted_data_bytes, aes_key, iv)
            
            # Return decrypted data
            return JsonResponse({
                'file_data': encrypted_data,
                'file_name': encrypted_file.original_name,
                'encrypted_aes_key': encrypted_file.encrypted_aes_key,
                'iv': encrypted_file.iv,
                'private_key': private_key_pem.replace('\n', '\\n')
            })
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    
    return render(request, 'download.html', {
        'file': encrypted_file,
        'private_key': private_key_pem.replace('\n', '\\n')
    })


@login_required
def delete_file(request, file_id):
    """View to delete an encrypted file."""
    try:
        encrypted_file = EncryptedFile.objects.get(id=file_id, user=request.user)
        
        # Delete physical file
        if encrypted_file.encrypted_file:
            file_path = os.path.join(settings.MEDIA_ROOT, encrypted_file.encrypted_file.path)
            if os.path.exists(file_path):
                os.remove(file_path)
        
        # Delete database record
        encrypted_file.delete()
        
        messages.success(request, "File deleted successfully!")
    except EncryptedFile.DoesNotExist:
        messages.error(request, "File not found!")
    
    return redirect('files')


# API Views
@csrf_exempt
def api_register(request):
    """API endpoint for user registration."""
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    try:
        data = json.loads(request.body)
        serializer = RegisterSerializer(data=data)
        
        if serializer.is_valid():
            user = serializer.save()
            return JsonResponse({
                'success': True,
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email
                }
            }, status=201)
        return JsonResponse({'error': serializer.errors}, status=400)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@csrf_exempt
def api_login(request):
    """API endpoint for user login."""
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    try:
        data = json.loads(request.body)
        username = data.get('username')
        password = data.get('password')
        
        user = authenticate(request, username=username, password=password)
        
        if user is not None:
            login(request, user)
            return JsonResponse({
                'success': True,
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email
                }
            })
        return JsonResponse({'error': 'Invalid credentials'}, status=401)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@login_required
def api_files(request):
    """API endpoint to list user's files."""
    if request.method == 'GET':
        files = EncryptedFile.objects.filter(user=request.user)
        serializer = EncryptedFileSerializer(files, many=True)
        return JsonResponse({'files': serializer.data}, safe=False)
    return JsonResponse({'error': 'Method not allowed'}, status=405)


@csrf_exempt
def api_generate_keys(request):
    """API endpoint to generate RSA key pair for a user."""
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    if not request.user.is_authenticated:
        return JsonResponse({'error': 'Authentication required'}, status=401)
    
    try:
        # Generate RSA key pair
        private_key, public_key = encryption_manager.generate_rsa_keypair()
        
        # Convert to PEM format
        private_key_pem = encryption_manager.rsa_private_key_to_pem(private_key)
        public_key_pem_bytes = encryption_manager.rsa_public_key_to_pem(public_key)
        public_key = public_key_pem_bytes.decode('utf-8')
        
        # Get or create user profile
        profile, created = UserProfile.objects.get_or_create(user=request.user)
        
        # Store keys (in production, encrypt private key with user's password)
        profile.public_key = public_key
        profile.private_key_encrypted = base64.b64encode(private_key_pem).decode('utf-8')
        profile.save()
        
        return JsonResponse({
            'success': True,
            'public_key': public_key.replace('\n', '\\n')
        })
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

