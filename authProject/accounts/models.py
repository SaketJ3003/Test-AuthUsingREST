from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from datetime import timedelta


class UserToken(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='active_token')
    access_token = models.TextField()
    refresh_token = models.TextField()
    created_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"Token for {self.user.username}"
    
    
class State(models.Model):
    name = models.CharField(max_length=50, unique=True)
    
    def __str__(self):
        return self.name
    
    class Meta:
        ordering = ['name']


class UserInfo(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='info')
    mobile = models.CharField(max_length=10, unique=True, blank=True)
    state = models.ForeignKey(State, on_delete=models.SET_NULL, null=True, blank=True, related_name='users')
    city = models.CharField(max_length=50, blank=True)
    company = models.CharField(max_length=100)
    job_profile = models.CharField(max_length=100)
    email_verified = models.BooleanField(default=False)
    mobile_verified = models.BooleanField(default=False)
    isActive = models.BooleanField(default=True)
    createdAt = models.DateTimeField(auto_now_add=True, null=True, blank=True)
    updatedAt = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"{self.user.email}"


class TempUser(models.Model):
    first_name = models.CharField(max_length=30)
    last_name = models.CharField(max_length=30)
    email = models.EmailField(unique=True)
    mobile = models.CharField(max_length=10)
    company = models.CharField(max_length=100)
    job_profile = models.CharField(max_length=100)
    state = models.ForeignKey(State, on_delete=models.SET_NULL, null=True, blank=True, related_name='temp_users')
    city = models.CharField(max_length=50, blank=True)
    password = models.CharField(max_length=255, default='')
    email_verified = models.BooleanField(default=False)
    createdAt = models.DateTimeField(auto_now_add=True)
    updatedAt = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"{self.email}"
    
    class Meta:
        ordering = ['-createdAt']


class TempOtp(models.Model):
    email = models.EmailField()
    otp = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    is_used = models.BooleanField(default=False)
    
    def __str__(self):
        return f"OTP for {self.email}"
    
    class Meta:
        ordering = ['-created_at']


class VerificationOtp(models.Model):
    VERIFICATION_TYPE_CHOICES = [
        ('email', 'Email'),
        ('mobile', 'Mobile'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='verification_otps')
    verification_type = models.CharField(max_length=10, choices=VERIFICATION_TYPE_CHOICES)
    otp = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    is_used = models.BooleanField(default=False)
    
    def __str__(self):
        return f"OTP for {self.user.email} ({self.verification_type})"
    
    def is_valid(self):
        return not self.is_used and timezone.now() < self.expires_at
    
    class Meta:
        ordering = ['-created_at']


class EmailVerificationToken(models.Model):
    email = models.EmailField(unique=True)
    token = models.CharField(max_length=255, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    is_used = models.BooleanField(default=False)
    
    def __str__(self):
        return f"Verification token for {self.email}"
    
    def is_valid(self):
        return not self.is_used and timezone.now() < self.expires_at
    
    class Meta:
        ordering = ['-created_at']
