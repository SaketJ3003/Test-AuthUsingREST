"""
URL configuration for authProject project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/6.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from accounts.views import (
    SignupViewSet, LoginViewSet, UserViewSet, EmailCheckViewSet,
    PasswordValidationViewSet, RegistrationEmailViewSet, SendOtpViewSet,
    VerifyOtpViewSet, RegistrationViewSet, homepage, create_profile_page, profile,
    verify_email_otp_page
)

router = DefaultRouter()
router.register(r'signup', SignupViewSet, basename='api-signup')
router.register(r'login', LoginViewSet, basename='api-login')
router.register(r'users', UserViewSet, basename='api-users')

router.register(r'email-check', EmailCheckViewSet, basename='api-email-check')
router.register(r'password-validate', PasswordValidationViewSet, basename='api-password-validate')
router.register(r'send-registration-email', RegistrationEmailViewSet, basename='api-send-registration-email')
router.register(r'send-otp', SendOtpViewSet, basename='api-send-otp')
router.register(r'verify-otp', VerifyOtpViewSet, basename='api-verify-otp')
router.register(r'registration', RegistrationViewSet, basename='api-registration')

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/', include(router.urls)),

    path('', homepage, name='homepage'),
    path('create-profile/', create_profile_page, name='create-profile'),
    path('verify-email-otp/', verify_email_otp_page, name='verify-email-otp'),
    path('profile/', profile, name='profile'),
]
