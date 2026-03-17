from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from django.contrib.auth.models import User
from django.utils import timezone
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.conf import settings
from django.shortcuts import render, redirect
from django.views.decorators.http import require_http_methods
from datetime import timedelta
import secrets
import random

from .serializers import (
    SignUpProfileSerializer, EmailCheckSerializer,
    PasswordValidationSerializer, RegistrationEmailSerializer,
    VerifyEmailOtpSerializer, VerifyRegistrationOtpSerializer,
    CreateProfileSerializer, UserProfileSerializer, LoginOTPRequestSerializer,
    LoginOTPVerifySerializer
)
from .models import (
    UserInfo, UserToken, OTP, TempUser,
    EmailVerificationToken, State
)


def homepage(request):
    context = {}
    if request.method == 'POST':
        context['error'] = "Use POST method at check-email endpoint"
    return render(request, 'accounts/homepage.html', context)


def get_profile_context(user):
    try:
        user_info = UserInfo.objects.get(user=user)
    except UserInfo.DoesNotExist:
        return None
    
    email_otp = OTP.objects.filter(
        user=user,
        otp_type='verification',
        verification_type='email',
        is_used=False
    ).first()
    
    mobile_otp = OTP.objects.filter(
        user=user,
        otp_type='verification',
        verification_type='mobile',
        is_used=False
    ).first()
    
    email_otp_expires_at = None
    mobile_otp_expires_at = None
    
    if email_otp and email_otp.is_valid():
        email_otp_expires_at = email_otp.expires_at.isoformat()
    
    if mobile_otp and mobile_otp.is_valid():
        mobile_otp_expires_at = mobile_otp.expires_at.isoformat()
    
    context = {
        'user_info': user_info,
        'email_verified': user_info.email_verified,
        'mobile_verified': user_info.mobile_verified,
        'email_otp_sent': email_otp is not None and email_otp.is_valid(),
        'mobile_otp_sent': mobile_otp is not None and mobile_otp.is_valid(),
        'email_otp_expires_at': email_otp_expires_at,
        'mobile_otp_expires_at': mobile_otp_expires_at,
    }
    
    return context


@require_http_methods(["GET"])
def profile(request):
    return render(request, 'accounts/profile.html')


@require_http_methods(["GET"])
def create_profile_page(request):
    token = request.GET.get('token', '')

    if not token:
        return render(request, 'accounts/homepage.html', {
            'error': 'Invalid registration link. Please request a new registration link.'
        })

    try:
        verification_token = EmailVerificationToken.objects.get(token=token)

        if verification_token.is_used:
            return render(request, 'accounts/homepage.html', {
                'error': 'This registration link has already been used. If you need help, please contact support.'
            })

        if not verification_token.is_valid():
            return render(request, 'accounts/homepage.html', {
                'error': 'Your registration link has expired (valid for 5 minutes). Please request a new registration link below.'
            })

        email = verification_token.email.lower()
        
        try:
            temp_user = TempUser.objects.get(email=email)
            
            otp = ''.join(random.choices('0123456789', k=6))
            otp_expires_at = timezone.now() + timedelta(minutes=2)
            
            OTP.objects.filter(email=email, otp_type='registration').delete()
            OTP.objects.create(
                email=email,
                otp_type='registration',
                otp=otp,
                expires_at=otp_expires_at
            )
            
            try:
                html_message = render_to_string('accounts/email_otp.html', {
                    'email': email,
                    'otp': otp,
                    'first_name': temp_user.first_name,
                    'type': 'registration'
                })
                plain_message = strip_tags(html_message)
                
                from_email = getattr(settings, 'EMAIL_HOST_USER', 'noreply@authproject.com')
                
                send_mail(
                    subject='Verify Your Email - OTP',
                    message=plain_message,
                    from_email=from_email,
                    recipient_list=[email],
                    html_message=html_message,
                    fail_silently=False,
                )
            except Exception as e:
                pass
            
            return redirect(f"/verify-email-otp/?email={email}&otp_expires_at={otp_expires_at.isoformat()}")
        
        except TempUser.DoesNotExist:
            states = State.objects.all()
            context = {
                'email': email,
                'token': token,
                'states': states
            }
            return render(request, 'accounts/create_profile.html', context)

    except EmailVerificationToken.DoesNotExist:
        return render(request, 'accounts/homepage.html', {
            'error': 'Invalid registration link. Please request a new registration link below.'
        })


@require_http_methods(["GET"])
def verify_email_otp_page(request):
    email = request.GET.get('email', '')
    otp_expires_at = request.GET.get('otp_expires_at', '')

    if not email or not otp_expires_at:
        return render(request, 'accounts/homepage.html', {
            'error': 'Invalid request. Please try again.'
        })

    context = {
        'email': email,
        'otp_expires_at': otp_expires_at
    }
    return render(request, 'accounts/verify_email_otp.html', context)



class SignupViewSet(viewsets.ViewSet):
    permission_classes = [AllowAny]

    def create(self, request):
        serializer = SignUpProfileSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            return Response(
                {
                    "message": "User registered successfully",
                    "user_id": user.id,
                    "email": user.email
                },
                status=status.HTTP_201_CREATED
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginViewSet(viewsets.ViewSet):
    permission_classes = [AllowAny]

    def create(self, request):
        serializer = LoginOTPRequestSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.validated_data['user']
            
            try:
                otp = ''.join(random.choices('0123456789', k=6))
                expires_at = timezone.now() + timedelta(minutes=2)
                
                OTP.objects.filter(
                    user=user,
                    otp_type='verification',
                    verification_type='login',
                    is_used=False
                ).delete()
                
                otp_obj = OTP.objects.create(
                    user=user,
                    otp_type='verification',
                    verification_type='login',
                    otp=otp,
                    expires_at=expires_at
                )
                
                html_message = f"""
                <div style="font-family: Arial, sans-serif; text-align: center; padding: 20px;">
                    <div style="background-color: #f5f5f5; padding: 30px; border-radius: 8px; max-width: 400px; margin: 0 auto;">
                        <h2 style="color: #333;">Login Verification</h2>
                        <p style="color: #666; font-size: 14px;">Your OTP for login is:</p>
                        <div style="background-color: #1f2937; color: #fff; padding: 15px; border-radius: 6px; font-size: 28px; font-weight: bold; letter-spacing: 5px; margin: 20px 0;">
                            {otp}
                        </div>
                        <p style="color: #999; font-size: 12px;">This code expires in 2 minutes</p>
                    </div>
                </div>
                """
                plain_message = f'Your login OTP is: {otp}. This code expires in 2 minutes.'
                
                from_email = getattr(settings, 'EMAIL_HOST_USER', 'noreply@authproject.com')
                send_mail(
                    subject='Your Login OTP',
                    message=plain_message,
                    from_email=from_email,
                    recipient_list=[user.email],
                    html_message=html_message,
                    fail_silently=False,
                )
                
                return Response(
                    {
                        'success': True,
                        'message': f'OTP has been sent to {user.email}. Please enter it to complete login.',
                        'email': user.email,
                        'otp_expires_at': expires_at.isoformat()
                    },
                    status=status.HTTP_200_OK
                )
            
            except Exception as e:
                return Response(
                    {
                        'success': False,
                        'message': 'Error sending OTP. Please try again.'
                    },
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    @action(detail=False, methods=['post'])
    def verify_otp(self, request):
        serializer = LoginOTPVerifySerializer(data=request.data)
        if serializer.is_valid():
            try:
                user = serializer.validated_data['user']
                otp_record = serializer.validated_data['otp_record']
                
                otp_record.is_used = True
                otp_record.save()
                
                from rest_framework_simplejwt.tokens import RefreshToken
                UserToken.objects.filter(user=user).delete()
                refresh = RefreshToken.for_user(user)
                
                UserToken.objects.create(
                    user=user,
                    access_token=str(refresh.access_token),
                    refresh_token=str(refresh)
                )
                
                return Response(
                    {
                        'success': True,
                        'message': 'Login successful',
                        'tokens': {
                            'access_token': str(refresh.access_token),
                            'refresh_token': str(refresh),
                            'user_id': user.id,
                            'email': user.email,
                            'first_name': user.first_name,
                            'last_name': user.last_name
                        }
                    },
                    status=status.HTTP_200_OK
                )
            
            except Exception as e:
                return Response(
                    {
                        'success': False,
                        'message': f'Error completing login: {str(e)}'
                    },
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    @action(detail=False, methods=['post'])
    def resend_otp(self, request):
        email = request.data.get('email', '').lower()
        
        if not email:
            return Response(
                {'success': False, 'message': 'Email is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            user = User.objects.get(email=email)
            
            try:
                otp = ''.join(random.choices('0123456789', k=6))
                expires_at = timezone.now() + timedelta(minutes=2)
                
                OTP.objects.filter(
                    user=user,
                    otp_type='verification',
                    verification_type='login',
                    is_used=False
                ).delete()
                
                otp_obj = OTP.objects.create(
                    user=user,
                    otp_type='verification',
                    verification_type='login',
                    otp=otp,
                    expires_at=expires_at
                )
                
                html_message = f"""
                <div style="font-family: Arial, sans-serif; text-align: center; padding: 20px;">
                    <div style="background-color: #f5f5f5; padding: 30px; border-radius: 8px; max-width: 400px; margin: 0 auto;">
                        <h2 style="color: #333;">Login Verification</h2>
                        <p style="color: #666; font-size: 14px;">Your OTP for login is:</p>
                        <div style="background-color: #1f2937; color: #fff; padding: 15px; border-radius: 6px; font-size: 28px; font-weight: bold; letter-spacing: 5px; margin: 20px 0;">
                            {otp}
                        </div>
                        <p style="color: #999; font-size: 12px;">This code expires in 2 minutes</p>
                    </div>
                </div>
                """
                plain_message = f'Your login OTP is: {otp}. This code expires in 2 minutes.'
                
                from_email = getattr(settings, 'EMAIL_HOST_USER', 'noreply@authproject.com')
                send_mail(
                    subject='Your Login OTP',
                    message=plain_message,
                    from_email=from_email,
                    recipient_list=[user.email],
                    html_message=html_message,
                    fail_silently=False,
                )
                
                return Response(
                    {
                        'success': True,
                        'message': f'New OTP has been sent to {user.email}',
                        'otp_expires_at': expires_at.isoformat()
                    },
                    status=status.HTTP_200_OK
                )
            
            except Exception as e:
                return Response(
                    {
                        'success': False,
                        'message': 'Error sending OTP. Please try again.'
                    },
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
        
        except User.DoesNotExist:
            return Response(
                {'success': False, 'message': 'User not found'},
                status=status.HTTP_404_NOT_FOUND
            )


class UserViewSet(viewsets.ViewSet):
    permission_classes = [IsAuthenticated]

    @action(detail=False, methods=['get'])
    def profile(self, request):
        try:
            user_info = UserInfo.objects.get(user=request.user)
            serializer = UserProfileSerializer(request.user)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except UserInfo.DoesNotExist:
            return Response(
                {"error": "User profile not found"},
                status=status.HTTP_404_NOT_FOUND
            )

    @action(detail=False, methods=['post'])
    def update_profile(self, request):
        try:
            from .serializers import UpdateProfileSerializer
            user_info = UserInfo.objects.get(user=request.user)
            serializer = UpdateProfileSerializer(
                data=request.data,
                context={'user_id': request.user.id}
            )
            if serializer.is_valid():
                serializer.update(request.user, serializer.validated_data)
                profile_serializer = UserProfileSerializer(request.user)
                return Response(
                    {
                        'success': True,
                        'message': 'Profile updated successfully',
                        'data': profile_serializer.data
                    },
                    status=status.HTTP_200_OK
                )
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except UserInfo.DoesNotExist:
            return Response(
                {"error": "User profile not found"},
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            return Response(
                {"error": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    @action(detail=False, methods=['post'])
    def logout(self, request):
        try:
            user_token = UserToken.objects.get(user=request.user)
            user_token.delete()
            return Response(
                {"message": "Logged out successfully"},
                status=status.HTTP_200_OK
            )
        except UserToken.DoesNotExist:
            return Response(
                {"error": "No active session found"},
                status=status.HTTP_400_BAD_REQUEST
            )


class EmailCheckViewSet(viewsets.ViewSet):
    permission_classes = [AllowAny]

    def create(self, request):
        serializer = EmailCheckSerializer(data=request.data)
        if serializer.is_valid():
            return Response({
                'exists': serializer.validated_data['exists'],
                'email': request.data.get('email')
            }, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



class PasswordValidationViewSet(viewsets.ViewSet):
    permission_classes = [AllowAny]

    def create(self, request):
        serializer = PasswordValidationSerializer(data=request.data)
        if serializer.is_valid():
            return Response({
                'valid': serializer.validated_data.get('valid'),
                'message': serializer.validated_data.get('message')
            }, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class RegistrationEmailViewSet(viewsets.ViewSet):
    permission_classes = [AllowAny]

    def create(self, request):
        serializer = RegistrationEmailSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            
            try:
                token = secrets.token_urlsafe(32)
                expires_at = timezone.now() + timedelta(minutes=5)
                
                EmailVerificationToken.objects.filter(email=email).delete()
                EmailVerificationToken.objects.create(
                    email=email,
                    token=token,
                    expires_at=expires_at
                )
                
                html_message = render_to_string('accounts/email_create_profile.html', {
                    'profile_link': f"{request.scheme}://{request.get_host()}/create-profile/?token={token}",
                    'email': email
                })
                plain_message = strip_tags(html_message)
                
                from_email = getattr(settings, 'EMAIL_HOST_USER', 'noreply@authproject.com')
                
                send_mail(
                    subject='Complete Your Registration',
                    message=plain_message,
                    from_email=from_email,
                    recipient_list=[email],
                    html_message=html_message,
                    fail_silently=False,
                )
                
                return Response({
                    'success': True,
                    'message': f'Registration link has been sent to {email}. Please check your inbox and spam folder.'
                }, status=status.HTTP_200_OK)
            
            except Exception as e:
                return Response({
                    'success': False,
                    'message': 'Error sending email. Please try again or use a different email.'
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class SendOtpViewSet(viewsets.ViewSet):
    permission_classes = [IsAuthenticated]

    @action(detail=False, methods=['post'])
    def email(self, request):
        try:
            user_info = UserInfo.objects.get(user=request.user)
            
            if user_info.email_verified:
                return Response({
                    'success': False,
                    'message': 'Email already verified'
                }, status=status.HTTP_200_OK)
            
            otp = ''.join(random.choices('0123456789', k=6))
            expires_at = timezone.now() + timedelta(minutes=2)
            
            OTP.objects.filter(
                user=request.user,
                otp_type='verification',
                verification_type='email',
                is_used=False
            ).delete()
            
            otp_obj = OTP.objects.create(
                user=request.user,
                otp_type='verification',
                verification_type='email',
                otp=otp,
                expires_at=expires_at
            )
            
            html_message = f"""
            <div style="font-family: Arial, sans-serif; text-align: center; padding: 20px;">
                <div style="background-color: #f5f5f5; padding: 30px; border-radius: 8px; max-width: 400px; margin: 0 auto;">
                    <h2 style="color: #333;">Verify Your Email</h2>
                    <p style="color: #666; font-size: 14px;">Your verification code is:</p>
                    <div style="background-color: #1f2937; color: #fff; padding: 15px; border-radius: 6px; font-size: 28px; font-weight: bold; letter-spacing: 5px; margin: 20px 0;">
                        {otp}
                    </div>
                    <p style="color: #999; font-size: 12px;">This code expires in 2 minutes</p>
                </div>
            </div>
            """
            plain_message = f'Your verification code is: {otp}. This code expires in 2 minutes.'
            
            from_email = getattr(settings, 'EMAIL_HOST_USER', 'noreply@authproject.com')
            send_mail(
                subject='Your Verification Code',
                message=plain_message,
                from_email=from_email,
                recipient_list=[request.user.email],
                html_message=html_message,
                fail_silently=False,
            )
            
            return Response({
                'success': True,
                'message': f'OTP sent to {request.user.email}',
                'expires_at': expires_at.isoformat()
            }, status=status.HTTP_200_OK)
        
        except UserInfo.DoesNotExist:
            return Response({
                'success': False,
                'message': 'User profile not found'
            }, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({
                'success': False,
                'message': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @action(detail=False, methods=['post'])
    def mobile(self, request):
        try:
            user_info = UserInfo.objects.get(user=request.user)
            
            if user_info.mobile_verified:
                return Response({
                    'success': False,
                    'message': 'Mobile already verified'
                }, status=status.HTTP_200_OK)
            
            if not user_info.mobile:
                return Response({
                    'success': False,
                    'message': 'Mobile number not found in profile'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            otp = ''.join(random.choices('0123456789', k=6))
            expires_at = timezone.now() + timedelta(minutes=2)
            
            OTP.objects.filter(
                user=request.user,
                otp_type='verification',
                verification_type='mobile',
                is_used=False
            ).delete()
            
            OTP.objects.create(
                user=request.user,
                otp_type='verification',
                verification_type='mobile',
                otp=otp,
                expires_at=expires_at
            )
            
            try:
                from twilio.rest import Client
                account_sid = getattr(settings, 'TWILIO_ACCOUNT_SID', None)
                auth_token = getattr(settings, 'TWILIO_AUTH_TOKEN', None)
                twilio_number = getattr(settings, 'TWILIO_PHONE_NUMBER', None)
                
                if all([account_sid, auth_token, twilio_number]):
                    if not account_sid.startswith('your_twilio') and not auth_token.startswith('your_twilio'):
                        client = Client(account_sid, auth_token)
                        mobile_number = user_info.mobile
                        if not mobile_number.startswith('+'):
                            mobile_number = '+91' + mobile_number
                        
                        client.messages.create(
                            body=f'Your OTP for email and mobile verification is: {otp}. This code expires in 2 minutes.',
                            from_=twilio_number,
                            to=mobile_number
                        )
            except:
                pass  
            
            return Response({
                'success': True,
                'message': f'OTP sent to {user_info.mobile}',
                'expires_at': expires_at.isoformat()
            }, status=status.HTTP_200_OK)
        
        except UserInfo.DoesNotExist:
            return Response({
                'success': False,
                'message': 'User profile not found'
            }, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({
                'success': False,
                'message': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class VerifyOtpViewSet(viewsets.ViewSet):
    permission_classes = [IsAuthenticated]

    def create(self, request):
        serializer = VerifyEmailOtpSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            verification_type = serializer.validated_data.get('verification_type')
            otp = serializer.validated_data.get('otp')
            
            try:
                otp_record = OTP.objects.filter(
                    user=request.user,
                    otp_type='verification',
                    verification_type=verification_type,
                    is_used=False
                ).first()
                
                if not otp_record:
                    return Response({
                        'success': False,
                        'message': 'No OTP request found. Please generate OTP first.'
                    }, status=status.HTTP_200_OK)
                
                if not (timezone.now() < otp_record.expires_at):
                    return Response({
                        'success': False,
                        'message': 'OTP has expired'
                    }, status=status.HTTP_200_OK)
                
                if otp_record.otp != otp:
                    return Response({
                        'success': False,
                        'message': 'Invalid OTP'
                    }, status=status.HTTP_200_OK)
                
                otp_record.is_used = True
                otp_record.save()
                
                user_info = UserInfo.objects.get(user=request.user)
                if verification_type == 'email':
                    user_info.email_verified = True
                else:
                    user_info.mobile_verified = True
                user_info.save()
                
                return Response({
                    'success': True,
                    'message': f'{verification_type.capitalize()} verified successfully!'
                }, status=status.HTTP_200_OK)
            
            except UserInfo.DoesNotExist:
                return Response({
                    'success': False,
                    'message': 'User profile not found'
                }, status=status.HTTP_404_NOT_FOUND)
            except Exception as e:
                return Response({
                    'success': False,
                    'message': str(e)
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class RegistrationViewSet(viewsets.ViewSet):
    permission_classes = [AllowAny]

    @action(detail=False, methods=['get'])
    def get_states(self, request):
        states = State.objects.all().values('id', 'name')
        return Response({
            'success': True,
            'states': list(states)
        }, status=status.HTTP_200_OK)

    @action(detail=False, methods=['post'])
    def create_profile(self, request):
        serializer = CreateProfileSerializer(data=request.data)
        if serializer.is_valid():
            try:
                email = serializer.validated_data['email'].lower()
                verification_token = serializer.validated_data['verification_token']
                password = serializer.validated_data['password']

                state = serializer.validated_data.get('state')

                from django.contrib.auth.hashers import make_password
                
                temp_user, created = TempUser.objects.update_or_create(
                    email=email,
                    defaults={
                        'first_name': serializer.validated_data['first_name'],
                        'last_name': serializer.validated_data['last_name'],
                        'mobile': serializer.validated_data['mobile'],
                        'company': serializer.validated_data['company'],
                        'job_profile': serializer.validated_data['job_profile'],
                        'state': state,
                        'city': serializer.validated_data.get('city', ''),
                        'password': make_password(password),
                        'email_verified': False
                    }
                )
                
                verification_token.is_used = True
                verification_token.save()
                
                otp = ''.join(random.choices('0123456789', k=6))
                otp_expires_at = timezone.now() + timedelta(minutes=2)

                email_lower = email.lower()
                OTP.objects.filter(email=email_lower, otp_type='registration').delete()
                OTP.objects.create(
                    email=email_lower,
                    otp_type='registration',
                    otp=otp,
                    expires_at=otp_expires_at
                )
                
                try:
                    html_message = render_to_string('accounts/email_otp.html', {
                        'email': email,
                        'otp': otp,
                        'first_name': serializer.validated_data['first_name'],
                        'type': 'registration'
                    })
                    plain_message = strip_tags(html_message)
                    
                    from_email = getattr(settings, 'EMAIL_HOST_USER', 'noreply@authproject.com')
                    
                    send_mail(
                        subject='Verify Your Email - OTP',
                        message=plain_message,
                        from_email=from_email,
                        recipient_list=[email],
                        html_message=html_message,
                        fail_silently=False,
                    )
                except Exception as e:
                    return Response({
                        'success': False,
                        'message': 'Error sending OTP. Please try again.'
                    }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                
                return Response({
                    'success': True,
                    'message': 'Profile created successfully. Please verify your email with the OTP sent.',
                    'email': email,
                    'otp_expires_at': otp_expires_at.isoformat()
                }, status=status.HTTP_201_CREATED)
            
            except Exception as e:
                return Response({
                    'success': False,
                    'message': f'Error creating profile: {str(e)}'
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=False, methods=['post'])
    def verify_registration_otp(self, request):
        serializer = VerifyRegistrationOtpSerializer(data=request.data)
        if serializer.is_valid():
            try:
                email = serializer.validated_data['email'].lower()
                temp_user = TempUser.objects.get(email=email)
                otp_record = serializer.validated_data['otp_record']
                
                otp_record.is_used = True
                otp_record.save()
                
                user = User.objects.create(
                    username=email,
                    email=email,
                    first_name=temp_user.first_name,
                    last_name=temp_user.last_name,
                    password=temp_user.password 
                )
                
                UserInfo.objects.create(
                    user=user,
                    mobile=temp_user.mobile,
                    state=temp_user.state,
                    city=temp_user.city,
                    company=temp_user.company,
                    job_profile=temp_user.job_profile,
                    email_verified=True
                )
                
                from rest_framework_simplejwt.tokens import RefreshToken
                refresh = RefreshToken.for_user(user)
                
                UserToken.objects.create(
                    user=user,
                    access_token=str(refresh.access_token),
                    refresh_token=str(refresh)
                )
                
                temp_user.delete()
                
                return Response({
                    'success': True,
                    'message': 'Email verified successfully! Your account has been created.',
                    'tokens': {
                        'access_token': str(refresh.access_token),
                        'refresh_token': str(refresh),
                        'user_id': user.id,
                        'email': user.email,
                        'first_name': user.first_name,
                        'last_name': user.last_name
                    }
                }, status=status.HTTP_201_CREATED)
            
            except Exception as e:
                return Response({
                    'success': False,
                    'message': f'Error creating account: {str(e)}'
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=False, methods=['post'])
    def resend_registration_otp(self, request):
        email = request.data.get('email', '').lower()

        if not email:
            return Response({
                'success': False,
                'message': 'Email is required'
            }, status=status.HTTP_400_BAD_REQUEST)

        try:
            temp_user = TempUser.objects.get(email=email)

            otp = ''.join(random.choices('0123456789', k=6))
            otp_expires_at = timezone.now() + timedelta(minutes=2)

            OTP.objects.filter(email=email, otp_type='registration').delete()
            OTP.objects.create(
                email=email,
                otp_type='registration',
                otp=otp,
                expires_at=otp_expires_at
            )

            try:
                html_message = render_to_string('accounts/email_otp.html', {
                    'email': email,
                    'otp': otp,
                    'first_name': temp_user.first_name,
                    'type': 'registration'
                })
                plain_message = strip_tags(html_message)

                from_email = getattr(settings, 'EMAIL_HOST_USER', 'noreply@authproject.com')

                send_mail(
                    subject='Verify Your Email - OTP',
                    message=plain_message,
                    from_email=from_email,
                    recipient_list=[email],
                    html_message=html_message,
                    fail_silently=False,
                )
            except Exception as e:
                return Response({
                    'success': False,
                    'message': 'Error sending OTP. Please try again.'
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            return Response({
                'success': True,
                'message': 'OTP has been resent successfully',
                'otp_expires_at': otp_expires_at.isoformat()
            }, status=status.HTTP_200_OK)

        except TempUser.DoesNotExist:
            return Response({
                'success': False,
                'message': 'Registration data not found. Please register again.'
            }, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({
                'success': False,
                'message': f'Error resending OTP: {str(e)}'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)