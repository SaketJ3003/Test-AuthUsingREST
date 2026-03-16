from rest_framework import serializers
from django.contrib.auth.models import User
from .models import UserInfo, UserToken, OTP, TempUser, State
from rest_framework_simplejwt.tokens import RefreshToken
from django.utils import timezone
import re


class SignUpProfileSerializer(serializers.ModelSerializer):
    first_name = serializers.CharField(max_length=15, required=True)
    last_name = serializers.CharField(max_length=15, required=True)
    password = serializers.CharField(write_only=True, min_length=8)
    confirm_password = serializers.CharField(write_only=True, min_length=8)
    mobile_number = serializers.CharField(source='info.mobile', max_length=10, required=False, allow_blank=True)
    company = serializers.CharField(source='info.company', max_length=50)
    job_profile = serializers.CharField(source='info.job_profile', max_length=30)
    email = serializers.EmailField(read_only=True)

    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'email', 'mobile_number', 'company', 'job_profile', 'password', 'confirm_password']

    def validate_mobile_number(self, value):

        if value and value.strip():
            if not re.match(r'^[6-9]\d{9}$', value):
                raise serializers.ValidationError(
                    "Mobile number must be 10 digits starting with 6, 7, 8, or 9."
                )
        return value

    def validate(self, data):
        if data['password'] != data['confirm_password']:
            raise serializers.ValidationError({"confirm_password": "Passwords do not match."})
        return data

    def create(self, validated_data):
        validated_data.pop('confirm_password')
        
        info_data = validated_data.pop('info', {})
        
        # Create User
        user = User.objects.create_user(
            username=validated_data['email'],
            email=validated_data['email'],
            first_name=validated_data.get('first_name', ''),
            last_name=validated_data.get('last_name', ''),
            password=validated_data['password']
        )
        
        # Create UserInfo
        UserInfo.objects.create(
            user=user,
            mobile=info_data.get('mobile', ''),
            company=info_data.get('company', ''),
            job_profile=info_data.get('job_profile', '')
        )
        
        return user


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        email = data.get('email')
        password = data.get('password')

        if not email or not password:
            raise serializers.ValidationError("Email and password are required.")

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            raise serializers.ValidationError("Invalid email or password.")

        if not user.check_password(password):
            raise serializers.ValidationError("Invalid email or password.")

        data['user'] = user
        return data

    def get_tokens(self, user):
        UserToken.objects.filter(user=user).delete()
        
        refresh = RefreshToken.for_user(user)
        
        UserToken.objects.create(
            user=user,
            access_token=str(refresh.access_token),
            refresh_token=str(refresh)
        )
        
        return {
            'access_token': str(refresh.access_token),
            'refresh_token': str(refresh),
            'user_id': user.id,
            'email': user.email,
            'first_name': user.first_name,
            'last_name': user.last_name
        }

    def create(self, validated_data):
        user = validated_data['user']
        return self.get_tokens(user)


class EmailCheckSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate(self, data):
        email = data.get('email')
        user_exists = User.objects.filter(email=email).exists()
        data['exists'] = user_exists
        return data


class PasswordValidationSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        email = data.get('email')
        password = data.get('password')

        try:
            user = User.objects.get(email=email)
            if user.check_password(password):
                data['valid'] = True
                data['message'] = 'Password is correct'
            else:
                data['valid'] = False
                data['message'] = 'Incorrect password'
        except User.DoesNotExist:
            data['valid'] = False
            data['message'] = 'Email not found'
        
        return data


class RegistrationEmailSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("This email is already registered. Please login instead.")
        return value


class OTPSerializer(serializers.Serializer):
    otp = serializers.CharField(max_length=6, min_length=6)
    verification_type = serializers.ChoiceField(choices=['email', 'mobile'])
    expires_at = serializers.DateTimeField(read_only=True)


class VerifyEmailOtpSerializer(serializers.Serializer):
    otp = serializers.CharField(max_length=6, min_length=6)
    verification_type = serializers.ChoiceField(choices=['email', 'mobile'])

    def validate(self, data):
        otp = data.get('otp')
        verification_type = data.get('verification_type')
        
        data['user'] = self.context.get('request').user if 'request' in self.context else None
        return data


class LoginOTPRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        email = data.get('email')
        password = data.get('password')

        if not email or not password:
            raise serializers.ValidationError("Email and password are required.")

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            raise serializers.ValidationError("Invalid email or password.")

        if not user.check_password(password):
            raise serializers.ValidationError("Invalid email or password.")

        data['user'] = user
        return data


class LoginOTPVerifySerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField(max_length=6, min_length=6)

    def validate(self, data):
        from .models import OTP
        email = data.get('email').lower()
        otp = data.get('otp')

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            raise serializers.ValidationError({"email": "Email not found."})

        otp_record = OTP.objects.filter(
            user=user,
            otp_type='verification',
            verification_type='login',
            is_used=False
        ).first()

        if not otp_record:
            raise serializers.ValidationError({"otp": "No OTP found. Please request a new OTP."})

        if not (timezone.now() < otp_record.expires_at):
            raise serializers.ValidationError({"otp": "OTP has expired. Please request a new one."})

        if otp_record.otp != otp:
            raise serializers.ValidationError({"otp": "Invalid OTP"})

        data['user'] = user
        data['otp_record'] = otp_record
        return data


class VerifyRegistrationOtpSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField(max_length=6, min_length=6)

    def validate_email(self, value):
        try:
            TempUser.objects.get(email=value.lower())
            return value
        except TempUser.DoesNotExist:
            raise serializers.ValidationError("Registration data not found. Please register again.")

    def validate(self, data):
        from .models import OTP
        email = data.get('email').lower()
        otp = data.get('otp')

        otp_record = OTP.objects.filter(
            email=email,
            otp_type='registration',
            is_used=False
        ).first()

        if not otp_record:
            raise serializers.ValidationError({'otp': 'No OTP found. Please request a new OTP.'})

        if not timezone.now() < otp_record.expires_at:
            raise serializers.ValidationError({'otp': 'OTP has expired. Please request a new one.'})

        if otp_record.otp != otp:
            raise serializers.ValidationError({'otp': 'Invalid OTP'})

        data['otp_record'] = otp_record
        return data


class CreateProfileSerializer(serializers.Serializer):
    first_name = serializers.CharField(max_length=15)
    last_name = serializers.CharField(max_length=15)
    mobile = serializers.CharField(max_length=10)
    company = serializers.CharField(max_length=50)
    job_profile = serializers.CharField(max_length=30)
    state = serializers.PrimaryKeyRelatedField(queryset=State.objects.all(), required=False, allow_null=True)
    city = serializers.CharField(max_length=20, required=False, allow_blank=True)
    password = serializers.CharField(write_only=True, min_length=8)
    confirm_password = serializers.CharField(write_only=True, min_length=8)
    token = serializers.CharField(write_only=True)

    def validate_mobile(self, value):
        if not re.match(r'^[6-9]\d{9}$', value):
            raise serializers.ValidationError("Mobile number must be 10 digits starting with 6, 7, 8, or 9.")
        return value

    def validate(self, data):
        if data['password'] != data['confirm_password']:
            raise serializers.ValidationError({"confirm_password": "Passwords do not match."})
        
        from .models import EmailVerificationToken
        token = data.get('token')
        
        try:
            verification_token = EmailVerificationToken.objects.get(token=token)
            if not verification_token.is_valid():
                raise serializers.ValidationError("Registration link has expired. Please start over.")
            data['verification_token'] = verification_token
            data['email'] = verification_token.email
        except EmailVerificationToken.DoesNotExist:
            raise serializers.ValidationError("Invalid registration link")
        
        return data


class UserProfileSerializer(serializers.ModelSerializer):
    mobile = serializers.CharField(source='info.mobile')
    company = serializers.CharField(source='info.company')
    job_profile = serializers.CharField(source='info.job_profile')
    state = serializers.CharField(source='info.state.name', allow_null=True)
    city = serializers.CharField(source='info.city')
    profile_image = serializers.SerializerMethodField()
    is_active = serializers.BooleanField(source='info.isActive')
    email_verified = serializers.BooleanField(source='info.email_verified')
    mobile_verified = serializers.BooleanField(source='info.mobile_verified')
    created_at = serializers.DateTimeField(source='info.createdAt')
    updated_at = serializers.DateTimeField(source='info.updatedAt')

    def get_profile_image(self, obj):
        if obj.info.profile_image:
            request = self.context.get('request')
            if request:
                return request.build_absolute_uri(obj.info.profile_image.url)
            return obj.info.profile_image.url
        return None

    class Meta:
        model = User
        fields = [
            'id', 'email', 'first_name', 'last_name', 'mobile', 'company',
            'job_profile', 'state', 'city', 'profile_image', 'is_active', 'email_verified',
            'mobile_verified', 'created_at', 'updated_at'
        ]


class UpdateProfileSerializer(serializers.Serializer):
    first_name = serializers.CharField(max_length=30, required=False, allow_blank=True)
    last_name = serializers.CharField(max_length=30, required=False, allow_blank=True)
    mobile = serializers.CharField(max_length=10, required=False, allow_blank=True)
    company = serializers.CharField(max_length=100, required=False, allow_blank=True)
    job_profile = serializers.CharField(max_length=100, required=False, allow_blank=True)
    state = serializers.PrimaryKeyRelatedField(queryset=State.objects.all(), required=False, allow_null=True)
    city = serializers.CharField(max_length=50, required=False, allow_blank=True)
    profile_image = serializers.ImageField(required=False, allow_null=True, allow_empty_file=True)

    def validate_first_name(self, value):
        if value and value.strip():
            if len(value.strip()) < 2:
                raise serializers.ValidationError("First name must be at least 2 characters long.")
            if not re.match(r'^[a-zA-Z\s\'-]+$', value):
                raise serializers.ValidationError("First name can only contain letters, spaces, hyphens, and apostrophes.")
        return value

    def validate_last_name(self, value):
        if value and value.strip():
            if len(value.strip()) < 2:
                raise serializers.ValidationError("Last name must be at least 2 characters long.")
            if not re.match(r'^[a-zA-Z\s\'-]+$', value):
                raise serializers.ValidationError("Last name can only contain letters, spaces, hyphens, and apostrophes.")
        return value

    def validate_mobile(self, value):
        if value and value.strip():
            if not re.match(r'^[6-9]\d{9}$', value):
                raise serializers.ValidationError("Mobile number must be 10 digits starting with 6, 7, 8, or 9.")

            existing_mobile = UserInfo.objects.filter(mobile=value).exclude(user__id=self.context.get('user_id')).exists()
            if existing_mobile:
                raise serializers.ValidationError("This mobile number is already in use.")
        return value

    def validate_company(self, value):
        if value and value.strip():
            if len(value.strip()) < 2:
                raise serializers.ValidationError("Company name must be at least 2 characters long.")
            if len(value.strip()) > 100:
                raise serializers.ValidationError("Company name must not exceed 100 characters.")
        return value

    def validate_job_profile(self, value):
        if value and value.strip():
            if len(value.strip()) < 2:
                raise serializers.ValidationError("Job title must be at least 2 characters long.")
            if len(value.strip()) > 100:
                raise serializers.ValidationError("Job title must not exceed 100 characters.")
        return value

    def validate_city(self, value):
        if value and value.strip():
            if len(value.strip()) < 2:
                raise serializers.ValidationError("City name must be at least 2 characters long.")
            if len(value.strip()) > 50:
                raise serializers.ValidationError("City name must not exceed 50 characters.")
        return value

    def validate_profile_image(self, value):
        if value:
            if value.size > 5 * 1024 * 1024:
                raise serializers.ValidationError("Profile image size cannot exceed 5MB.")
            
            allowed_formats = ['jpeg', 'jpg', 'png']
            file_format = value.name.split('.')[-1].lower()
            if file_format not in allowed_formats:
                raise serializers.ValidationError(f"Invalid image format. Allowed formats: {', '.join(allowed_formats)}")
        
        return value

    def update(self, instance, validated_data):
        user = instance
        user_info = user.info

        if 'first_name' in validated_data:
            user.first_name = validated_data['first_name']
        if 'last_name' in validated_data:
            user.last_name = validated_data['last_name']
        user.save()

        if 'mobile' in validated_data:
            user_info.mobile = validated_data['mobile']
        if 'company' in validated_data:
            user_info.company = validated_data['company']
        if 'job_profile' in validated_data:
            user_info.job_profile = validated_data['job_profile']
        if 'state' in validated_data:
            user_info.state = validated_data['state']
        if 'city' in validated_data:
            user_info.city = validated_data['city']
        if 'profile_image' in validated_data:
            if validated_data['profile_image'] is None:
                if user_info.profile_image:
                    user_info.profile_image.delete()
                user_info.profile_image = None
            else:
                user_info.profile_image = validated_data['profile_image']
        user_info.save()

        return user
