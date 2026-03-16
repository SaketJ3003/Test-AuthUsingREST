from django.contrib import admin
from .models import UserInfo, TempUser, State, UserToken, EmailVerificationToken, OTP

# Register your models here.
admin.site.register(UserInfo)
admin.site.register(TempUser)
admin.site.register(State)
admin.site.register(UserToken)
admin.site.register(OTP)
admin.site.register(EmailVerificationToken)