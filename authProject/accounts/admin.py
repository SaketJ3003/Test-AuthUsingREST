from django.contrib import admin
from .models import UserInfo, TempOtp, TempUser, State,UserToken
# Register your models here.
admin.site.register(UserInfo)
admin.site.register(TempOtp)
admin.site.register(TempUser)
admin.site.register(State)
admin.site.register(UserToken)