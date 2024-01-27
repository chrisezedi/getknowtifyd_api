from django.contrib import admin
from django.urls import path
from core.views import (CreateUser, ActivateUser, ResendActivationMail, CustomTokenRefreshView,
                        CheckUsernameAvailabilityView, SetUsernameView, LoginUserView, GoogleAuthView)
from rest_framework_simplejwt.views import TokenObtainPairView

admin.site.site_header = 'Getknowtifyd'
admin.site.index_title = 'Admin'


urlpatterns = [
    path('admin/', admin.site.urls),
    path('auth/signup', CreateUser.as_view(), name="signup"),
    path('auth/signin', LoginUserView.as_view(), name="signin"),
    path('auth/activate', ActivateUser.as_view(), name="activate"),
    path('auth/resendactivationmail', ResendActivationMail.as_view(), name="resendmail"),
    path('auth/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('auth/token/refresh/', CustomTokenRefreshView.as_view(), name='token_refresh'),
    path('auth/google-auth', GoogleAuthView.as_view(), name='google_auth'),
    path('user/check-username-availability', CheckUsernameAvailabilityView.as_view(),
         name='check-username-availability'),
    path('user/set-username', SetUsernameView.as_view(),
         name='set-username')
]
