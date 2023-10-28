from django.contrib import admin
from django.urls import path, include
from core.views import CreateUser, ActivateUser, ResendActivationMail

admin.site.site_header = 'Getknowtifyd'
admin.site.index_title = 'Admin'


urlpatterns = [
    path('admin/', admin.site.urls),
    path('auth/signup', CreateUser.as_view()),
    path('auth/activate', ActivateUser.as_view(), name='activate'),
    path('auth/resendactivationmail', ResendActivationMail.as_view(), name='resendmail'),
]
