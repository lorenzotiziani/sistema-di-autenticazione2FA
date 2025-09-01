from django.urls import path
from .views import RegisterView,ActivateAccountView
from rest_framework_simplejwt.views import TokenObtainPairView,TokenRefreshView
from .views import (
    RegisterView, ActivateAccountView, Enable2FAView, Verify2FAView,
    LoginView, VerifyOTPView, Disable2FAView
)

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('activate/<uidb64>/<token>/', ActivateAccountView.as_view(), name='activate'),

    path('login/', LoginView.as_view(), name='login'),
    path('login/verify-otp/', VerifyOTPView.as_view(), name='verify-otp'),

    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('2fa/enable/', Enable2FAView.as_view(), name='enable-2fa'),
    path('2fa/verify/', Verify2FAView.as_view(), name='verify-2fa'),
    path('2fa/disable/', Disable2FAView.as_view(), name='disable-2fa'),
]