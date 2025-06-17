from django.urls import path
from .views import RegisterView,ActivateAccountView
from rest_framework_simplejwt.views import TokenObtainPairView,TokenRefreshView
from .views import (
    RegisterView, ActivateAccountView, Enable2FAView, Verify2FAView,
    LoginView, VerifyOTPView
)

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('activate/<uidb64>/<token>/', ActivateAccountView.as_view(), name='activate'),

    path('login/', LoginView.as_view(), name='login'),                  # <-- login con OTP se attivo
    path('login/verify-otp/', VerifyOTPView.as_view(), name='verify-otp'),  # <-- verifica OTP

    path('refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('2fa/enable/', Enable2FAView.as_view(), name='enable-2fa'),
    path('2fa/verify/', Verify2FAView.as_view(), name='verify-2fa'),
]