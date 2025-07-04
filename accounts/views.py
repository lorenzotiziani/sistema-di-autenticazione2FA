from django.contrib.auth.base_user import AbstractBaseUser
from django.db import models
from django.contrib.auth.models import AbstractUser,BaseUserManager,PermissionsMixin
from django.utils import timezone
from django.urls import reverse
from rest_framework import serializers
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth import get_user_model, authenticate
from django.core.mail import send_mail
from django.conf import settings
import pyotp
import qrcode
import io
import base64
import jwt
from datetime import timedelta
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.tokens import RefreshToken
from .serializers import RegisterSerializer, MyTokenObtainPairSerializer


# Funzione di utilità per la generazione del link di attivazione
def generate_activation_link(user, request):
    uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
    token = default_token_generator.make_token(user)
    relative_link = reverse('activate', kwargs={'uidb64': uidb64, 'token': token})
    return request.build_absolute_uri(relative_link)


# Salva l'utente e manda la mail di attivazione
class RegisterView(APIView):
    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            user.is_active = False
            user.save()

            activation_link = generate_activation_link(user, request)

            send_mail(
                subject="Attiva il tuo account",
                message=f"Clicca il link per attivare il tuo account:\n {activation_link}",
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[user.email],
            )

            return Response({'message': 'Registrazione completata. Controlla la tua email per attivare l\'account.'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# Attiva l'account tramite link dalla mail
class ActivateAccountView(APIView):
    def get(self, request, uidb64, token):
        try:
            uid = urlsafe_base64_decode(uidb64).decode()
            user = get_user_model().objects.get(pk=uid)
        except Exception:
            return Response({'error': 'Link non valido'}, status=status.HTTP_400_BAD_REQUEST)

        if default_token_generator.check_token(user, token):
            user.is_active = True
            user.save()
            return Response({'message': 'Account attivato! Ora puoi accedere.'}, status=status.HTTP_200_OK)
        return Response({'error': 'Token non valido o scaduto'}, status=status.HTTP_400_BAD_REQUEST)

class Enable2FAView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        if user.is_2fa_enabled and user.totp_secret:
            return Response({'message': '2FA già attivo.'}, status=400)

        secret = pyotp.random_base32()
        user.totp_secret = secret
        user.is_2fa_enabled = True
        user.save()

        otp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
            name=user.email,
            issuer_name="Sistema Django 2FA"
        )

        # Genera QR code
        qr = qrcode.make(otp_uri)
        buffered = io.BytesIO()
        qr.save(buffered, format="PNG")
        qr_base64 = base64.b64encode(buffered.getvalue()).decode()

        #CREAZIONE DI NUOVI TOKEN
        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)

        return Response({
            'message': '2FA abilitato. Scansiona il QR Code e verifica con OTP.',
            'qr_code_base64': qr_base64,
            'manual_code': secret,
            'access': access_token,
            'refresh': str(refresh)
        }, status=200)

class Verify2FAView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        if not user.is_2fa_enabled or not user.totp_secret:
            return Response({'error': '2FA non attivo.'}, status=400)

        otp_code = request.data.get('otp')
        if not otp_code:
            return Response({'error': 'Codice OTP mancante.'}, status=400)

        totp = pyotp.TOTP(user.totp_secret)
        if totp.verify(otp_code):
            return Response({'message': 'Codice OTP verificato con successo.'}, status=200)
        else:
            return Response({'error': 'Codice OTP non valido.'}, status=400)

class LoginView(APIView):
    def post(self, request):
        email = request.data.get("email")
        password = request.data.get("password")
        user = authenticate(request, email=email, password=password)

        if user is None:
            return Response({"error": "Credenziali non valide."}, status=401)
        if not user.is_active:
            return Response({"error": "Account non attivato."}, status=403)

        if user.is_2fa_enabled:
            payload = {
                "user_id": user.id,
                "exp": (timezone.now() + timedelta(minutes=5)).timestamp(),
                "type": "temp"
            }
            temp_token = jwt.encode(payload, settings.SECRET_KEY, algorithm="HS256")
            return Response({"message": "OTP richiesto", "temp_token": temp_token})
        else:
            refresh = RefreshToken.for_user(user)
            return Response({
                "access": str(refresh.access_token),
                "refresh": str(refresh)
            })


class VerifyOTPView(APIView):
    authentication_classes = []
    permission_classes = []

    def post(self, request):
        otp = request.data.get("otp")
        temp_token = request.data.get("temp_token")

        try:
            payload = jwt.decode(temp_token, settings.SECRET_KEY, algorithms=["HS256"])
            if payload.get("type") != "temp":
                raise jwt.InvalidTokenError()
        except jwt.ExpiredSignatureError:
            return Response({"error": "Token scaduto."}, status=401)
        except jwt.InvalidTokenError:
            return Response({"error": "Token non valido."}, status=400)

        user_id = payload.get("user_id")
        try:
            user = get_user_model().objects.get(id=user_id)
        except get_user_model().DoesNotExist:
            return Response({"error": "Utente non trovato."}, status=404)

        totp = pyotp.TOTP(user.totp_secret)
        if not totp.verify(otp):
            return Response({"error": "Codice OTP non valido."}, status=400)

        refresh = RefreshToken.for_user(user)
        return Response({
            "access": str(refresh.access_token),
            "refresh": str(refresh)
        })

class Disable2FAView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        if not user.is_2fa_enabled:
            return Response({'message': 'La 2FA non è attiva per questo account.'}, status=status.HTTP_400_BAD_REQUEST)


        user.totp_secret = None
        user.is_2fa_enabled = False
        user.save()


        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)

        return Response({
            'message': '2FA disabilitata con successo.',
            'access': access_token,
            'refresh': str(refresh)
        }, status=status.HTTP_200_OK)