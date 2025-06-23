from django.contrib.auth.base_user import AbstractBaseUser
from django.db import models
from django.contrib.auth.models import AbstractUser,BaseUserManager,PermissionsMixin
from django.utils import timezone

class UserManager(BaseUserManager):
    def create_user(self,email,password,**extra_fields):
        if not email:
            raise ValueError('The email must be set')
        email=self.normalize_email(email)
        user=self.model(email=email,**extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')

        return self.create_user(email, password, **extra_fields)

#modello che utilizza la mail come username
class User(AbstractBaseUser,PermissionsMixin):
    email=models.EmailField(max_length=255,unique=True)
    first_name=models.CharField(max_length=255)
    last_name=models.CharField(max_length=255)
    #flag che si attiva dopo aver cliccato il link della mail
    is_active=models.BooleanField(default=True)
    is_staff=models.BooleanField(default=False)
    date_joined=models.DateTimeField(default=timezone.now)
    #per il codice OTP
    totp_secret = models.CharField(max_length=32, blank=True, null=True)
    #per sapere se è attivo il 2FA
    is_2fa_enabled=models.BooleanField(default=False)

    objects = UserManager()  # Usi un manager personalizzato per gestire creazione utenti/superuser.

    USERNAME_FIELD = 'email'  # L'email è usata al posto dello username per il login.
    REQUIRED_FIELDS = []  # Nessun campo extra richiesto per creare un superuser.

    def __str__(self):
        return self.email