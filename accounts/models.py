from django.db import models
from django.contrib.auth.models import AbstractUser

class CustomUser(AbstractUser):
    email = models.EmailField(unique=True)
    first_name = models.CharField(max_length=50)
    last_name = models.CharField(max_length=50)
    dob = models.DateField(null=True, blank=True)
    country = models.CharField(max_length=100, blank=True)
    mfa_secret = models.CharField(max_length=32, blank=True, null=True)
    is_mfa_enabled = models.BooleanField(default=False)

    def __str__(self):
        return self.username