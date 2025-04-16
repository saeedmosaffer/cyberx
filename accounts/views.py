from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .serializers import UserRegisterSerializer, LoginSerializer
from django.contrib.auth import login
from .models import CustomUser
import pyotp
from django.core.mail import send_mail
from rest_framework_simplejwt.tokens import RefreshToken
import requests
import os
import socket
import re
from django.core.cache import cache
import time

class RegisterView(APIView):
    def post(self, request):
        serializer = UserRegisterSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            return Response({"message": "User registered successfully"}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class LoginView(APIView):
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.validated_data
            login(request, user)
            refresh = RefreshToken.for_user(user)
            # Generate MFA OTP if enabled
            if user.is_mfa_enabled:
                mfa_secret = user.mfa_secret or pyotp.random_base32()
                user.mfa_secret = mfa_secret
                user.save()
                totp = pyotp.TOTP(mfa_secret)
                otp = totp.now()
                send_mail(
                    subject='Your MFA Code',
                    message=f'Your one-time code is {otp}',
                    from_email=None,
                    recipient_list=[user.email],
                )
                return Response({
                    "message": "OTP sent to email",
                    "user_id": user.id,
                    "mfa_required": True
                }, status=status.HTTP_200_OK)
            return Response({
                "refresh": str(refresh),
                "access": str(refresh.access_token),
                "mfa_required": False
            }, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class MFAVerifyView(APIView):
    def post(self, request):
        user_id = request.data.get('user_id')
        otp = request.data.get('otp')
        try:
            user = CustomUser.objects.get(id=user_id)
            totp = pyotp.TOTP(user.mfa_secret)
            if totp.verify(otp):
                login(request, user)
                refresh = RefreshToken.for_user(user)
                return Response({
                    "refresh": str(refresh),
                    "access": str(refresh.access_token),
                    "message": "MFA verified"
                }, status=status.HTTP_200_OK)
            return Response({"error": "Invalid OTP"}, status=status.HTTP_400_BAD_REQUEST)
        except CustomUser.DoesNotExist:
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)


class CheckBotnetView(APIView):
    def get(self, request):
        ip_address = request.META.get('REMOTE_ADDR')
        cache_key = f"rate_limit_{ip_address}"
        request_count = cache.get(cache_key, 0)
        expiration = cache.get(f"{cache_key}_expiration", 0)

        current_time = int(time.time())
        if current_time > expiration:
            request_count = 0
            expiration = current_time + 60
            cache.set(f"{cache_key}_expiration", expiration, timeout=60)

        if request_count >= 10:
            return Response({"error": "Rate limit exceeded. Please try again later."}, status=status.HTTP_429_TOO_MANY_REQUESTS)

        cache.set(cache_key, request_count + 1, timeout=60)

        target = request.query_params.get('target', None)
        if not target:
            return Response({"error": "Target IP or domain is required."}, status=status.HTTP_400_BAD_REQUEST)

        url_pattern = re.compile(r'^(?:https?://)?([^/]+)')
        match = url_pattern.match(target)
        if match:
            target = match.group(1)

        ip_pattern = re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')
        ip_address_target = target

        if not ip_pattern.match(target):
            try:
                ip_address_target = socket.gethostbyname(target)
            except socket.gaierror:
                return Response({"error": "Could not resolve domain to an IP address."}, status=status.HTTP_400_BAD_REQUEST)

        api_key = os.getenv('ABUSEIPDB_API_KEY', '9bb97d0d431f7aafd28abf7a800b6555c6a5e330b2147ad2e678f063cf633b088116b38ca95d6bbe')
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {
            "Key": api_key,
            "Accept": "application/json"
        }
        params = {
            "ipAddress": ip_address_target,
            "maxAgeInDays": "90"
        }

        try:
            response = requests.get(url, headers=headers, params=params)
            response.raise_for_status()
            data = response.json()
            return Response(data, status=status.HTTP_200_OK)
        except requests.exceptions.RequestException as e:
            return Response({"error": f"Failed to check botnet: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)