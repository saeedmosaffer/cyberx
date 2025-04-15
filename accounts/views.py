from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .serializers import UserRegisterSerializer, LoginSerializer
from django.contrib.auth import login
from .models import CustomUser
import pyotp
from django.core.mail import send_mail
from rest_framework_simplejwt.tokens import RefreshToken

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