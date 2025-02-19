from django.shortcuts import render
from rest_framework import viewsets, permissions
from .models import Custom_User
from .serializer import CustomUserSerializer

# Create your views here.

class CustomUserViewSet(viewsets.ModelViewSet):
    queryset = Custom_User.objects.all()
    serializer_class = CustomUserSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_permissions(self):
        if self.action in ['list', 'retrieve']:
            self.permission_classes = [permissions.IsAuthenticated]
        elif self.action in ['create', 'update', 'partial_update', 'destroy']:
            self.permission_classes = [permissions.IsAdminUser]
        return super().get_permissions()
