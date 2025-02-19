from rest_framework import serializers
from .models import Custom_User

class CustomUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = Custom_User
        fields = [
            'id', 'username', 'email', 'role', 'phone_number', 'preferences',
            'is_email_verified', 'is_phone_verified', 'last_login_ip',
            'failed_login_attempts', 'account_locked_until', 'created_at',
            'updated_at', 'password_history', 'is_password_expired',
            'otp_secret', 'backup_codes'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at', 'password_history', 'backup_codes']

    def create(self, validated_data):
        user = Custom_User(
            email=validated_data['email'],
            username=validated_data['username'],
            role=validated_data.get('role', 'student'),
            phone_number=validated_data.get('phone_number', ''),
            preferences=validated_data.get('preferences', {}),
            is_email_verified=validated_data.get('is_email_verified', False),
            is_phone_verified=validated_data.get('is_phone_verified', False),
            last_login_ip=validated_data.get('last_login_ip', None),
            failed_login_attempts=validated_data.get('failed_login_attempts', 0),
            account_locked_until=validated_data.get('account_locked_until', None),
            is_password_expired=validated_data.get('is_password_expired', False),
            otp_secret=validated_data.get('otp_secret', None),
        )
        user.set_password(validated_data['password'])
        user.save()
        return user

    def update(self, instance, validated_data):
        instance.email = validated_data.get('email', instance.email)
        instance.username = validated_data.get('username', instance.username)
        instance.role = validated_data.get('role', instance.role)
        instance.phone_number = validated_data.get('phone_number', instance.phone_number)
        instance.preferences = validated_data.get('preferences', instance.preferences)
        instance.is_email_verified = validated_data.get('is_email_verified', instance.is_email_verified)
        instance.is_phone_verified = validated_data.get('is_phone_verified', instance.is_phone_verified)
        instance.last_login_ip = validated_data.get('last_login_ip', instance.last_login_ip)
        instance.failed_login_attempts = validated_data.get('failed_login_attempts', instance.failed_login_attempts)
        instance.account_locked_until = validated_data.get('account_locked_until', instance.account_locked_until)
        instance.is_password_expired = validated_data.get('is_password_expired', instance.is_password_expired)
        instance.otp_secret = validated_data.get('otp_secret', instance.otp_secret)

        if 'password' in validated_data:
            instance.set_password(validated_data['password'])

        instance.save()
        return instance