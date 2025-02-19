from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils.translation import gettext_lazy as _
from django.core.validators import RegexValidator
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import make_password
import uuid
import pyotp

CustomUser = get_user_model()

class Custom_User(AbstractUser):
    """
    Custom User Model for the Humsanity Platform.
    Includes fields for roles, preferences, and security features.
    """

    # Constants
    ROLE_CHOICES = (
        ('student', 'Student'),
        ('coach', 'Coach'),
        ('admin', 'Admin'),
    )

    # Fields
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)  # Unique identifier
    email = models.EmailField(_('email address'), unique=True)  # Email as unique identifier
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='student')  # User role
    phone_number = models.CharField(
        max_length=15,
        blank=True,
        null=True,
        validators=[RegexValidator(r'^\+?1?\d{9,15}$', 'Invalid phone number format.')]
    )  # Optional phone number for 2FA
    preferences = models.JSONField(default=dict, blank=True, null=True)  # User preferences (e.g., notifications)
    is_email_verified = models.BooleanField(default=False)  # Email verification status
    is_phone_verified = models.BooleanField(default=False, null=True)  # Phone verification status
    last_login_ip = models.GenericIPAddressField(blank=True, null=True)  # Track last login IP
    failed_login_attempts = models.PositiveIntegerField(default=0, null=True)  # Track failed login attempts
    account_locked_until = models.DateTimeField(blank=True, null=True)  # Account lockout timestamp
    created_at = models.DateTimeField(auto_now_add=True)  # Timestamp for account creation
    updated_at = models.DateTimeField(auto_now=True)  # Timestamp for last update

    # Password-related fields
    password_history = models.JSONField(default=list, blank=True)  # Store previous passwords
    is_password_expired = models.BooleanField(default=False)  # Flag for password expiration

    # Two-Factor Authentication (2FA) fields
    otp_secret = models.CharField(max_length=16, blank=True, null=True)  # Secret for authenticator apps
    backup_codes = models.JSONField(default=list, blank=True)  # Backup codes for 2FA recovery

    # Methods
    def __str__(self):
        return self.email

    def save(self, *args, **kwargs):
        """
        Override the save method to enforce additional logic:
        - Hash passwords.
        - Validate phone numbers.
        """
        if self.pk is None:  # New user creation
            self.set_password(self.password)  # Hash the password
        super().save(*args, **kwargs)

    def check_password_strength(self, password):
        """
        Validate password strength before saving.
        """
        from django.core.exceptions import ValidationError
        if len(password) < 8:
            raise ValidationError("Password must be at least 8 characters long.")
        if not any(char.isdigit() for char in password):
            raise ValidationError("Password must contain at least one digit.")
        if not any(char.isalpha() for char in password):
            raise ValidationError("Password must contain at least one letter.")
        if not any(char.isupper() for char in password):
            raise ValidationError("Password must contain at least one uppercase letter.")
        if not any(char.islower() for char in password):
            raise ValidationError("Password must contain at least one lowercase letter.")
        return True

    def add_to_password_history(self, password):
        """
        Add the current password to the password history.
        """
        hashed_password = make_password(password)
        self.password_history.append(hashed_password)
        self.save(update_fields=['password_history'])

    def generate_backup_codes(self):
        """
        Generate and store backup codes for 2FA recovery.
        """
        import secrets
        self.backup_codes = [secrets.token_hex(4) for _ in range(5)]
        self.save(update_fields=['backup_codes'])

    def check_otp(self, otp):
        """
        Verify OTP for 2FA.
        """
       
        if self.otp_secret:
            totp = pyotp.TOTP(self.otp_secret)
            return totp.verify(otp)
        return False