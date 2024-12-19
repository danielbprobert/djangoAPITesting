from django_otp.plugins.otp_totp.models import TOTPDevice
from django.db import models
from django.contrib.auth.models import AbstractUser
from django.conf import settings
from django.utils.timezone import now
from datetime import datetime, timedelta
import uuid
import requests

class CustomUser(AbstractUser):
    email = models.EmailField(unique=True)
    otp_device = models.OneToOneField(
        TOTPDevice,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='custom_user_device',
    )

class UserChangeAudit(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, 
        on_delete=models.CASCADE, 
        related_name='change_audit_logs'
    )
    changed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True, 
        related_name='changed_user_logs'
    ) 
    field_name = models.CharField(max_length=255)
    old_value = models.TextField(null=True, blank=True)  
    new_value = models.TextField(null=True, blank=True)  
    timestamp = models.DateTimeField(default=now)  

    def __str__(self):
        return f"Change in {self.field_name} for {self.user.username} by {self.changed_by.username if self.changed_by else 'System'}"

class APIKey(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name="api_keys")
    key = models.CharField(max_length=40, unique=True)
    is_production = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def save(self, *args, **kwargs):
        if self.user.api_keys.count() >= 5:
            raise ValueError("You cannot create more than 5 API keys.")

        if self.is_production:
            APIKey.objects.filter(user=self.user, is_production=True).update(is_production=False)
        super().save(*args, **kwargs)

class SalesforceConnection(models.Model):
    ORG_TYPE_CHOICES = [
        ('Production', 'Production'),
        ('Sandbox', 'Sandbox'),
        ('Developer', 'Developer'),
        ('ScratchOrg', 'ScratchOrg'),
    ]

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="salesforce_connections")
    connection_name = models.CharField(max_length=255)
    access_token = models.CharField(max_length=255)
    refresh_token = models.CharField(max_length=255, blank=True, null=True)
    instance_url = models.URLField()
    authenticated = models.BooleanField(default=False)
    organization_id = models.CharField(max_length=255, blank=True, null=True)
    org_type = models.CharField(max_length=10, choices=ORG_TYPE_CHOICES, default='Production')  # New field for organization type
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Salesforce Connection for {self.user.username} - {self.connection_name} ({self.get_org_type_display()})"

    def refresh_access_token(self):
        """
        Refresh the Salesforce access token using the stored refresh token.
        """
        if not self.refresh_token:
            raise ValueError("No refresh token available for this Salesforce connection.")

        token_url = f"{self.instance_url}/services/oauth2/token"
        payload = {
            "grant_type": "refresh_token",
            "client_id": settings.SALESFORCE_CLIENT_ID,
            "client_secret": settings.SALESFORCE_CLIENT_SECRET,
            "refresh_token": self.refresh_token,
        }

        response = requests.post(token_url, data=payload)
        if response.status_code == 200:
            data = response.json()
            self.access_token = data["access_token"]
            self.instance_url = data.get("instance_url", self.instance_url)  # Update instance URL if provided
            self.authenticated = True
            self.updated_at = datetime.now()
            self.save()
        else:
            raise ValueError(f"Failed to refresh Salesforce access token: {response.text}")


class LoginHistory(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="login_history")
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    browser_details = models.TextField(null=True, blank=True)
    login_time = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username} - {self.login_time}"

class APIUsage(models.Model):
    STATUS_CHOICES = [
        ('SUCCESS', 'Success'),
        ('FAILURE', 'Failure'),
    ]

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="api_usage_logs")
    api_key = models.ForeignKey(APIKey, on_delete=models.SET_NULL, null=True, blank=True, related_name="usage_logs")
    salesforce_connection = models.ForeignKey(SalesforceConnection, on_delete=models.SET_NULL, null=True, blank=True, related_name="usage_logs")
    sf_document_id = models.CharField(max_length=255, null=True, blank=True)
    status = models.CharField(max_length=7, choices=STATUS_CHOICES)
    timestamp = models.DateTimeField(auto_now_add=True)
    error_message = models.TextField(null=True, blank=True) 

    process_start_time = models.DateTimeField(null=True, blank=True)
    process_end_time = models.DateTimeField(null=True, blank=True)
    process_duration = models.FloatField(null=True, blank=True)  # duration in seconds
    process_status = models.CharField(max_length=10, null=True, blank=True)  # SUCCESS or FAILURE

    transaction_id = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)  # Add this field

    def calculate_process_duration(self):
        if self.process_start_time and self.process_end_time:
            self.process_duration = (self.process_end_time - self.process_start_time).total_seconds()
            self.save()

    def __str__(self):
        return f"API Usage by {self.user.username} - {self.status} at {self.timestamp}"

class ProcessLog(models.Model):
    api_usage = models.ForeignKey('APIUsage', on_delete=models.CASCADE, related_name="process_logs")
    step_name = models.CharField(max_length=255)  # Name of the step
    start_time = models.DateTimeField(auto_now_add=True)  # Start time of the step
    end_time = models.DateTimeField(null=True, blank=True)  # End time of the step
    duration_seconds = models.FloatField(null=True, blank=True)  # Duration in seconds
    status = models.CharField(max_length=10)  # SUCCESS or FAILURE
    error_message = models.TextField(null=True, blank=True)  # Error message if the step fails

    def calculate_duration(self):
        """
        Calculates the duration of the step in seconds
        """
        if self.start_time and self.end_time:
            self.duration_seconds = (self.end_time - self.start_time).total_seconds()
            self.save()

    def __str__(self):
        return f"Step: {self.step_name} for API Usage: {self.api_usage.id}"
    
    
class TrustedIP(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="trusted_ips")
    ip_address = models.GenericIPAddressField()
    is_trusted = models.BooleanField(default=False)
    added_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        status = "Trusted" if self.is_trusted else "Untrusted"
        return f"{self.user.username} - {self.ip_address} ({status})"