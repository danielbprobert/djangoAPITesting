from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import CustomUser, APIKey, APIUsage, TrustedIP, UserChangeAudit, SalesforceConnection

class APIKeyInline(admin.TabularInline):
    model = APIKey
    extra = 0 
    fields = ('key', 'is_production', 'created_at')
    readonly_fields = ('key', 'created_at')
    can_delete = True

class APIUsageInline(admin.TabularInline):
    model = APIUsage
    extra = 0
    readonly_fields = ('timestamp', 'status', 'sf_document_id', 'api_key', 'salesforce_connection', 'api_call_summary')

    def api_call_summary(self, obj):
        return f"Document: {obj.sf_document_id}, Status: {obj.status}"
    api_call_summary.short_description = "API Call Summary"

class TrustedIPInline(admin.TabularInline):
    model = TrustedIP
    extra = 0  
    readonly_fields = ('ip_address', 'is_trusted', 'added_at') 
    can_delete = False  

    def has_add_permission(self, request, obj):
        """Prevent adding new IPs directly via inline."""
        return False
    
class UserChangeAuditInline(admin.TabularInline):
    model = UserChangeAudit
    fk_name = 'user'  # Specify the 'user' field as the relationship to CustomUser
    extra = 0
    readonly_fields = ('changed_by', 'field_name', 'old_value', 'new_value', 'timestamp')
    can_delete = False

    def has_add_permission(self, request, obj):
        """Disallow adding new audit records directly."""
        return False

@admin.register(CustomUser)
class CustomUserAdmin(UserAdmin):
    model = CustomUser

    list_display = ('username', 'email', 'first_name', 'last_name', 'is_staff', 'is_active')
    list_filter = ('is_staff', 'is_active', 'groups')
    search_fields = ('username', 'email', 'first_name', 'last_name')
    ordering = ('username',)

    fieldsets = UserAdmin.fieldsets + (
        (None, {'fields': ('otp_device',)}), 
    )
    add_fieldsets = UserAdmin.add_fieldsets + (
        (None, {'fields': ('username', 'email', 'password1', 'password2', 'otp_device')}), 
    )

    inlines = [APIKeyInline, APIUsageInline, TrustedIPInline, UserChangeAuditInline]

@admin.register(SalesforceConnection)
class SalesforceConnectionAdmin(admin.ModelAdmin):
    list_display = ('user', 'connection_name', 'authenticated', 'instance_url', 'created_at', 'updated_at')
    search_fields = ('user__username', 'connection_name', 'instance_url')
    list_filter = ('authenticated', 'created_at', 'updated_at')
    readonly_fields = ('created_at', 'updated_at')
    ordering = ('-created_at',)

    fieldsets = (
        (None, {
            'fields': ('user', 'connection_name', 'access_token', 'refresh_token', 'instance_url', 'authenticated')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
        }),
    )

