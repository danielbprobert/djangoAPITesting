from django.contrib import admin
from .models import SubscriptionOption, UserSubscription

@admin.register(SubscriptionOption)
class SubscriptionOptionAdmin(admin.ModelAdmin):
    list_display = ("name", "api_limit", "cost")
    search_fields = ("name",)

@admin.register(UserSubscription)
class UserSubscriptionAdmin(admin.ModelAdmin):
    list_display = ("user", "subscription_option", "is_active", "start_date", "end_date")
    search_fields = ("user__username", "subscription_option__name")
    list_filter = ("is_active",)
