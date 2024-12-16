from django.db import models
from django.conf import settings

class SubscriptionOption(models.Model):
    name = models.CharField(max_length=255)  # Option name, e.g., "Basic", "Pro", "Enterprise"
    api_limit = models.PositiveIntegerField()  # Number of API requests allowed per month
    cost = models.DecimalField(max_digits=10, decimal_places=2)  # Monthly cost

    def __str__(self):
        return f"{self.name}"

class UserSubscription(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="subscriptions")
    subscription_option = models.ForeignKey(SubscriptionOption, on_delete=models.CASCADE)
    start_date = models.DateTimeField(auto_now_add=True)
    end_date = models.DateTimeField(blank=True, null=True)  # For cancellations
    is_active = models.BooleanField(default=True)

    def __str__(self):
        return f"{self.user.username} - {self.subscription_option.name}"

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["user", "subscription_option"], name="unique_user_subscription"),
        ]
