from django.urls import path
from .views import DocumentProcessingView, UserAPIUsageLogsView, UserAPIUsageByTransactionView, SuperUserOnlyView

urlpatterns = [
    path('process-document/', DocumentProcessingView.as_view(), name='process-document'),
    path('transactions/', UserAPIUsageLogsView.as_view(), name='user_api_usage_logs'),
    path('transaction/', UserAPIUsageByTransactionView.as_view(), name='user_api_usage_by_transaction'),
    path('superuser-only/', SuperUserOnlyView.as_view(), name='superuser_only_api'),
]