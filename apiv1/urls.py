from django.urls import path
from .views import DocumentProcessingView, UserAPIUsageLogsView

urlpatterns = [
    path('process-document/', DocumentProcessingView.as_view(), name='process-document'),
    path('transactions/', UserAPIUsageLogsView.as_view(), name='user_api_usage_logs'),
]