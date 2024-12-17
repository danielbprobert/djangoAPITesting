from django.urls import path
from .views import DocumentProcessingView

urlpatterns = [
    path('process-document/', DocumentProcessingView.as_view(), name='process-document'),
]