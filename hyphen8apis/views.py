from django.shortcuts import render
from sentry_sdk import capture_message, capture_exception

def custom_403_view(request, exception=None):
    capture_message("403 Forbidden Error", level="error")
    return render(request, "403.html", status=403)

def custom_404_view(request, exception=None):
    capture_message("404 Page Not Found Error", level="error")
    return render(request, "404.html", status=404)

def custom_500_view(request):
    capture_exception(Exception("500 Internal Server Error"))
    return render(request, "500.html", status=500)