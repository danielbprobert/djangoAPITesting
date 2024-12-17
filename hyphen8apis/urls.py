from django.contrib import admin
from django.conf.urls import handler403, handler404, handler500
from django.urls import path, include
from django.contrib.auth import views as auth_views
from .views import custom_403_view, custom_404_view, custom_500_view

handler403 = custom_403_view
handler404 = custom_404_view
handler500 = custom_500_view

urlpatterns = [
    path('admin/', admin.site.urls),
    path('admin/login/', auth_views.LoginView.as_view(), name='admin_login'),
    path('', include('users.urls')),
    path("subscriptions/", include("subscriptions.urls")),
    path('api/v1/', include('apiv1.urls')),
]
