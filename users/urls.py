from django.urls import path
from . import views
from django.contrib.auth import views as auth_views

urlpatterns = [
    path('', views.dashbaord, name='home'),
    path('profile/', views.profile, name='profile'),
    path('profile/update/', views.update_profile, name='update_profile'),

    path('login-history/', views.login_history, name='login_history'),
    path('ip-management/', views.ip_management, name='ip_management'),
    
    path('register/', views.register, name='register'),
    path('login/', views.otp_login, name='login'),
    path('logout/', views.user_logout, name='logout'),

    path('password-reset/', auth_views.PasswordResetView.as_view(template_name='users/password_reset.html'), name='password_reset'),
    path('password-reset/done/', auth_views.PasswordResetDoneView.as_view(template_name='users/password_reset_done.html'), name='password_reset_done'),
    path('password-reset-confirm/<uidb64>/<token>/', auth_views.PasswordResetConfirmView.as_view(template_name='users/password_reset_confirm.html'), name='password_reset_confirm'),
    path('password-reset-complete/', auth_views.PasswordResetCompleteView.as_view(template_name='users/password_reset_complete.html'), name='password_reset_complete'),

    path('otp-setup/', views.otp_setup, name='otp_setup'),
    path('enable-otp/', views.enable_otp, name='enable_otp'),
    path('disable-otp/', views.disable_otp, name='disable_otp'),
    path('mark-trusted/<int:ip_id>/', views.mark_ip_as_trusted, name='mark_trusted'),
    path('delete-ip/<int:ip_id>/', views.delete_ip, name='delete_ip'),
    path('download-login-history/', views.download_login_history, name='download_login_history'),
    
    path('api-keys/', views.apikeys, name='apikeys'),  # Primary view for API keys management
    path('api-keys/<int:key_id>/update/', views.update_api_key, name='update_api_key'),
    path('api-keys/<int:key_id>/delete/', views.delete_api_key, name='delete_api_key'),
    
    path('connections/', views.connections, name='connections'),
    path('add_connection/', views.add_connection, name='add_connection'),
    path('salesforce/login/', views.salesforce_login, name='salesforce_login'),
    path('salesforce/callback/', views.salesforce_callback, name='salesforce_callback'),
    path('salesforce/save-tokens/', views.save_salesforce_tokens, name='save_salesforce_tokens'),
    path('salesforce/disconnect/<int:connection_id>/', views.disconnect_salesforce_connection, name='disconnect_salesforce_connection'),
]
