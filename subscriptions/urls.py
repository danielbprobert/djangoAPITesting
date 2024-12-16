from django.urls import path
from . import views

app_name = 'subscriptions'

urlpatterns = [
    path('subscription-options/', views.subscription_options_list, name='subscription_options_list'),
    path('subscribe/<int:option_id>/', views.subscribe, name='subscribe'),
]
