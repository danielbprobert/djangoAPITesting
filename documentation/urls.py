from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name='documentation_index'),
    path('<slug:slug>/', views.section, name='documentation_section'),
]