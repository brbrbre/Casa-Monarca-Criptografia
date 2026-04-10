from django.urls import path

from . import views

app_name = 'iam'

urlpatterns = [
    path('', views.dashboard_view, name='dashboard'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('users/add/', views.collaborator_create_view, name='user_add'),
    path('users/<int:pk>/', views.collaborator_detail_view, name='detail'),
    path('users/<int:pk>/edit/', views.collaborator_edit_view, name='user_edit'),
    path('users/<int:pk>/toggle/', views.collaborator_toggle_view, name='user_toggle'),
    path('users/<int:pk>/delete/', views.collaborator_delete_view, name='user_delete'),
    path('audit/', views.audit_log_view, name='audit_log'),
]
