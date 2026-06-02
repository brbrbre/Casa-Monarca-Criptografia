from django.urls import path

from . import views

app_name = 'iam'

urlpatterns = [
    path('', views.dashboard_view, name='dashboard'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('users/add/', views.collaborator_create_view, name='user_add'),
    path('users/<int:pk>/created/', views.collaborator_created_view, name='collaborator_created'),
    path('users/<int:pk>/', views.collaborator_detail_view, name='detail'),
    path('users/<int:pk>/edit/', views.collaborator_edit_view, name='user_edit'),
    path('users/<int:pk>/toggle/', views.collaborator_toggle_view, name='user_toggle'),
    path('users/<int:pk>/revoke/', views.collaborator_revoke_view, name='user_revoke'),
    path('users/<int:pk>/delete/', views.collaborator_delete_view, name='user_delete'),
    path('users/<int:pk>/certificate/issue/', views.issue_certificate_view, name='certificate_issue'),
    path('users/<int:pk>/certificate/validate/', views.validate_certificate_view, name='certificate_validate'),
    path('users/<int:pk>/certificate/revoke/', views.revoke_certificate_view, name='certificate_revoke'),
    path('onboarding/', views.onboarding_view, name='onboarding'),
    path('onboarding/download/', views.onboarding_certificate_download_view, name='onboarding_download'),
    path('onboarding/download/key/', views.onboarding_key_download_view, name='onboarding_key_download'),
    path('onboarding/pending/', views.pending_onboarding_view, name='pending_onboarding'),
    path('users/<int:pk>/onboarding/approve/', views.approve_onboarding_view, name='approve_onboarding'),
    path('audit/', views.audit_log_view, name='audit_log'),
    path('recovery/', views.password_recovery_request_view, name='password_recovery_request'),
    path('recovery/answer/', views.password_recovery_answer_view, name='password_recovery_answer'),
    path('recovery/reset/', views.password_recovery_reset_view, name='password_recovery_reset'),
    path('password/change/', views.password_change_view, name='password_change'),
    path('security-question/', views.security_question_setup_view, name='security_question_setup'),
    path('api/user-role/', views.user_role_type_view, name='user_role_type'),
    # Certificate Management (admin-only)
    path('certificados/', views.certificate_mgmt_list_view, name='certificate_mgmt_list'),
    path('certificados/usuario/<int:user_id>/vincular/', views.certificate_mgmt_issue_view, name='certificate_mgmt_issue'),
    path('certificados/<int:cert_id>/', views.certificate_mgmt_detail_view, name='certificate_mgmt_detail'),
    path('certificados/<int:cert_id>/auditoria/', views.certificate_mgmt_audit_view, name='certificate_mgmt_audit'),
    path('certificados/<int:cert_id>/revocar/', views.certificate_mgmt_revoke_view, name='certificate_mgmt_revoke'),
    path('certificados/<int:cert_id>/suspender/', views.certificate_mgmt_suspend_view, name='certificate_mgmt_suspend'),
    path('certificados/<int:cert_id>/reactivar/', views.certificate_mgmt_reactivate_view, name='certificate_mgmt_reactivate'),
    path('certificados/<int:cert_id>/baja/', views.certificate_mgmt_deactivate_view, name='certificate_mgmt_deactivate'),
]
