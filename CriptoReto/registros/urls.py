from django.urls import path
from . import views

app_name = 'registros'

urlpatterns = [
    # ── Creation workflow ──────────────────────────────────────────────────────
    path('nuevo/',          views.registro_new,    name='registro_new'),
    path('nuevo/revisar/',  views.registro_review, name='registro_review'),
    path('<int:pk>/exito/', views.registro_exito,  name='registro_exito'),

    # ── CRUD ───────────────────────────────────────────────────────────────────
    path('',                             views.registro_list,         name='registro_list'),
    path('eliminados/',                  views.registro_deleted_list, name='registro_deleted_list'),
    path('<int:pk>/',                    views.registro_detail,       name='registro_detail'),
    path('<int:pk>/editar/',             views.registro_edit,         name='registro_edit'),
    path('<int:pk>/eliminar/',           views.registro_delete,       name='registro_delete'),
    path('<int:pk>/expediente/',         views.registro_expediente,   name='registro_expediente'),

    # ── Crypto ─────────────────────────────────────────────────────────────────
    path('<int:pk>/verificar/', views.registro_verify,   name='registro_verify'),
    path('clave-publica/',      views.export_public_key, name='export_public_key'),

    # ── Approval workflow ──────────────────────────────────────────────────────
    # batch-sign must come before <int:pk>/workflow/ to avoid ambiguity
    path('workflow/batch-sign/',          views.batch_sign_view,          name='batch_sign'),
    path('workflow/',                     views.workflow_list,            name='workflow_list'),
    path('workflow/<int:pk>/',            views.workflow_detail,          name='workflow_detail'),
    path('workflow/<int:pk>/decide/',     views.workflow_decide,          name='workflow_decide'),
    path('workflow/<int:pk>/execute/',    views.workflow_execute,         name='workflow_execute'),
    path('workflow/<int:pk>/registro/',   views.workflow_registration_preview, name='workflow_registration_preview'),
    path('<int:pk>/workflow/<str:action>/', views.workflow_request_create, name='workflow_request_create'),

    # ── ARCO rights ────────────────────────────────────────────────────────────
    path('arco/',                         views.arco_list,     name='arco_list'),
    path('<int:pk>/arco/nueva/',          views.arco_create,   name='arco_create'),
    path('arco/<int:pk>/',               views.arco_detail,   name='arco_detail'),
    path('arco/<int:pk>/ejecutar/',       views.arco_execute,  name='arco_execute'),
    path('arco/<int:pk>/descargar/',      views.arco_download, name='arco_download'),

    # ── Audit chain ────────────────────────────────────────────────────────────
    path('cadena/', views.chain_audit_view, name='chain_audit'),

    # ── Notifications ──────────────────────────────────────────────────────────
    path('notificaciones/marcar-leidas/', views.notifications_mark_read, name='notifications_mark_read'),

    # ── Tickets ────────────────────────────────────────────────────────────────
    path('tickets/',              views.ticket_list,   name='ticket_list'),
    path('tickets/<str:ticket_id>/', views.ticket_detail, name='ticket_detail'),
]
