from django.urls import path
from . import views

app_name = 'registros'

urlpatterns = [
    # ── Creation workflow ──────────────────────────────────────────────────────
    path('nuevo/',          views.registro_new,    name='registro_new'),
    path('nuevo/revisar/',  views.registro_review, name='registro_review'),
    path('<int:pk>/exito/', views.registro_exito,  name='registro_exito'),

    # ── CRUD ───────────────────────────────────────────────────────────────────
    path('',                    views.registro_list,   name='registro_list'),
    path('<int:pk>/',           views.registro_detail, name='registro_detail'),
    path('<int:pk>/editar/',    views.registro_edit,   name='registro_edit'),
    path('<int:pk>/eliminar/',  views.registro_delete, name='registro_delete'),

    # ── Crypto ─────────────────────────────────────────────────────────────────
    path('<int:pk>/verificar/', views.registro_verify,   name='registro_verify'),
    path('clave-publica/',      views.export_public_key, name='export_public_key'),
]
