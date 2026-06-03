from django.contrib import admin
from .models import ArcoTicket, MigrantRegistration, MigrantRegistrationSignature


@admin.register(MigrantRegistration)
class MigrantRegistrationAdmin(admin.ModelAdmin):
    list_display = ['pk', 'internal_id', 'gender', 'service_date', 'created_by', 'created_at', 'is_deleted']
    list_filter = ['is_deleted', 'gender', 'age_group', 'population_group']
    search_fields = ['internal_id']
    readonly_fields = ['created_at', 'updated_at', 'created_by', 'created_by_role']


@admin.register(MigrantRegistrationSignature)
class MigrantRegistrationSignatureAdmin(admin.ModelAdmin):
    list_display = ['pk', 'registration', 'curve_name', 'signed_by', 'signed_at']
    readonly_fields = ['signed_at']


@admin.register(ArcoTicket)
class ArcoTicketAdmin(admin.ModelAdmin):
    list_display = ['ticket_id', 'arco_request', 'state', 'created_by', 'created_at']
    list_filter = ['state', 'created_at']
    search_fields = ['ticket_id', 'arco_request__case_id']
    readonly_fields = ['ticket_id', 'created_at', 'updated_at']
    fieldsets = (
        ('Identificación', {'fields': ['ticket_id', 'arco_request']}),
        ('Estado', {'fields': ['state']}),
        ('Creación', {'fields': ['created_by', 'created_at']}),
        ('Revisión Coordinador', {'fields': ['coordinator_reviewed_by', 'coordinator_reviewed_at', 'coordinator_notes', 'coordinator_signature']}),
        ('Aprobación Admin', {'fields': ['admin_approved_by', 'admin_approved_at', 'admin_notes', 'admin_signature']}),
        ('Ejecución', {'fields': ['executed_at', 'rejection_reason', 'updated_at']}),
    )
