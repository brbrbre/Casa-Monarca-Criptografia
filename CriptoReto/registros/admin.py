from django.contrib import admin
from .models import MigrantRegistration, MigrantRegistrationSignature


@admin.register(MigrantRegistration)
class MigrantRegistrationAdmin(admin.ModelAdmin):
    list_display = ['pk', 'full_name', 'nationality', 'created_by', 'created_at', 'is_deleted']
    list_filter = ['is_deleted', 'gender', 'current_legal_status']
    search_fields = ['full_name', 'document_number', 'nationality']
    readonly_fields = ['created_at', 'updated_at', 'created_by', 'created_by_role']


@admin.register(MigrantRegistrationSignature)
class MigrantRegistrationSignatureAdmin(admin.ModelAdmin):
    list_display = ['pk', 'registration', 'curve_name', 'signed_by', 'signed_at']
    readonly_fields = ['signed_at']
