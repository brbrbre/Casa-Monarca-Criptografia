from django.contrib import admin
from django.contrib.auth.admin import UserAdmin

from .models import Area, Collaborator, AuditLog, LoginAttempt


@admin.register(Area)
class AreaAdmin(admin.ModelAdmin):
    list_display = ('name', 'slug')
    prepopulated_fields = {'slug': ('name',)}


@admin.register(Collaborator)
class CollaboratorAdmin(UserAdmin):
    model = Collaborator
    list_display = ('username', 'email', 'get_full_name', 'access_level', 'area', 'is_active', 'is_revoked')
    list_filter = ('access_level', 'area', 'is_active', 'is_revoked', 'mfa_enabled')
    fieldsets = (
        (None, {'fields': ('username', 'password')}),
        ('Información personal', {'fields': ('first_name', 'last_name', 'email', 'phone', 'job_title')}),
        ('Identidad y acceso', {'fields': ('internal_id', 'area', 'access_level', 'role', 'onboarding_date', 'is_active', 'is_revoked', 'mfa_enabled')}),
        ('Metadatos', {'fields': ('created_by', 'revoked_by', 'revoked_at', 'deleted_at')}),
        ('Permisos', {'fields': ('is_staff', 'is_superuser', 'groups', 'user_permissions')}),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('username', 'email', 'password1', 'password2', 'access_level', 'area', 'role'),
        }),
    )
    search_fields = ('username', 'email', 'first_name', 'last_name')
    ordering = ('username',)


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ('created_at', 'actor', 'target', 'action')
    list_filter = ('action', 'created_at')
    search_fields = ('actor__username', 'target__username', 'details')


@admin.register(LoginAttempt)
class LoginAttemptAdmin(admin.ModelAdmin):
    list_display = ('created_at', 'username', 'ip_address', 'successful')
    list_filter = ('successful', 'created_at')
    search_fields = ('username', 'ip_address')
