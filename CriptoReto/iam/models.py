import uuid
from datetime import timedelta

import pyotp
from django.contrib.auth.models import AbstractUser
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models
from django.utils import timezone
from django.urls import reverse


class Area(models.Model):
    slug = models.SlugField(max_length=32, unique=True)
    name = models.CharField(max_length=64)
    description = models.TextField(blank=True)

    class Meta:
        ordering = ['name']
        verbose_name = 'Área'
        verbose_name_plural = 'Áreas'

    def __str__(self):
        return self.name


class Collaborator(AbstractUser):
    ACCESS_LEVEL_CHOICES = [
        (1, 'Administración (Nivel 1)'),
        (2, 'Coordinador (Nivel 2)'),
        (3, 'Operativo (Nivel 3)'),
        (4, 'Externo (Nivel 4)'),
    ]

    ROLE_CHOICES = [
        ('Administrador IT', 'Administrador IT'),
        ('Coordinador Legal', 'Coordinador Legal'),
        ('Coordinador Humanitario', 'Coordinador Humanitario'),
        ('Operativo Humanitario', 'Operativo Humanitario'),
        ('Psicólogo', 'Psicólogo'),
        ('Comunicación', 'Comunicación'),
        ('Almacén', 'Almacén'),
        ('Personal Externo', 'Personal Externo'),
    ]

    email = models.EmailField('Correo institucional', unique=True)
    phone = models.CharField('Teléfono', max_length=32, blank=True)
    area = models.ForeignKey(
        Area,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='collaborators',
        verbose_name='Área',
    )
    access_level = models.PositiveSmallIntegerField(
        'Nivel de acceso',
        choices=ACCESS_LEVEL_CHOICES,
        default=4,
        validators=[MinValueValidator(1), MaxValueValidator(4)],
        db_index=True,
    )
    role = models.CharField('Rol', max_length=64, choices=ROLE_CHOICES, blank=True)
    job_title = models.CharField('Puesto', max_length=128, blank=True)
    onboarding_date = models.DateField('Fecha de ingreso', null=True, blank=True)
    internal_id = models.CharField('Identificador interno', max_length=32, unique=True, blank=True)
    is_revoked = models.BooleanField('Acceso revocado', default=False)
    revoked_at = models.DateTimeField('Fecha de revocación', null=True, blank=True)
    revoked_by = models.ForeignKey(
        'self',
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='revoked_users',
        verbose_name='Revocado por',
    )
    created_by = models.ForeignKey(
        'self',
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='created_users',
        verbose_name='Creado por',
    )
    created_at = models.DateTimeField('Fecha de creación', auto_now_add=True)
    is_deleted = models.BooleanField('Eliminado lógicamente', default=False)
    deleted_at = models.DateTimeField('Fecha de eliminación', null=True, blank=True)
    totp_secret = models.CharField('TOTP secreto', max_length=64, blank=True)
    mfa_enabled = models.BooleanField('MFA activo', default=False)

    USERNAME_FIELD = 'username'
    EMAIL_FIELD = 'email'
    REQUIRED_FIELDS = ['email']

    class Meta:
        verbose_name = 'Colaborador'
        verbose_name_plural = 'Colaboradores'
        ordering = ['last_name', 'first_name']

    def __str__(self):
        return f'{self.get_full_name() or self.username}'

    def save(self, *args, **kwargs):
        if not self.internal_id:
            self.internal_id = f'CM-{uuid.uuid4().hex[:8].upper()}'
        if self.mfa_enabled and not self.totp_secret:
            self.totp_secret = pyotp.random_base32()
        super().save(*args, **kwargs)

    def get_absolute_url(self):
        return reverse('iam:detail', kwargs={'pk': self.pk})

    def is_system_admin(self):
        return self.access_level == 1

    def can_view(self, target: 'Collaborator'):
        if self.is_system_admin():
            return True
        if self == target:
            return True
        if self.access_level in (2, 3) and self.area and target.area == self.area:
            return True
        return False

    def can_edit(self, target: 'Collaborator'):
        if self.is_system_admin():
            return True
        if self == target:
            return False
        if self.access_level == 2 and self.area and target.area == self.area and target.access_level >= 3:
            return True
        return False

    def can_delete(self, target: 'Collaborator'):
        return self.can_edit(target)

    def can_activate(self, target: 'Collaborator'):
        return self.can_edit(target)

    def status_label(self):
        if self.is_deleted:
            return 'Eliminado'
        if self.is_revoked:
            return 'Revocado'
        if not self.is_active:
            return 'Inactivo'
        return 'Activo'

    def verify_totp(self, token: str) -> bool:
        if not self.mfa_enabled or not self.totp_secret:
            return False
        try:
            return pyotp.TOTP(self.totp_secret).verify(str(token), valid_window=1)
        except Exception:
            return False

    def totp_provisioning_uri(self):
        if not self.totp_secret:
            self.totp_secret = pyotp.random_base32()
            self.save(update_fields=['totp_secret'])
        return pyotp.totp.TOTP(self.totp_secret).provisioning_uri(
            name=self.email or self.username,
            issuer_name='Casa Monarca',
        )


class AuditLog(models.Model):
    actor = models.ForeignKey(
        Collaborator,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='actor_logs',
        verbose_name='Actor',
    )
    target = models.ForeignKey(
        Collaborator,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='target_logs',
        verbose_name='Usuario objetivo',
    )
    action = models.CharField('Acción', max_length=128)
    details = models.TextField('Detalles', blank=True)
    created_at = models.DateTimeField('Fecha y hora', auto_now_add=True)

    class Meta:
        ordering = ['-created_at']
        verbose_name = 'Registro de auditoría'
        verbose_name_plural = 'Registros de auditoría'

    def __str__(self):
        return f'{self.created_at:%Y-%m-%d %H:%M} - {self.action}'


class LoginAttempt(models.Model):
    username = models.CharField('Nombre de usuario', max_length=150)
    ip_address = models.GenericIPAddressField('IP', null=True, blank=True)
    successful = models.BooleanField('Éxito', default=False)
    created_at = models.DateTimeField('Fecha y hora', auto_now_add=True)

    class Meta:
        ordering = ['-created_at']
        verbose_name = 'Intento de acceso'
        verbose_name_plural = 'Intentos de acceso'

    @classmethod
    def recent_failed_count(cls, username: str, minutes: int = 15) -> int:
        window = timezone.now() - timedelta(minutes=minutes)
        return cls.objects.filter(username__iexact=username, successful=False, created_at__gte=window).count()

    @classmethod
    def is_blocked(cls, username: str, threshold: int = 5, minutes: int = 15) -> bool:
        return cls.recent_failed_count(username, minutes=minutes) >= threshold
