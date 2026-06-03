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

    ONBOARDING_STATUS_PENDING = 'pending'
    ONBOARDING_STATUS_SUBMITTED = 'submitted'
    ONBOARDING_STATUS_APPROVED = 'approved'
    ONBOARDING_STATUS_REJECTED = 'rejected'
    ONBOARDING_STATUS_CHOICES = [
        (ONBOARDING_STATUS_PENDING, 'Pendiente'),
        (ONBOARDING_STATUS_SUBMITTED, 'Enviado'),
        (ONBOARDING_STATUS_APPROVED, 'Aprobado'),
        (ONBOARDING_STATUS_REJECTED, 'Rechazado'),
    ]

    onboarding_status = models.CharField(
        'Estado de onboarding',
        max_length=16,
        choices=ONBOARDING_STATUS_CHOICES,
        default=ONBOARDING_STATUS_PENDING,
    )
    onboarding_requested_at = models.DateTimeField('Solicitado el', auto_now_add=True)
    onboarding_submitted_at = models.DateTimeField('Formulario enviado el', null=True, blank=True)
    onboarding_approved_at = models.DateTimeField('Aprobado el', null=True, blank=True)
    onboarding_approved_by = models.ForeignKey(
        'self',
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='approved_onboardings',
        verbose_name='Aprobado por',
    )
    official_id_document = models.FileField(
        'Identificación oficial',
        upload_to='official_ids/',
        null=True,
        blank=True,
    )
    certificate_delivered_at = models.DateTimeField('Certificado entregado', null=True, blank=True)
    cert_file_downloaded = models.BooleanField('.cert descargado', default=False)
    key_file_downloaded = models.BooleanField('.key descargado', default=False)
    is_deleted = models.BooleanField('Eliminado lógicamente', default=False)
    deleted_at = models.DateTimeField('Fecha de eliminación', null=True, blank=True)
    totp_secret = models.CharField('TOTP secreto', max_length=64, blank=True)
    mfa_enabled = models.BooleanField('MFA activo', default=False)

    ADMIN_TYPE_PRODUCTION = 'production'
    ADMIN_TYPE_CONTINGENCY = 'contingency'
    ADMIN_TYPE_CHOICES = [
        (ADMIN_TYPE_PRODUCTION, 'Producción'),
        (ADMIN_TYPE_CONTINGENCY, 'Contingencias'),
    ]
    admin_type = models.CharField(
        'Tipo de cuenta admin',
        max_length=16,
        choices=ADMIN_TYPE_CHOICES,
        blank=True,
    )

    SECURITY_QUESTIONS = [
        ('mascota', '¿Cuál fue el nombre de tu primera mascota?'),
        ('comida', '¿Cuál es tu comida favorita?'),
        ('heroe', '¿Cuál fue el nombre de tu héroe de la infancia?'),
        ('apodo', '¿Cuál era tu apodo de infancia?'),
        ('deporte', '¿Cuál es tu deporte favorito?'),
        ('ciudad', '¿En qué ciudad naciste?'),
        ('amigo', '¿Cuál es el nombre de tu mejor amigo de la infancia?'),
        ('escuela', '¿Cuál fue el nombre de tu escuela primaria?'),
    ]
    security_question = models.CharField('Pregunta de seguridad', max_length=16, choices=SECURITY_QUESTIONS, blank=True)
    security_answer_hash = models.CharField('Respuesta de seguridad', max_length=256, blank=True)

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

    def can_issue_certificate(self, target: 'Collaborator'):
        """Only Level 1 admins may issue or reissue certificates."""
        return self.access_level == 1

    def can_revoke_certificate(self, target: 'Collaborator'):
        """Only Level 1 admins may revoke certificates."""
        return self.access_level == 1

    def can_view_audit(self, target: 'Collaborator' = None):
        """Level 1 sees all audit. Level 2 sees own area. Level 3/4 have no audit access."""
        if self.access_level == 1:
            return True
        if self.access_level == 2 and target and target.area == self.area:
            return True
        return False

    def status_label(self):
        if self.is_deleted:
            return 'Eliminado'
        if self.is_revoked:
            return 'Revocado'
        if self.onboarding_status == self.ONBOARDING_STATUS_PENDING:
            return 'Pendiente'
        if self.onboarding_status == self.ONBOARDING_STATUS_SUBMITTED:
            return 'Enviado'
        if self.onboarding_status == self.ONBOARDING_STATUS_REJECTED:
            return 'Rechazado'
        if not self.is_active:
            return 'Inactivo'
        if self.access_level <= 2:
            try:
                cert = self.certificate
                if cert.status == 'SUSPENDED':
                    return 'Activo — Cert. Suspendido'
                if cert.status == 'REVOKED':
                    return 'Activo — Cert. Revocado'
                if cert.status == 'INACTIVE':
                    return 'Activo — Cert. Baja'
            except Exception:
                pass
        return 'Activo'

    @property
    def onboarding_pending(self):
        return self.onboarding_status == self.ONBOARDING_STATUS_PENDING

    @property
    def onboarding_submitted(self):
        return self.onboarding_status == self.ONBOARDING_STATUS_SUBMITTED

    @property
    def onboarding_approved(self):
        return self.onboarding_status == self.ONBOARDING_STATUS_APPROVED

    @property
    def onboarding_rejected(self):
        return self.onboarding_status == self.ONBOARDING_STATUS_REJECTED

    @property
    def onboarding_ready_for_certificate(self):
        return self.onboarding_status == self.ONBOARDING_STATUS_APPROVED and self.certificate_delivered_at is None

    @property
    def onboarding_complete(self):
        """True when the collaborator has submitted all required onboarding data."""
        return (
            self.onboarding_status == self.ONBOARDING_STATUS_SUBMITTED
            and bool(self.first_name.strip())
            and bool(self.last_name.strip())
            and bool(self.official_id_document)
            and bool(self.security_question)
            and bool(self.security_answer_hash)
        )

    def set_security_answer(self, answer: str):
        from django.contrib.auth.hashers import make_password
        self.security_answer_hash = make_password(answer.strip().lower())

    def check_security_answer(self, answer: str) -> bool:
        from django.contrib.auth.hashers import check_password
        if not self.security_answer_hash:
            return False
        return check_password(answer.strip().lower(), self.security_answer_hash)

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


class UserCertificate(models.Model):
    STATUS_ACTIVE = 'ACTIVE'
    STATUS_SUSPENDED = 'SUSPENDED'
    STATUS_REVOKED = 'REVOKED'
    STATUS_INACTIVE = 'INACTIVE'
    STATUS_EXPIRED = 'EXPIRED'
    STATUS_CHOICES = [
        (STATUS_ACTIVE, 'Activo'),
        (STATUS_SUSPENDED, 'Suspendido'),
        (STATUS_REVOKED, 'Revocado'),
        (STATUS_INACTIVE, 'Inactivo'),
        (STATUS_EXPIRED, 'Expirado'),
    ]

    collaborator = models.OneToOneField(
        Collaborator,
        on_delete=models.PROTECT,
        related_name='certificate',
        verbose_name='Colaborador',
    )
    certificate_data = models.TextField('Datos del certificado encriptado')
    fingerprint = models.CharField('Huella digital', max_length=64, unique=True)
    issued_at = models.DateTimeField('Fecha de emisión', auto_now_add=True)
    expires_at = models.DateTimeField('Fecha de expiración')
    is_revoked = models.BooleanField('Certificado revocado', default=False)
    revoked_at = models.DateTimeField('Fecha de revocación', null=True, blank=True)
    revoked_by = models.ForeignKey(
        Collaborator,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='certificates_revoked',
        verbose_name='Revocado por',
    )
    issued_by = models.ForeignKey(
        Collaborator,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='certificates_issued',
        verbose_name='Emitido por',
    )
    # Only populated for coordinators: AES-GCM encrypted PKCS#8 DER private key.
    key_data = models.TextField('Llave privada cifrada', blank=True)

    # ── Certificate lifecycle management fields ──────────────────────────────
    status = models.CharField(
        'Estado', max_length=16, choices=STATUS_CHOICES, default=STATUS_ACTIVE, db_index=True,
    )
    serial_number = models.CharField('Número de serie', max_length=128, blank=True)
    revocation_reason = models.TextField('Motivo de revocación', blank=True)
    suspended_at = models.DateTimeField('Fecha de suspensión', null=True, blank=True)
    suspended_by = models.ForeignKey(
        Collaborator,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='certificates_suspended',
        verbose_name='Suspendido por',
    )
    suspension_reason = models.TextField('Motivo de suspensión', blank=True)
    deactivated_at = models.DateTimeField('Fecha de baja', null=True, blank=True)
    deactivated_by = models.ForeignKey(
        Collaborator,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='certificates_deactivated',
        verbose_name='Dado de baja por',
    )
    deactivation_reason = models.TextField('Motivo de baja', blank=True)

    class Meta:
        verbose_name = 'Certificado de usuario'
        verbose_name_plural = 'Certificados de usuario'

    @property
    def is_valid(self):
        if self.is_revoked:
            return False
        if self.status in (self.STATUS_REVOKED, self.STATUS_SUSPENDED, self.STATUS_INACTIVE):
            return False
        return self.expires_at > timezone.now()

    @property
    def effective_status(self):
        if self.status == self.STATUS_ACTIVE and self.expires_at <= timezone.now():
            return self.STATUS_EXPIRED
        return self.status

    @property
    def effective_status_display(self):
        return dict(self.STATUS_CHOICES).get(self.effective_status, self.effective_status)

    def __str__(self):
        return f'Certificate({self.collaborator.username} | {self.fingerprint[:12]})'


class CertificateAuditLog(models.Model):
    ACTION_ISSUED = 'ISSUED'
    ACTION_REVOKED = 'REVOKED'
    ACTION_SUSPENDED = 'SUSPENDED'
    ACTION_REACTIVATED = 'REACTIVATED'
    ACTION_DEACTIVATED = 'DEACTIVATED'

    certificate = models.ForeignKey(
        UserCertificate,
        on_delete=models.PROTECT,
        related_name='cert_audit_logs',
        verbose_name='Certificado',
    )
    action = models.CharField('Acción', max_length=32)
    performed_by = models.ForeignKey(
        Collaborator,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='cert_audit_actions',
        verbose_name='Realizado por',
    )
    timestamp = models.DateTimeField('Fecha y hora', auto_now_add=True)
    previous_status = models.CharField('Estado anterior', max_length=16, blank=True)
    new_status = models.CharField('Estado nuevo', max_length=16, blank=True)
    metadata = models.JSONField('Metadatos', default=dict, blank=True)

    class Meta:
        ordering = ['-timestamp']
        verbose_name = 'Auditoría de certificado'
        verbose_name_plural = 'Auditorías de certificados'

    def save(self, *args, **kwargs):
        if self.pk:
            return  # append-only: never update
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise PermissionError('Los registros de auditoría no se pueden eliminar.')

    def __str__(self):
        return f'{self.timestamp:%Y-%m-%d %H:%M} — {self.action}'


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
