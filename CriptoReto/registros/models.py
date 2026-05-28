import hashlib
import json

from django.conf import settings
from django.db import models
from django.utils import timezone

# Version string for the current privacy notice text.
# Bump this whenever the notice is amended.
PRIVACY_NOTICE_VERSION = '1.0'


class MigrantRegistration(models.Model):
    GENDER_CHOICES = [
        ('masculino', 'Masculino'),
        ('femenino', 'Femenino'),
        ('no_binario', 'No binario'),
        ('prefiero_no_decir', 'Prefiero no decir'),
    ]

    DOCUMENT_TYPE_CHOICES = [
        ('pasaporte', 'Pasaporte'),
        ('id_nacional', 'Identificación nacional'),
        ('acta_nacimiento', 'Acta de nacimiento'),
        ('visa', 'Visa'),
        ('sin_documentos', 'Sin documentos'),
        ('otro', 'Otro'),
    ]

    MARITAL_STATUS_CHOICES = [
        ('soltero', 'Soltero/a'),
        ('casado', 'Casado/a'),
        ('union_libre', 'Unión libre'),
        ('divorciado', 'Divorciado/a'),
        ('viudo', 'Viudo/a'),
    ]

    LEGAL_STATUS_CHOICES = [
        ('solicitante_asilo', 'Solicitante de asilo'),
        ('refugiado_reconocido', 'Refugiado reconocido'),
        ('migrante_regular', 'Migrante en situación regular'),
        ('migrante_irregular', 'Migrante en situación irregular'),
        ('desconoce', 'Desconoce su situación'),
    ]

    ASSISTANCE_CHOICES = [
        ('legal', 'Asesoría legal'),
        ('medica', 'Atención médica'),
        ('alimentaria', 'Apoyo alimentario'),
        ('alojamiento', 'Alojamiento temporal'),
        ('psicologica', 'Apoyo psicológico'),
        ('educacion', 'Servicios educativos'),
        ('laboral', 'Apoyo laboral'),
        ('documentacion', 'Gestión documental'),
        ('transporte', 'Apoyo de transporte'),
        ('otro', 'Otro'),
    ]

    # ── Personal ──────────────────────────────────────────────────────────────
    full_name = models.CharField('Nombre completo', max_length=255)
    birth_date = models.DateField('Fecha de nacimiento')
    gender = models.CharField('Género', max_length=20, choices=GENDER_CHOICES)
    nationality = models.CharField('Nacionalidad', max_length=100)
    country_of_origin = models.CharField('País de origen', max_length=100)
    document_type = models.CharField('Tipo de documento', max_length=30, choices=DOCUMENT_TYPE_CHOICES)
    document_number = models.CharField('Número de documento', max_length=100, blank=True)

    # ── Contact ───────────────────────────────────────────────────────────────
    phone = models.CharField('Teléfono', max_length=20, blank=True)
    email = models.EmailField('Correo electrónico', blank=True)

    # ── Entry ─────────────────────────────────────────────────────────────────
    entry_date = models.DateField('Fecha de ingreso al país')
    entry_point = models.CharField('Punto de ingreso', max_length=200)
    transit_countries = models.TextField('Países de tránsito', blank=True)
    intended_destination = models.CharField('Destino final deseado', max_length=200, blank=True)

    # ── Family / Group ────────────────────────────────────────────────────────
    marital_status = models.CharField('Estado civil', max_length=20, choices=MARITAL_STATUS_CHOICES)
    travels_alone = models.BooleanField('Viaja solo/a', default=True)
    group_size = models.PositiveSmallIntegerField('Personas en el grupo', default=1)
    minors_in_group = models.PositiveSmallIntegerField('Menores en el grupo', default=0)

    # ── Needs ─────────────────────────────────────────────────────────────────
    assistance_requested = models.CharField('Tipo de asistencia solicitada', max_length=500)
    migration_reason = models.TextField('Motivo de migración')
    current_legal_status = models.CharField(
        'Situación migratoria actual', max_length=30, choices=LEGAL_STATUS_CHOICES,
    )
    shelter_name = models.CharField('Nombre del albergue/alojamiento', max_length=200, blank=True)

    # ── Emergency contact ─────────────────────────────────────────────────────
    emergency_contact_name = models.CharField('Nombre del contacto de emergencia', max_length=255)
    emergency_contact_phone = models.CharField('Teléfono del contacto de emergencia', max_length=20)
    emergency_contact_relationship = models.CharField(
        'Parentesco del contacto de emergencia', max_length=100,
    )

    # ── Additional ────────────────────────────────────────────────────────────
    observations = models.TextField('Observaciones adicionales', blank=True)
    data_consent = models.BooleanField('Consentimiento de tratamiento de datos personales', default=False)

    # ── Privacy consent audit trail ───────────────────────────────────────────
    privacy_accepted_at = models.DateTimeField('Consentimiento aceptado el', null=True, blank=True)
    privacy_accepted_ip = models.GenericIPAddressField('IP de aceptación', null=True, blank=True)
    privacy_notice_version = models.CharField(
        'Versión del aviso de privacidad', max_length=10, default=PRIVACY_NOTICE_VERSION,
    )

    # ── Metadata ──────────────────────────────────────────────────────────────
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name='registrations_created',
        verbose_name='Creado por',
    )
    created_by_role = models.PositiveSmallIntegerField('Nivel de acceso del creador')
    created_at = models.DateTimeField('Fecha de creación', auto_now_add=True)
    updated_at = models.DateTimeField('Última actualización', auto_now=True)
    is_deleted = models.BooleanField('Eliminado', default=False)
    deleted_at = models.DateTimeField('Fecha de eliminación', null=True, blank=True)
    deleted_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='registrations_deleted',
        verbose_name='Eliminado por',
    )

    class Meta:
        verbose_name = 'Registro migrante'
        verbose_name_plural = 'Registros migrantes'
        ordering = ['-created_at']

    def __str__(self):
        return f'{self.full_name} — #{self.pk}'

    def get_assistance_list(self):
        label_map = dict(self.ASSISTANCE_CHOICES)
        return [label_map.get(k.strip(), k.strip()) for k in self.assistance_requested.split(',') if k.strip()]

    def soft_delete(self, user):
        self.is_deleted = True
        self.deleted_at = timezone.now()
        self.deleted_by = user
        self.save(update_fields=['is_deleted', 'deleted_at', 'deleted_by'])


class MigrantRegistrationSignature(models.Model):
    registration = models.OneToOneField(
        MigrantRegistration,
        on_delete=models.PROTECT,
        related_name='signature',
        verbose_name='Registro',
    )
    message_hash = models.CharField('Hash SHA-256 del mensaje', max_length=64)
    signature_r = models.TextField('Componente R de la firma ECDSA')
    signature_s = models.TextField('Componente S de la firma ECDSA')
    public_key = models.TextField('Clave pública (PEM)')
    curve_name = models.CharField('Curva elíptica', max_length=50)
    signed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name='signatures_made',
        verbose_name='Firmado por',
    )
    signed_by_role = models.PositiveSmallIntegerField('Nivel de acceso del firmante')
    signed_at = models.DateTimeField('Fecha de firma', auto_now_add=True)

    class Meta:
        verbose_name = 'Firma digital'
        verbose_name_plural = 'Firmas digitales'

    def __str__(self):
        return f'Firma #{self.pk} — Registro #{self.registration_id}'


# ══════════════════════════════════════════════════════════════════════════════
# GENERAL-PURPOSE ACTION SIGNATURE  (hash-chained ledger)
# ══════════════════════════════════════════════════════════════════════════════

class ActionSignature(models.Model):
    """
    ECDSA signature for any platform action (workflow step, ARCO, batch).

    Each entry chains to the previous via prev_chain_hash, building an
    append-only cryptographic ledger.  Modifying any earlier entry breaks
    every subsequent hash in the chain.
    """

    SUBJECT_REGISTRATION = 'registration'
    SUBJECT_WORKFLOW_STEP = 'workflow_step'
    SUBJECT_ARCO = 'arco_request'
    SUBJECT_BATCH_ITEM = 'batch_item'

    SUBJECT_CHOICES = [
        (SUBJECT_REGISTRATION, 'Registro migrante'),
        (SUBJECT_WORKFLOW_STEP, 'Paso de aprobación'),
        (SUBJECT_ARCO, 'Solicitud ARCO'),
        (SUBJECT_BATCH_ITEM, 'Elemento de firma masiva'),
    ]

    subject_type = models.CharField('Tipo de sujeto', max_length=20, choices=SUBJECT_CHOICES)
    subject_id = models.PositiveIntegerField('ID del sujeto')

    message_hash = models.CharField('Hash del payload', max_length=64)
    signature_r = models.TextField('Firma R')
    signature_s = models.TextField('Firma S')
    public_key = models.TextField('Clave pública (PEM)')
    curve_name = models.CharField('Curva', max_length=50, default='secp256k1')

    # ── Hash chain ────────────────────────────────────────────────────────────
    # SHA-256 of the previous ActionSignature's canonical JSON representation.
    # Empty string for the genesis (first) entry.
    prev_chain_hash = models.CharField('Hash del eslabón anterior', max_length=64, blank=True)
    chain_position = models.PositiveIntegerField('Posición en la cadena', default=0)

    # ── Signer ────────────────────────────────────────────────────────────────
    signed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name='action_signatures',
        verbose_name='Firmado por',
    )
    signed_by_role = models.PositiveSmallIntegerField('Nivel del firmante')
    signed_at = models.DateTimeField('Firmado el', auto_now_add=True)

    # ── Batch reference ───────────────────────────────────────────────────────
    batch = models.ForeignKey(
        'BatchSignSession',
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='signatures',
        verbose_name='Sesión de firma masiva',
    )

    class Meta:
        verbose_name = 'Firma de acción'
        verbose_name_plural = 'Firmas de acciones'
        ordering = ['chain_position', 'id']

    def __str__(self):
        return f'ActionSig #{self.pk} ({self.subject_type}:{self.subject_id}) pos={self.chain_position}'

    def to_canonical_dict(self) -> dict:
        """Deterministic dict used when computing the next entry's prev_chain_hash."""
        return {
            'id': self.pk,
            'subject_type': self.subject_type,
            'subject_id': self.subject_id,
            'message_hash': self.message_hash,
            'signature_r': self.signature_r,
            'signature_s': self.signature_s,
            'curve_name': self.curve_name,
            'chain_position': self.chain_position,
            'prev_chain_hash': self.prev_chain_hash,
            'signed_by_id': self.signed_by_id,
            'signed_at': self.signed_at.isoformat() if self.signed_at else '',
        }

    def chain_hash(self) -> str:
        payload = json.dumps(self.to_canonical_dict(), sort_keys=True, ensure_ascii=False)
        return hashlib.sha256(payload.encode('utf-8')).hexdigest()


class BatchSignSession(models.Model):
    """
    Records a single password-confirmation event that produced N independent signatures.

    This avoids requiring separate password re-entry for every item in a batch
    while still maintaining a per-item audit trail.
    """
    signed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name='batch_sessions',
        verbose_name='Operador',
    )
    signed_at = models.DateTimeField('Firmado el', auto_now_add=True)
    ip_address = models.GenericIPAddressField('IP', null=True, blank=True)
    item_count = models.PositiveIntegerField('Número de elementos firmados')
    batch_root_hash = models.CharField('Hash raíz del lote', max_length=64)

    class Meta:
        verbose_name = 'Sesión de firma masiva'
        verbose_name_plural = 'Sesiones de firma masiva'

    def __str__(self):
        return f'Batch #{self.pk} — {self.item_count} firmas — {self.signed_by}'


# ══════════════════════════════════════════════════════════════════════════════
# WORKFLOW — approval chain
# ══════════════════════════════════════════════════════════════════════════════

class WorkflowRequest(models.Model):
    """
    Represents any action that requires hierarchical approval before execution.

    Escalation rules (defined in workflow.py):
      • Voluntario (4) UPDATE  → Operativo (3) approves → Coordinador (2) executes
      • Any level    DELETE   → escalates until Admin (1) executes
      • ARCO Cancelación      → escalates to Admin (1)
    """

    # ── Action types ──────────────────────────────────────────────────────────
    ACTION_UPDATE_REGISTRATION = 'update_registration'
    ACTION_DELETE_REGISTRATION = 'delete_registration'
    ACTION_ARCO_ACCESS = 'arco_access'
    ACTION_ARCO_RECTIFICATION = 'arco_rectification'
    ACTION_ARCO_CANCELLATION = 'arco_cancellation'
    ACTION_ARCO_OPPOSITION = 'arco_opposition'

    ACTION_CHOICES = [
        (ACTION_UPDATE_REGISTRATION, 'Actualizar Registro'),
        (ACTION_DELETE_REGISTRATION, 'Eliminar Registro'),
        (ACTION_ARCO_ACCESS, 'ARCO — Acceso'),
        (ACTION_ARCO_RECTIFICATION, 'ARCO — Rectificación'),
        (ACTION_ARCO_CANCELLATION, 'ARCO — Cancelación'),
        (ACTION_ARCO_OPPOSITION, 'ARCO — Oposición'),
    ]

    # ── States ────────────────────────────────────────────────────────────────
    STATE_SUBMITTED = 'submitted'
    STATE_PENDING_REVIEW = 'pending_review'
    STATE_ESCALATED = 'escalated'
    STATE_APPROVED = 'approved'
    STATE_REJECTED = 'rejected'
    STATE_SIGNED = 'signed'
    STATE_EXECUTED = 'executed'

    STATE_CHOICES = [
        (STATE_SUBMITTED, 'Enviado'),
        (STATE_PENDING_REVIEW, 'En revisión'),
        (STATE_ESCALATED, 'Escalado al nivel superior'),
        (STATE_APPROVED, 'Aprobado'),
        (STATE_REJECTED, 'Rechazado'),
        (STATE_SIGNED, 'Firmado digitalmente'),
        (STATE_EXECUTED, 'Ejecutado'),
    ]

    action_type = models.CharField('Tipo de acción', max_length=30, choices=ACTION_CHOICES)
    state = models.CharField('Estado', max_length=20, choices=STATE_CHOICES, default=STATE_SUBMITTED, db_index=True)

    # ── Requester ─────────────────────────────────────────────────────────────
    requested_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name='workflow_requests_made',
        verbose_name='Solicitado por',
    )
    requested_by_role = models.PositiveSmallIntegerField('Nivel del solicitante')

    # ── Target ────────────────────────────────────────────────────────────────
    registration = models.ForeignKey(
        MigrantRegistration,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='workflow_requests',
        verbose_name='Registro afectado',
    )

    # ── Payload ───────────────────────────────────────────────────────────────
    # JSON with the proposed changes (for UPDATE) or the reason (for DELETE/ARCO)
    payload = models.JSONField('Datos de la solicitud', default=dict)
    notes = models.TextField('Notas del solicitante', blank=True)

    # ── Approval routing ──────────────────────────────────────────────────────
    # Level required to act on this request right now (decrements as approved)
    current_approver_level = models.PositiveSmallIntegerField('Nivel aprobador actual')
    # Levels still pending (JSON list, e.g. [3, 2] means Operativo then Coordinador)
    pending_levels = models.JSONField('Niveles pendientes', default=list)

    # ── Signature ─────────────────────────────────────────────────────────────
    action_signature = models.OneToOneField(
        ActionSignature,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='workflow_request',
        verbose_name='Firma de acción',
    )

    created_at = models.DateTimeField('Creado el', auto_now_add=True)
    updated_at = models.DateTimeField('Actualizado el', auto_now=True)

    class Meta:
        verbose_name = 'Solicitud de flujo'
        verbose_name_plural = 'Solicitudes de flujo'
        ordering = ['-created_at']

    def __str__(self):
        return f'WF#{self.pk} {self.get_action_type_display()} [{self.get_state_display()}]'

    def is_pending_for(self, user) -> bool:
        return self.state in (self.STATE_SUBMITTED, self.STATE_PENDING_REVIEW, self.STATE_ESCALATED) \
               and self.current_approver_level == user.access_level

    def can_approve(self, user) -> bool:
        return user.access_level <= self.current_approver_level and self.is_pending_for(user)


class ApprovalStep(models.Model):
    """
    Immutable audit record of one actor's decision on a WorkflowRequest.
    Each step includes a hash chain link to prevent tampering.
    """

    ACTION_APPROVED = 'approved'
    ACTION_REJECTED = 'rejected'
    ACTION_ESCALATED = 'escalated'

    ACTION_CHOICES = [
        (ACTION_APPROVED, 'Aprobado'),
        (ACTION_REJECTED, 'Rechazado'),
        (ACTION_ESCALATED, 'Escalado'),
    ]

    request = models.ForeignKey(
        WorkflowRequest,
        on_delete=models.PROTECT,
        related_name='approval_steps',
        verbose_name='Solicitud',
    )
    action = models.CharField('Decisión', max_length=20, choices=ACTION_CHOICES)
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name='approval_steps',
        verbose_name='Actor',
    )
    actor_role = models.PositiveSmallIntegerField('Nivel del actor')
    notes = models.TextField('Notas', blank=True)

    # ── Hash chain ────────────────────────────────────────────────────────────
    step_hash = models.CharField('Hash de este paso', max_length=64, blank=True)
    prev_step_hash = models.CharField('Hash del paso anterior', max_length=64, blank=True)

    created_at = models.DateTimeField('Registrado el', auto_now_add=True)

    class Meta:
        verbose_name = 'Paso de aprobación'
        verbose_name_plural = 'Pasos de aprobación'
        ordering = ['created_at']

    def __str__(self):
        return f'Step#{self.pk} WF#{self.request_id} {self.action} by {self.actor}'

    def compute_hash(self) -> str:
        data = {
            'request_id': self.request_id,
            'action': self.action,
            'actor_id': self.actor_id,
            'actor_role': self.actor_role,
            'prev_step_hash': self.prev_step_hash,
            'created_at': self.created_at.isoformat() if self.created_at else '',
        }
        return hashlib.sha256(
            json.dumps(data, sort_keys=True, ensure_ascii=False).encode('utf-8')
        ).hexdigest()


# ══════════════════════════════════════════════════════════════════════════════
# ARCO RIGHTS REQUEST
# ══════════════════════════════════════════════════════════════════════════════

class ArcoRequest(models.Model):
    """
    Formal ARCO (Acceso, Rectificación, Cancelación, Oposición) rights request
    filed on behalf of or by a migrant.

    Hierarchy:
      Acceso / Oposición  → Operativo can read directly; Coordinador authorises
      Rectificación       → requires Coordinador authorisation
      Cancelación         → requires Admin authorisation
    """

    ARCO_ACCESS = 'access'
    ARCO_RECTIFICATION = 'rectification'
    ARCO_CANCELLATION = 'cancellation'
    ARCO_OPPOSITION = 'opposition'

    ARCO_TYPE_CHOICES = [
        (ARCO_ACCESS, 'Acceso — conocer los datos almacenados'),
        (ARCO_RECTIFICATION, 'Rectificación — corregir datos inexactos'),
        (ARCO_CANCELLATION, 'Cancelación — solicitar eliminación de datos'),
        (ARCO_OPPOSITION, 'Oposición — oponerse a un uso específico'),
    ]

    STATE_SUBMITTED = 'submitted'
    STATE_IN_REVIEW = 'in_review'
    STATE_APPROVED = 'approved'
    STATE_REJECTED = 'rejected'
    STATE_EXECUTED = 'executed'
    STATE_ESCALATED = 'escalated'

    STATE_CHOICES = [
        (STATE_SUBMITTED, 'Enviada'),
        (STATE_IN_REVIEW, 'En revisión'),
        (STATE_APPROVED, 'Aprobada'),
        (STATE_REJECTED, 'Rechazada'),
        (STATE_EXECUTED, 'Ejecutada'),
        (STATE_ESCALATED, 'Escalada'),
    ]

    arco_type = models.CharField('Tipo de derecho ARCO', max_length=20, choices=ARCO_TYPE_CHOICES)
    registration = models.ForeignKey(
        MigrantRegistration,
        on_delete=models.PROTECT,
        related_name='arco_requests',
        verbose_name='Registro afectado',
    )
    state = models.CharField('Estado', max_length=20, choices=STATE_CHOICES, default=STATE_SUBMITTED, db_index=True)
    description = models.TextField('Descripción de la solicitud')

    requested_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name='arco_requests_made',
        verbose_name='Solicitado por',
    )
    reviewed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='arco_requests_reviewed',
        verbose_name='Revisado por',
    )
    executed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='arco_requests_executed',
        verbose_name='Ejecutado por',
    )

    # ── Linked workflow ───────────────────────────────────────────────────────
    workflow_request = models.OneToOneField(
        WorkflowRequest,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='arco_request',
        verbose_name='Flujo de aprobación',
    )

    execution_notes = models.TextField('Notas de ejecución', blank=True)
    legal_deadline = models.DateField(
        'Plazo legal de respuesta',
        help_text='20 días hábiles desde la recepción.',
        null=True, blank=True,
    )

    created_at = models.DateTimeField('Recibida el', auto_now_add=True)
    reviewed_at = models.DateTimeField('Revisada el', null=True, blank=True)
    executed_at = models.DateTimeField('Ejecutada el', null=True, blank=True)

    class Meta:
        verbose_name = 'Solicitud ARCO'
        verbose_name_plural = 'Solicitudes ARCO'
        ordering = ['-created_at']

    def __str__(self):
        return f'ARCO#{self.pk} {self.get_arco_type_display()} [{self.get_state_display()}]'

    @property
    def required_executor_level(self) -> int:
        """Return the minimum access_level allowed to EXECUTE this ARCO type."""
        if self.arco_type == self.ARCO_CANCELLATION:
            return 1  # Admin only
        if self.arco_type == self.ARCO_RECTIFICATION:
            return 2  # Coordinador or above
        # Access and Opposition: Operativo can read directly; Coordinador authorises changes
        return 3

    def can_execute(self, user) -> bool:
        return user.access_level <= self.required_executor_level
