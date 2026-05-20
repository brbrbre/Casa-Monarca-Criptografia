from django.conf import settings
from django.db import models
from django.utils import timezone


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
    # Comma-separated values from ASSISTANCE_CHOICES
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
        """Return assistance_requested as a list of human-readable labels."""
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
