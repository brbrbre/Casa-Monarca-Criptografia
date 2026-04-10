from django.core.management.base import BaseCommand
from django.utils import timezone

from iam.models import Area, Collaborator, AuditLog


class Command(BaseCommand):
    help = 'Carga datos de prueba para Casa Monarca en la base de datos.'

    def handle(self, *args, **options):
        areas = [
            ('humanitario', 'Humanitario', 'Área de atención humanitaria directa.'),
            ('psicosocial', 'Psicosocial', 'Área de apoyo psicológico y psicosocial.'),
            ('legal', 'Legal', 'Área de asesoría legal y derechos humanos.'),
            ('comunicaciones', 'Comunicaciones', 'Área de comunicación y relaciones públicas.'),
            ('almacen', 'Almacén', 'Área de logística y almacén.'),
            ('it', 'Tecnología', 'Área de sistemas y soporte técnico.'),
        ]

        for slug, name, description in areas:
            Area.objects.update_or_create(slug=slug, defaults={'name': name, 'description': description})

        admin, _ = Collaborator.objects.get_or_create(
            username='admin',
            defaults={
                'email': 'admin@casamonarca.org',
                'first_name': 'Ana',
                'last_name': 'Sánchez',
                'access_level': 1,
                'role': 'Administrador IT',
                'area': Area.objects.get(slug='it'),
                'onboarding_date': timezone.now().date(),
                'is_staff': True,
                'is_superuser': True,
                'is_active': True,
            },
        )
        if not admin.password:
            admin.set_password('Admin2026!')
            admin.save()

        seeds = [
            {
                'username': 'legal_coordinator',
                'email': 'coordinacion.legal@casamonarca.org',
                'first_name': 'Luisa',
                'last_name': 'Pérez',
                'access_level': 2,
                'role': 'Coordinador Legal',
                'area': Area.objects.get(slug='legal'),
                'job_title': 'Coordinadora Legal',
                'onboarding_date': timezone.now().date(),
                'password': 'Legal2026!',
            },
            {
                'username': 'humanitario_ops',
                'email': 'operaciones.humanitario@casamonarca.org',
                'first_name': 'María',
                'last_name': 'Gómez',
                'access_level': 3,
                'role': 'Operativo Humanitario',
                'area': Area.objects.get(slug='humanitario'),
                'job_title': 'Operativa Humanitaria',
                'onboarding_date': timezone.now().date(),
                'password': 'Humanitario2026!',
            },
            {
                'username': 'external_comms',
                'email': 'externo.comunicaciones@casamonarca.org',
                'first_name': 'Carlos',
                'last_name': 'Ramos',
                'access_level': 4,
                'role': 'Personal Externo',
                'area': Area.objects.get(slug='comunicaciones'),
                'job_title': 'Colaborador Externo de Comunicaciones',
                'onboarding_date': timezone.now().date(),
                'password': 'Comms2026!',
            },
            {
                'username': 'warehouse_manager',
                'email': 'gerencia.almacen@casamonarca.org',
                'first_name': 'Sofía',
                'last_name': 'Martínez',
                'access_level': 3,
                'role': 'Almacén',
                'area': Area.objects.get(slug='almacen'),
                'job_title': 'Gerente de Almacén',
                'onboarding_date': timezone.now().date(),
                'password': 'Almacen2026!',
            },
            {
                'username': 'psychologist',
                'email': 'psicologia@casamonarca.org',
                'first_name': 'Ana',
                'last_name': 'Torres',
                'access_level': 3,
                'role': 'Psicólogo',
                'area': Area.objects.get(slug='psicosocial'),
                'job_title': 'Psicóloga',
                'onboarding_date': timezone.now().date(),
                'password': 'Psico2026!',
            },
            {
                'username': 'external_support',
                'email': 'apoyo.externo@casamonarca.org',
                'first_name': 'Luis',
                'last_name': 'Campos',
                'access_level': 4,
                'role': 'Personal Externo',
                'area': Area.objects.get(slug='it'),
                'job_title': 'Soporte Externo',
                'onboarding_date': timezone.now().date(),
                'password': 'Soporte2026!',
            },
        ]

        for seed in seeds:
            user, created = Collaborator.objects.update_or_create(
                username=seed['username'],
                defaults={
                    'email': seed['email'],
                    'first_name': seed['first_name'],
                    'last_name': seed['last_name'],
                    'access_level': seed['access_level'],
                    'role': seed['role'],
                    'area': seed['area'],
                    'job_title': seed['job_title'],
                    'onboarding_date': seed['onboarding_date'],
                    'is_staff': seed['access_level'] <= 2,
                    'is_active': True,
                },
            )
            user.set_password(seed['password'])
            user.created_by = admin
            user.save()
            if created:
                AuditLog.objects.create(
                    actor=admin,
                    target=user,
                    action='Creación de usuario de prueba',
                    details=f'Usuario de prueba creado con contraseña temporal.',
                )

        self.stdout.write(self.style.SUCCESS('Datos de prueba cargados correctamente.'))
