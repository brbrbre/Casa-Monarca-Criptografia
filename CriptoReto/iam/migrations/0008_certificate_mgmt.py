import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


def set_initial_cert_status(apps, schema_editor):
    UserCertificate = apps.get_model('iam', 'UserCertificate')
    from django.utils import timezone
    now = timezone.now()
    for cert in UserCertificate.objects.all():
        if cert.is_revoked:
            status = 'REVOKED'
        elif cert.expires_at <= now:
            status = 'EXPIRED'
        else:
            status = 'ACTIVE'
        # Also extract serial number for X.509 PEM certs
        serial = ''
        cert_data = cert.certificate_data or ''
        if cert_data.strip().startswith('-----BEGIN CERTIFICATE-----'):
            try:
                from cryptography.x509 import load_pem_x509_certificate
                x509_cert = load_pem_x509_certificate(cert_data.encode())
                serial = format(x509_cert.serial_number, 'x').upper()
            except Exception:
                pass
        UserCertificate.objects.filter(pk=cert.pk).update(status=status, serial_number=serial)


class Migration(migrations.Migration):

    dependencies = [
        ('iam', '0007_onboarding_submitted_flow'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.AddField(
            model_name='usercertificate',
            name='status',
            field=models.CharField(
                choices=[
                    ('ACTIVE', 'Activo'),
                    ('SUSPENDED', 'Suspendido'),
                    ('REVOKED', 'Revocado'),
                    ('INACTIVE', 'Inactivo'),
                    ('EXPIRED', 'Expirado'),
                ],
                db_index=True,
                default='ACTIVE',
                max_length=16,
                verbose_name='Estado',
            ),
        ),
        migrations.AddField(
            model_name='usercertificate',
            name='serial_number',
            field=models.CharField(blank=True, max_length=128, verbose_name='Número de serie'),
        ),
        migrations.AddField(
            model_name='usercertificate',
            name='revocation_reason',
            field=models.TextField(blank=True, verbose_name='Motivo de revocación'),
        ),
        migrations.AddField(
            model_name='usercertificate',
            name='suspended_at',
            field=models.DateTimeField(blank=True, null=True, verbose_name='Fecha de suspensión'),
        ),
        migrations.AddField(
            model_name='usercertificate',
            name='suspended_by',
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name='certificates_suspended',
                to=settings.AUTH_USER_MODEL,
                verbose_name='Suspendido por',
            ),
        ),
        migrations.AddField(
            model_name='usercertificate',
            name='suspension_reason',
            field=models.TextField(blank=True, verbose_name='Motivo de suspensión'),
        ),
        migrations.AddField(
            model_name='usercertificate',
            name='deactivated_at',
            field=models.DateTimeField(blank=True, null=True, verbose_name='Fecha de baja'),
        ),
        migrations.AddField(
            model_name='usercertificate',
            name='deactivated_by',
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name='certificates_deactivated',
                to=settings.AUTH_USER_MODEL,
                verbose_name='Dado de baja por',
            ),
        ),
        migrations.AddField(
            model_name='usercertificate',
            name='deactivation_reason',
            field=models.TextField(blank=True, verbose_name='Motivo de baja'),
        ),
        migrations.RunPython(set_initial_cert_status, migrations.RunPython.noop),
        migrations.CreateModel(
            name='CertificateAuditLog',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('action', models.CharField(max_length=32, verbose_name='Acción')),
                ('timestamp', models.DateTimeField(auto_now_add=True, verbose_name='Fecha y hora')),
                ('previous_status', models.CharField(blank=True, max_length=16, verbose_name='Estado anterior')),
                ('new_status', models.CharField(blank=True, max_length=16, verbose_name='Estado nuevo')),
                ('metadata', models.JSONField(blank=True, default=dict, verbose_name='Metadatos')),
                ('certificate', models.ForeignKey(
                    on_delete=django.db.models.deletion.PROTECT,
                    related_name='cert_audit_logs',
                    to='iam.usercertificate',
                    verbose_name='Certificado',
                )),
                ('performed_by', models.ForeignKey(
                    blank=True,
                    null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name='cert_audit_actions',
                    to=settings.AUTH_USER_MODEL,
                    verbose_name='Realizado por',
                )),
            ],
            options={
                'verbose_name': 'Auditoría de certificado',
                'verbose_name_plural': 'Auditorías de certificados',
                'ordering': ['-timestamp'],
            },
        ),
    ]
