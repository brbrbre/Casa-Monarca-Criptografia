"""
Encrypt PII fields in MigrantRegistration.

Converts personally-identifiable fields from CharField/DateField/TextField to
EncryptedTextField/EncryptedDateField (stored as TEXT in the DB).
All PII is now stored as AES-256-GCM ciphertext, never as plaintext.
"""

from django.db import migrations
import crypto_core.fields


class Migration(migrations.Migration):

    dependencies = [
        ('registros', '0010_signed_flow_log'),
    ]

    operations = [
        # full_name: CharField(255) → EncryptedTextField (TEXT)
        migrations.AlterField(
            model_name='migrantregistration',
            name='full_name',
            field=crypto_core.fields.EncryptedTextField(verbose_name='Nombre completo'),
        ),
        # birth_date: DateField → EncryptedDateField (TEXT stores encrypted ISO date)
        migrations.AlterField(
            model_name='migrantregistration',
            name='birth_date',
            field=crypto_core.fields.EncryptedDateField(verbose_name='Fecha de nacimiento'),
        ),
        # nationality: CharField(100) → EncryptedTextField
        migrations.AlterField(
            model_name='migrantregistration',
            name='nationality',
            field=crypto_core.fields.EncryptedTextField(verbose_name='Nacionalidad'),
        ),
        # country_of_origin: CharField(100) → EncryptedTextField
        migrations.AlterField(
            model_name='migrantregistration',
            name='country_of_origin',
            field=crypto_core.fields.EncryptedTextField(verbose_name='País de origen'),
        ),
        # document_number: CharField(100) → EncryptedTextField
        migrations.AlterField(
            model_name='migrantregistration',
            name='document_number',
            field=crypto_core.fields.EncryptedTextField(
                blank=True, default='', verbose_name='Número de documento'
            ),
        ),
        # phone: CharField(20) → EncryptedTextField (old max_length too short for ciphertext)
        migrations.AlterField(
            model_name='migrantregistration',
            name='phone',
            field=crypto_core.fields.EncryptedTextField(
                blank=True, default='', verbose_name='Teléfono'
            ),
        ),
        # email: EmailField → EncryptedTextField
        migrations.AlterField(
            model_name='migrantregistration',
            name='email',
            field=crypto_core.fields.EncryptedTextField(
                blank=True, default='', verbose_name='Correo electrónico'
            ),
        ),
        # migration_reason: TextField → EncryptedTextField
        migrations.AlterField(
            model_name='migrantregistration',
            name='migration_reason',
            field=crypto_core.fields.EncryptedTextField(verbose_name='Motivo de migración'),
        ),
        # emergency_contact_name: CharField(255) → EncryptedTextField
        migrations.AlterField(
            model_name='migrantregistration',
            name='emergency_contact_name',
            field=crypto_core.fields.EncryptedTextField(
                verbose_name='Nombre del contacto de emergencia'
            ),
        ),
        # emergency_contact_phone: CharField(20) → EncryptedTextField
        migrations.AlterField(
            model_name='migrantregistration',
            name='emergency_contact_phone',
            field=crypto_core.fields.EncryptedTextField(
                verbose_name='Teléfono del contacto de emergencia'
            ),
        ),
        # emergency_contact_relationship: CharField(100) → EncryptedTextField
        migrations.AlterField(
            model_name='migrantregistration',
            name='emergency_contact_relationship',
            field=crypto_core.fields.EncryptedTextField(
                verbose_name='Parentesco del contacto de emergencia'
            ),
        ),
        # observations: TextField → EncryptedTextField
        migrations.AlterField(
            model_name='migrantregistration',
            name='observations',
            field=crypto_core.fields.EncryptedTextField(
                blank=True, default='', verbose_name='Observaciones adicionales'
            ),
        ),
        # transit_countries: TextField → EncryptedTextField (migration routes are sensitive)
        migrations.AlterField(
            model_name='migrantregistration',
            name='transit_countries',
            field=crypto_core.fields.EncryptedTextField(
                blank=True, default='', verbose_name='Países de tránsito'
            ),
        ),
    ]
