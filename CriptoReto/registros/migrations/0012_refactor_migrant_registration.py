"""
Refactor MigrantRegistration: replace legacy fields with the 12-field schema.

Changes:
  ADD   first_name, first_surname, second_surname (EncryptedTextField)
  ADD   service_date (DateField — copied from entry_date)
  ADD   state_or_region, age_group, population_group (CharField)
  ALTER gender choices → Femenino/Masculino/No binario/LGBTIQ+
  DROP  full_name, nationality, email, document_type, document_number,
        migration_reason, transit_countries, entry_point, intended_destination,
        travels_alone, group_size, minors_in_group, assistance_requested,
        current_legal_status, shelter_name, emergency_contact_*, observations,
        entry_date
"""

import crypto_core.fields
from django.db import migrations, models


def copy_service_date(apps, schema_editor):
    schema_editor.execute(
        'UPDATE registros_migrantregistration'
        ' SET service_date = entry_date'
        ' WHERE entry_date IS NOT NULL'
    )


def reverse_service_date(apps, schema_editor):
    schema_editor.execute(
        'UPDATE registros_migrantregistration'
        ' SET entry_date = service_date'
        ' WHERE service_date IS NOT NULL'
    )


class Migration(migrations.Migration):
    dependencies = [
        ('registros', '0011_encrypt_sensitive_fields'),
    ]

    operations = [
        # ── 1. Add new fields (nullable / with defaults so existing rows are valid) ──
        migrations.AddField(
            model_name='migrantregistration',
            name='first_name',
            field=crypto_core.fields.EncryptedTextField(blank=True, default='', verbose_name='Nombre'),
        ),
        migrations.AddField(
            model_name='migrantregistration',
            name='first_surname',
            field=crypto_core.fields.EncryptedTextField(blank=True, default='', verbose_name='Primer apellido'),
        ),
        migrations.AddField(
            model_name='migrantregistration',
            name='second_surname',
            field=crypto_core.fields.EncryptedTextField(blank=True, default='X', verbose_name='Segundo apellido'),
        ),
        migrations.AddField(
            model_name='migrantregistration',
            name='service_date',
            field=models.DateField(blank=True, null=True, verbose_name='Fecha de servicio'),
        ),
        migrations.AddField(
            model_name='migrantregistration',
            name='state_or_region',
            field=models.CharField(blank=True, default='', max_length=100, verbose_name='Departamento/Estado'),
        ),
        migrations.AddField(
            model_name='migrantregistration',
            name='age_group',
            field=models.CharField(
                blank=True,
                choices=[
                    ('infancia', 'Infancia (0-11 años)'),
                    ('adolescencia', 'Adolescencia (12-17 años)'),
                    ('adulto', 'Adulto (18-59 años)'),
                    ('adulto_mayor', 'Adulto mayor (60+ años)'),
                ],
                default='',
                max_length=30,
                verbose_name='Grupo de edad',
            ),
        ),
        migrations.AddField(
            model_name='migrantregistration',
            name='population_group',
            field=models.CharField(
                blank=True,
                choices=[
                    ('adulto', 'Adulto (18-59)'),
                    ('adulto_mayor', 'Adulto mayor (+60)'),
                    ('nina_acompanada', 'Niña acompañada'),
                    ('nino_acompanado', 'Niño acompañado'),
                    ('adolescente_hombre', 'Adolescente hombre acompañado'),
                    ('adolescente_mujer', 'Adolescente mujer acompañada'),
                    ('nna_no_acompanado', 'NNA No acompañado'),
                ],
                default='',
                max_length=50,
                verbose_name='Grupo poblacional',
            ),
        ),
        # ── 2. Copy entry_date → service_date for existing rows ────────────────
        migrations.RunPython(copy_service_date, reverse_code=reverse_service_date),
        # ── 3. Update gender choices ───────────────────────────────────────────
        migrations.AlterField(
            model_name='migrantregistration',
            name='gender',
            field=models.CharField(
                choices=[
                    ('femenino', 'Femenino'),
                    ('masculino', 'Masculino'),
                    ('no_binario', 'No binario'),
                    ('lgbtiq', 'LGBTIQ+'),
                ],
                max_length=20,
                verbose_name='Género',
            ),
        ),
        # ── 4. Remove old fields ───────────────────────────────────────────────
        migrations.RemoveField(model_name='migrantregistration', name='full_name'),
        migrations.RemoveField(model_name='migrantregistration', name='nationality'),
        migrations.RemoveField(model_name='migrantregistration', name='email'),
        migrations.RemoveField(model_name='migrantregistration', name='document_type'),
        migrations.RemoveField(model_name='migrantregistration', name='document_number'),
        migrations.RemoveField(model_name='migrantregistration', name='migration_reason'),
        migrations.RemoveField(model_name='migrantregistration', name='transit_countries'),
        migrations.RemoveField(model_name='migrantregistration', name='entry_point'),
        migrations.RemoveField(model_name='migrantregistration', name='intended_destination'),
        migrations.RemoveField(model_name='migrantregistration', name='travels_alone'),
        migrations.RemoveField(model_name='migrantregistration', name='group_size'),
        migrations.RemoveField(model_name='migrantregistration', name='minors_in_group'),
        migrations.RemoveField(model_name='migrantregistration', name='assistance_requested'),
        migrations.RemoveField(model_name='migrantregistration', name='current_legal_status'),
        migrations.RemoveField(model_name='migrantregistration', name='shelter_name'),
        migrations.RemoveField(model_name='migrantregistration', name='emergency_contact_name'),
        migrations.RemoveField(model_name='migrantregistration', name='emergency_contact_phone'),
        migrations.RemoveField(model_name='migrantregistration', name='emergency_contact_relationship'),
        migrations.RemoveField(model_name='migrantregistration', name='observations'),
        migrations.RemoveField(model_name='migrantregistration', name='entry_date'),
    ]
