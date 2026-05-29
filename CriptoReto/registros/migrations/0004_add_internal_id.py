from django.db import migrations, models
import uuid


def generate_internal_ids(apps, schema_editor):
    MigrantRegistration = apps.get_model('registros', 'MigrantRegistration')
    for registration in MigrantRegistration.objects.filter(internal_id__isnull=True):
        registration.internal_id = f'CM-{uuid.uuid4().hex[:8].upper()}'
        registration.save(update_fields=['internal_id'])


class Migration(migrations.Migration):

    dependencies = [
        ('registros', '0003_notification'),
    ]

    operations = [
        migrations.AddField(
            model_name='migrantregistration',
            name='internal_id',
            field=models.CharField(
                'Identificador interno',
                max_length=32,
                unique=True,
                blank=True,
                null=True,
            ),
        ),
        migrations.RunPython(generate_internal_ids, migrations.RunPython.noop),
    ]
