from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('iam', '0006_usercertificate_key_data'),
    ]

    operations = [
        migrations.AddField(
            model_name='collaborator',
            name='onboarding_submitted_at',
            field=models.DateTimeField(blank=True, null=True, verbose_name='Formulario enviado el'),
        ),
        migrations.AddField(
            model_name='collaborator',
            name='cert_file_downloaded',
            field=models.BooleanField(default=False, verbose_name='.cert descargado'),
        ),
        migrations.AddField(
            model_name='collaborator',
            name='key_file_downloaded',
            field=models.BooleanField(default=False, verbose_name='.key descargado'),
        ),
        migrations.AlterField(
            model_name='collaborator',
            name='onboarding_status',
            field=models.CharField(
                choices=[
                    ('pending', 'Pendiente'),
                    ('submitted', 'Enviado'),
                    ('approved', 'Aprobado'),
                    ('rejected', 'Rechazado'),
                ],
                default='pending',
                max_length=16,
                verbose_name='Estado de onboarding',
            ),
        ),
    ]
