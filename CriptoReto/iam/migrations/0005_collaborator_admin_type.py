from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('iam', '0004_collaborator_security_question'),
    ]

    operations = [
        migrations.AddField(
            model_name='collaborator',
            name='admin_type',
            field=models.CharField(
                blank=True,
                choices=[
                    ('production', 'Producción'),
                    ('contingency', 'Contingencias'),
                ],
                max_length=16,
                verbose_name='Tipo de cuenta admin',
            ),
        ),
    ]
