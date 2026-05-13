from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('iam', '0005_collaborator_admin_type'),
    ]

    operations = [
        migrations.AddField(
            model_name='usercertificate',
            name='key_data',
            field=models.TextField(blank=True, verbose_name='Llave privada cifrada'),
        ),
    ]
