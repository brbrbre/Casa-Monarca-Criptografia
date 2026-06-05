from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('registros', '0014_arco_ticket_model'),
    ]

    operations = [
        migrations.AddField(
            model_name='arcorequest',
            name='rectif_field',
            field=models.CharField(
                blank=True, default='', max_length=50, verbose_name='Campo a rectificar'
            ),
        ),
        migrations.AddField(
            model_name='arcorequest',
            name='rectif_value',
            field=models.TextField(
                blank=True, default='', verbose_name='Nuevo valor para rectificación'
            ),
        ),
    ]
