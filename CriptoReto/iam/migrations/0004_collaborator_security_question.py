from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('iam', '0003_collaborator_certificate_delivered_at_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='collaborator',
            name='security_question',
            field=models.CharField(
                blank=True,
                choices=[
                    ('mascota', '¿Cuál fue el nombre de tu primera mascota?'),
                    ('comida', '¿Cuál es tu comida favorita?'),
                    ('heroe', '¿Cuál fue el nombre de tu héroe de la infancia?'),
                    ('apodo', '¿Cuál era tu apodo de infancia?'),
                    ('deporte', '¿Cuál es tu deporte favorito?'),
                    ('ciudad', '¿En qué ciudad naciste?'),
                    ('amigo', '¿Cuál es el nombre de tu mejor amigo de la infancia?'),
                    ('escuela', '¿Cuál fue el nombre de tu escuela primaria?'),
                ],
                max_length=16,
                verbose_name='Pregunta de seguridad',
            ),
        ),
        migrations.AddField(
            model_name='collaborator',
            name='security_answer_hash',
            field=models.CharField(blank=True, max_length=256, verbose_name='Respuesta de seguridad'),
        ),
    ]
