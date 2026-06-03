"""
Add ARCO cancellation fields to MigrantRegistration and
modifications_before_execution to WorkflowRequest.
"""

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ('registros', '0012_refactor_migrant_registration'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        # ── MigrantRegistration: ARCO cancellation fields ─────────────────────
        migrations.AddField(
            model_name='migrantregistration',
            name='arco_cancellation_reason',
            field=models.CharField(
                verbose_name='Razón de cancelación ARCO',
                max_length=20,
                choices=[('cancellation', 'Cancelación ARCO'), ('opposition', 'Oposición ARCO')],
                null=True,
                blank=True,
            ),
        ),
        migrations.AddField(
            model_name='migrantregistration',
            name='arco_cancelled_at',
            field=models.DateTimeField(verbose_name='Cancelado por ARCO el', null=True, blank=True),
        ),
        migrations.AddField(
            model_name='migrantregistration',
            name='arco_cancelled_by',
            field=models.ForeignKey(
                verbose_name='Cancelado por (ARCO)',
                to=settings.AUTH_USER_MODEL,
                null=True,
                blank=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name='arco_cancellations_executed',
            ),
        ),
        # ── WorkflowRequest: modifications before execution ───────────────────
        migrations.AddField(
            model_name='workflowrequest',
            name='modifications_before_execution',
            field=models.JSONField(
                verbose_name='Modificaciones antes de ejecución',
                default=dict,
                blank=True,
            ),
        ),
    ]
