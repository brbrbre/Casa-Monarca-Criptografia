from django import forms
from .models import ArcoRequest, MigrantRegistration


class MigrantRegistrationForm(forms.ModelForm):
    # Override to show checkboxes; value stored as comma-separated string in the model
    assistance_requested = forms.MultipleChoiceField(
        choices=MigrantRegistration.ASSISTANCE_CHOICES,
        widget=forms.CheckboxSelectMultiple,
        label='Tipo de asistencia solicitada',
        help_text='Selecciona todos los tipos de asistencia que necesita.',
    )
    # Use id="privacy_accept" so the privacy-modal partial can check it
    data_consent = forms.BooleanField(
        required=True,
        widget=forms.CheckboxInput(attrs={'id': 'privacy_accept'}),
        label='He leído y acepto el Aviso de Privacidad Integral',
        error_messages={'required': 'Debes aceptar el Aviso de Privacidad para continuar.'},
    )

    class Meta:
        model = MigrantRegistration
        exclude = [
            'created_by', 'created_by_role',
            'created_at', 'updated_at',
            'is_deleted', 'deleted_at', 'deleted_by',
            # Privacy audit fields are set by the view, not the form
            'privacy_accepted_at', 'privacy_accepted_ip', 'privacy_notice_version',
        ]
        widgets = {
            'birth_date': forms.DateInput(attrs={'type': 'date'}),
            'entry_date': forms.DateInput(attrs={'type': 'date'}),
            'migration_reason': forms.Textarea(attrs={'rows': 4}),
            'transit_countries': forms.Textarea(attrs={'rows': 2}),
            'observations': forms.Textarea(attrs={'rows': 3}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Pre-select checkboxes when editing an existing instance
        if self.instance and self.instance.pk and self.instance.assistance_requested:
            self.initial['assistance_requested'] = [
                v.strip() for v in self.instance.assistance_requested.split(',') if v.strip()
            ]

    def clean_assistance_requested(self):
        values = self.cleaned_data.get('assistance_requested', [])
        if not values:
            raise forms.ValidationError('Selecciona al menos un tipo de asistencia.')
        return ','.join(values)

    def clean_group_size(self):
        value = self.cleaned_data.get('group_size', 1)
        if value < 1:
            raise forms.ValidationError('El tamaño del grupo debe ser al menos 1.')
        return value

    def clean(self):
        cleaned = super().clean()
        minors = cleaned.get('minors_in_group', 0)
        group = cleaned.get('group_size', 1)
        travels_alone = cleaned.get('travels_alone', True)
        if minors > group:
            self.add_error('minors_in_group', 'Los menores no pueden superar el tamaño del grupo.')
        if travels_alone and group > 1:
            self.add_error('travels_alone', 'Si viaja acompañado/a, desmarca "Viaja solo/a".')
        return cleaned


class ArcoRequestForm(forms.ModelForm):
    class Meta:
        model = ArcoRequest
        fields = ['arco_type', 'description']
        widgets = {
            'description': forms.Textarea(attrs={
                'rows': 5,
                'placeholder': (
                    'Describe detalladamente tu solicitud: qué datos deseas '
                    'acceder / corregir / eliminar y el motivo.'
                ),
            }),
        }
        labels = {
            'arco_type': 'Tipo de derecho ARCO',
            'description': 'Descripción de la solicitud',
        }

    def clean_description(self):
        val = self.cleaned_data.get('description', '').strip()
        if len(val) < 20:
            raise forms.ValidationError('La descripción debe tener al menos 20 caracteres.')
        return val


class WorkflowApprovalForm(forms.Form):
    """Used by approvers to approve or reject a WorkflowRequest."""
    decision = forms.ChoiceField(
        choices=[('approved', 'Aprobar'), ('rejected', 'Rechazar')],
        widget=forms.RadioSelect,
        label='Decisión',
    )
    notes = forms.CharField(
        required=False,
        widget=forms.Textarea(attrs={'rows': 3, 'placeholder': 'Observaciones (opcionales)'}),
        label='Notas',
    )
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={'autocomplete': 'current-password'}),
        label='Contraseña (para confirmar identidad)',
    )
