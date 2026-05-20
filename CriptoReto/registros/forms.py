from django import forms
from .models import MigrantRegistration


class MigrantRegistrationForm(forms.ModelForm):
    # Override to show checkboxes; value stored as comma-separated string
    assistance_requested = forms.MultipleChoiceField(
        choices=MigrantRegistration.ASSISTANCE_CHOICES,
        widget=forms.CheckboxSelectMultiple,
        label='Tipo de asistencia solicitada',
        help_text='Selecciona todos los tipos de asistencia que necesita.',
    )

    class Meta:
        model = MigrantRegistration
        exclude = [
            'created_by', 'created_by_role',
            'created_at', 'updated_at',
            'is_deleted', 'deleted_at', 'deleted_by',
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
        # When editing an existing instance, pre-select checkboxes
        if self.instance and self.instance.pk and self.instance.assistance_requested:
            self.initial['assistance_requested'] = [
                v.strip() for v in self.instance.assistance_requested.split(',') if v.strip()
            ]
        self.fields['data_consent'].label = (
            'Otorgo mi consentimiento para el tratamiento de mis datos personales '
            'conforme a la Ley Federal de Protección de Datos Personales.'
        )

    def clean_assistance_requested(self):
        values = self.cleaned_data.get('assistance_requested', [])
        if not values:
            raise forms.ValidationError('Selecciona al menos un tipo de asistencia.')
        return ','.join(values)

    def clean_data_consent(self):
        value = self.cleaned_data.get('data_consent')
        if not value:
            raise forms.ValidationError('Debes aceptar el consentimiento de datos para continuar.')
        return value

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
