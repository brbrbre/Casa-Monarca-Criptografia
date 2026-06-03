import re

from django import forms
from .models import ArcoRequest, MigrantRegistration


class MigrantRegistrationForm(forms.ModelForm):
    # Use id="privacy_accept" so the privacy-modal partial can check it
    data_consent = forms.BooleanField(
        required=True,
        widget=forms.CheckboxInput(attrs={'id': 'privacy_accept'}),
        label='He leído y acepto el Aviso de Privacidad Integral',
        error_messages={'required': 'Debes aceptar el Aviso de Privacidad para continuar.'},
    )
    consent_method = forms.ChoiceField(
        choices=MigrantRegistration.CONSENT_METHOD_CHOICES,
        initial=MigrantRegistration.CONSENT_DIGITAL,
        label='Método de captura del consentimiento',
        help_text='Indica cómo se obtuvo el consentimiento del beneficiario.',
    )
    consent_by_proxy = forms.BooleanField(
        required=False,
        label='El personal capturó el consentimiento en nombre del beneficiario',
        help_text='Marcar cuando el beneficiario NO puede operar el sistema y el personal actúa como intermediario.',
    )

    class Meta:
        model = MigrantRegistration
        exclude = [
            'created_by', 'created_by_role',
            'created_at', 'updated_at',
            'is_deleted', 'deleted_at', 'deleted_by',
            'privacy_accepted_at', 'privacy_accepted_ip', 'privacy_notice_version',
            # ARCO cancellation fields — managed only by system logic, not editable in forms
            'arco_cancellation_reason', 'arco_cancelled_at', 'arco_cancelled_by',
        ]
        widgets = {
            # format='%Y-%m-%d' is required because USE_I18N=True (es-mx) formats as
            # DD/MM/YYYY by default, which <input type="date"> rejects and shows blank.
            'birth_date': forms.DateInput(attrs={'type': 'date'}, format='%Y-%m-%d'),
            'service_date': forms.DateInput(attrs={'type': 'date'}, format='%Y-%m-%d'),
            'first_name': forms.TextInput(attrs={'maxlength': '50'}),
            'first_surname': forms.TextInput(attrs={'maxlength': '50'}),
            'second_surname': forms.TextInput(attrs={'maxlength': '50'}),
            'country_of_origin': forms.TextInput(attrs={'maxlength': '100'}),
            'phone': forms.TextInput(attrs={'maxlength': '30'}),
        }

    def clean_second_surname(self):
        val = self.cleaned_data.get('second_surname', '').strip()
        return val if val else 'X'

    def clean_phone(self):
        val = self.cleaned_data.get('phone', '').strip()
        if val and not re.match(r'^\+\d{1,3}-\d{1,5}-\d{4,15}$', val):
            raise forms.ValidationError(
                'Formato inválido. Usa: +país-área-número (ej: +52-55-12345678).'
            )
        return val

    def clean_first_name(self):
        val = self.cleaned_data.get('first_name', '').strip()
        if len(val) > 50:
            raise forms.ValidationError('El nombre no puede superar los 50 caracteres.')
        return val

    def clean_first_surname(self):
        val = self.cleaned_data.get('first_surname', '').strip()
        if len(val) > 50:
            raise forms.ValidationError('El primer apellido no puede superar los 50 caracteres.')
        return val

    def clean_country_of_origin(self):
        val = self.cleaned_data.get('country_of_origin', '').strip()
        if len(val) > 100:
            raise forms.ValidationError('El país de origen no puede superar los 100 caracteres.')
        return val


class ArcoRequestForm(forms.ModelForm):
    attached_document = forms.FileField(
        label='Documento de respaldo (PDF)',
        required=False,
        help_text='Solo Rectificación: adjunta el PDF con la evidencia de los datos correctos. Máx. 5 MB.',
        widget=forms.ClearableFileInput(attrs={'accept': '.pdf,application/pdf'}),
    )

    class Meta:
        model = ArcoRequest
        fields = ['arco_type', 'description', 'attached_document']
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

    def clean_attached_document(self):
        doc = self.cleaned_data.get('attached_document')
        if not doc:
            return doc
        content_type = getattr(doc, 'content_type', '')
        name = doc.name.lower()
        if content_type not in ('application/pdf', 'application/octet-stream') and not name.endswith('.pdf'):
            raise forms.ValidationError('Solo se aceptan archivos PDF (.pdf).')
        if doc.size > 5 * 1024 * 1024:
            raise forms.ValidationError('El archivo no puede superar los 5 MB.')
        return doc

    def clean(self):
        cleaned = super().clean()
        arco_type = cleaned.get('arco_type')
        doc = cleaned.get('attached_document')
        if arco_type == ArcoRequest.ARCO_RECTIFICATION and not doc:
            pass  # document recommended but not required
        return cleaned


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


class WorkflowUpdateRequestForm(forms.ModelForm):
    """
    Propose field changes via a WorkflowRequest.
    Mirrors MigrantRegistrationForm but omits the privacy consent checkbox.
    Only the 12 tracked registration fields are shown; all metadata / ARCO fields
    are excluded so they don't appear when the template iterates the form.
    """
    class Meta:
        model = MigrantRegistration
        fields = [
            'first_name', 'first_surname', 'second_surname',
            'birth_date', 'gender',
            'country_of_origin', 'state_or_region',
            'phone', 'service_date',
            'marital_status', 'age_group', 'population_group',
        ]
        widgets = {
            # format='%Y-%m-%d' fixes blank dates under es-mx locale (see MigrantRegistrationForm)
            'birth_date': forms.DateInput(attrs={'type': 'date'}, format='%Y-%m-%d'),
            'service_date': forms.DateInput(attrs={'type': 'date'}, format='%Y-%m-%d'),
            'first_name': forms.TextInput(attrs={'maxlength': '50'}),
            'first_surname': forms.TextInput(attrs={'maxlength': '50'}),
            'second_surname': forms.TextInput(attrs={'maxlength': '50'}),
            'country_of_origin': forms.TextInput(attrs={'maxlength': '100'}),
            'phone': forms.TextInput(attrs={'maxlength': '30'}),
        }

    def clean_second_surname(self):
        val = self.cleaned_data.get('second_surname', '').strip()
        return val if val else 'X'

    def clean_phone(self):
        val = self.cleaned_data.get('phone', '').strip()
        if val and not re.match(r'^\+\d{1,3}-\d{1,5}-\d{4,15}$', val):
            raise forms.ValidationError(
                'Formato inválido. Usa: +país-área-número (ej: +52-55-12345678).'
            )
        return val
