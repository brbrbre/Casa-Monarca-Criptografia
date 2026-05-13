import re

from django import forms
from django.utils import timezone

from .models import Collaborator, Area


def validate_strong_password(password):
    errors = []
    if len(password) < 8:
        errors.append('Debe tener al menos 8 caracteres.')
    if not re.search(r'[A-Z]', password):
        errors.append('Debe incluir al menos una letra mayúscula.')
    if not re.search(r'\d', password):
        errors.append('Debe incluir al menos un número.')
    if not re.search(r'[!@#$%^&*()\-_=+\[\]{};:\'",.<>/?\\|`~]', password):
        errors.append('Debe incluir al menos un carácter especial (ej. !, @, #, $).')
    if errors:
        raise forms.ValidationError(errors)


class LoginForm(forms.Form):
    username = forms.CharField(
        label='Usuario',
        max_length=150,
        widget=forms.TextInput(attrs={'autofocus': True, 'autocomplete': 'username'}),
    )
    password = forms.CharField(
        label='Contraseña',
        widget=forms.PasswordInput(attrs={'autocomplete': 'current-password'}),
    )
    otp = forms.CharField(
        label='Código MFA',
        required=False,
        widget=forms.TextInput(attrs={'placeholder': '123456', 'inputmode': 'numeric'}),
    )
    # Used by admin (legacy encrypted JSON cert) and shown for coordinators as the .cert file.
    certificate = forms.FileField(
        label='Certificado digital (.cert)',
        required=False,
        widget=forms.ClearableFileInput(attrs={'accept': '.cert'}),
        help_text='Archivo de certificado digital emitido para el colaborador.',
    )
    # Used exclusively by coordinators: the PKCS#8 DER private key.
    key_file = forms.FileField(
        label='Llave privada (.key)',
        required=False,
        widget=forms.ClearableFileInput(attrs={'accept': '.key'}),
        help_text='Archivo de llave privada correspondiente al certificado.',
    )


class OnboardingForm(forms.ModelForm):
    new_password1 = forms.CharField(
        label='Nueva contraseña',
        widget=forms.PasswordInput,
        required=True,
    )
    new_password2 = forms.CharField(
        label='Confirma la contraseña',
        widget=forms.PasswordInput,
        required=True,
    )
    security_question = forms.ChoiceField(
        label='Pregunta de seguridad',
        choices=Collaborator.SECURITY_QUESTIONS,
    )
    security_answer = forms.CharField(
        label='Respuesta',
        max_length=128,
        widget=forms.TextInput(attrs={'autocomplete': 'off'}),
    )
    security_answer_confirm = forms.CharField(
        label='Confirma tu respuesta',
        max_length=128,
        widget=forms.TextInput(attrs={'autocomplete': 'off'}),
    )

    class Meta:
        model = Collaborator
        fields = ['first_name', 'last_name', 'phone', 'official_id_document']
        widgets = {
            'official_id_document': forms.ClearableFileInput(attrs={'accept': 'application/pdf'}),
            'phone': forms.TextInput(attrs={'inputmode': 'numeric', 'pattern': r'\d*'}),
        }

    def clean_phone(self):
        phone = self.cleaned_data.get('phone', '')
        if phone and not phone.isdigit():
            raise forms.ValidationError('El teléfono solo puede contener números.')
        return phone

    def clean_new_password1(self):
        password = self.cleaned_data.get('new_password1')
        if password:
            validate_strong_password(password)
        return password

    def clean(self):
        cleaned = super().clean()
        password1 = cleaned.get('new_password1')
        password2 = cleaned.get('new_password2')
        if password1 and password2 and password1 != password2:
            raise forms.ValidationError('Las contraseñas no coinciden.')
        ans1 = cleaned.get('security_answer', '').strip().lower()
        ans2 = cleaned.get('security_answer_confirm', '').strip().lower()
        if ans1 and ans2 and ans1 != ans2:
            raise forms.ValidationError('Las respuestas de seguridad no coinciden.')
        return cleaned

    def clean_official_id_document(self):
        document = self.cleaned_data.get('official_id_document')
        if document and not document.name.lower().endswith('.pdf'):
            raise forms.ValidationError('Solo se aceptan archivos PDF.')
        return document


class CollaboratorForm(forms.ModelForm):
    password = forms.CharField(label='Contraseña temporal', required=False, widget=forms.PasswordInput, help_text='Dejar vacío para no cambiar la contraseña.')
    mfa_enabled = forms.BooleanField(label='Habilitar MFA (TOTP)', required=False)

    class Meta:
        model = Collaborator
        fields = [
            'username',
            'first_name',
            'last_name',
            'email',
            'phone',
            'area',
            'access_level',
            'admin_type',
            'role',
            'job_title',
            'onboarding_date',
            'mfa_enabled',
        ]
        widgets = {
            'onboarding_date': forms.DateInput(attrs={'type': 'date'}),
            'phone': forms.TextInput(attrs={'inputmode': 'numeric', 'pattern': r'\d*'}),
        }

    def clean_phone(self):
        phone = self.cleaned_data.get('phone', '')
        if phone and not phone.isdigit():
            raise forms.ValidationError('El teléfono solo puede contener números.')
        return phone

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['area'].queryset = Area.objects.order_by('name')
        self.fields['email'].help_text = 'Correo institucional válido.'
        self.fields['username'].help_text = 'Identificador único para el acceso.'
        self.fields['admin_type'].required = False
        self.fields['admin_type'].help_text = 'Solo aplica para cuentas de nivel Administración (Nivel 1).'

    def clean(self):
        cleaned = super().clean()
        access_level = cleaned.get('access_level')
        admin_type = cleaned.get('admin_type', '')
        if access_level == 1 and not admin_type:
            self.add_error('admin_type', 'Las cuentas de Nivel 1 deben tener un tipo de cuenta (Producción o Contingencias).')
        if access_level != 1 and admin_type:
            cleaned['admin_type'] = ''
        return cleaned

    def clean_email(self):
        email = self.cleaned_data.get('email')
        if email and Collaborator.objects.exclude(pk=self.instance.pk).filter(email__iexact=email).exists():
            raise forms.ValidationError('Ya existe un usuario con este correo institucional.')
        return email

    def clean_username(self):
        username = self.cleaned_data.get('username')
        if username and Collaborator.objects.exclude(pk=self.instance.pk).filter(username__iexact=username).exists():
            raise forms.ValidationError('Este nombre de usuario ya está en uso.')
        return username

    def save(self, commit=True):
        collaborator = super().save(commit=False)
        password = self.cleaned_data.get('password')
        if password:
            collaborator.set_password(password)
        if commit:
            collaborator.save()
        return collaborator


class SecurityQuestionSetupForm(forms.Form):
    security_question = forms.ChoiceField(
        label='Pregunta de seguridad',
        choices=Collaborator.SECURITY_QUESTIONS,
    )
    security_answer = forms.CharField(
        label='Respuesta',
        max_length=128,
        widget=forms.TextInput(attrs={'autocomplete': 'off'}),
    )
    security_answer_confirm = forms.CharField(
        label='Confirma tu respuesta',
        max_length=128,
        widget=forms.TextInput(attrs={'autocomplete': 'off'}),
    )

    def clean(self):
        cleaned = super().clean()
        ans1 = cleaned.get('security_answer', '').strip().lower()
        ans2 = cleaned.get('security_answer_confirm', '').strip().lower()
        if ans1 and ans2 and ans1 != ans2:
            raise forms.ValidationError('Las respuestas no coinciden.')
        return cleaned


class PasswordRecoveryRequestForm(forms.Form):
    username = forms.CharField(label='Usuario', max_length=150)

    def clean_username(self):
        username = self.cleaned_data.get('username', '').strip()
        try:
            user = Collaborator.objects.get(username__iexact=username, is_active=True, is_deleted=False, is_revoked=False)
        except Collaborator.DoesNotExist:
            raise forms.ValidationError('No se encontró una cuenta activa con ese usuario.')
        if not user.security_question or not user.security_answer_hash:
            raise forms.ValidationError('Esta cuenta no tiene configurada una pregunta de seguridad. Contacta al administrador.')
        return username


class SecurityAnswerForm(forms.Form):
    answer = forms.CharField(
        label='Tu respuesta',
        max_length=128,
        widget=forms.TextInput(attrs={'autocomplete': 'off'}),
    )


class PasswordRecoveryResetForm(forms.Form):
    new_password1 = forms.CharField(label='Nueva contraseña', widget=forms.PasswordInput)
    new_password2 = forms.CharField(label='Confirma la contraseña', widget=forms.PasswordInput)

    def clean_new_password1(self):
        password = self.cleaned_data.get('new_password1')
        if password:
            validate_strong_password(password)
        return password

    def clean(self):
        cleaned = super().clean()
        p1 = cleaned.get('new_password1')
        p2 = cleaned.get('new_password2')
        if p1 and p2 and p1 != p2:
            raise forms.ValidationError('Las contraseñas no coinciden.')
        return cleaned


class CollaboratorSearchForm(forms.Form):
    query = forms.CharField(label='Buscar', required=False)
    area = forms.ModelChoiceField(label='Área', required=False, queryset=Area.objects.order_by('name'))
    access_level = forms.ChoiceField(
        label='Nivel',
        required=False,
        choices=[('', 'Todos los niveles')] + Collaborator.ACCESS_LEVEL_CHOICES,
    )
    status = forms.ChoiceField(
        label='Estado',
        required=False,
        choices=[('', 'Todos los estados'), ('active', 'Activo'), ('revoked', 'Revocado'), ('inactive', 'Inactivo'), ('deleted', 'Eliminado')],
    )
