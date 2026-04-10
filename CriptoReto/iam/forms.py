from django import forms
from django.contrib.auth import authenticate
from django.utils import timezone

from .models import Collaborator, Area


class LoginForm(forms.Form):
    username = forms.CharField(label='Usuario', max_length=150, widget=forms.TextInput(attrs={'autofocus': True}))
    password = forms.CharField(label='Contraseña', widget=forms.PasswordInput)
    otp = forms.CharField(label='Código MFA', required=False, widget=forms.TextInput(attrs={'placeholder': '123456'}))

    def clean(self):
        cleaned = super().clean()
        username = cleaned.get('username')
        password = cleaned.get('password')
        if username and password:
            user = authenticate(username=username, password=password)
            if user is None:
                raise forms.ValidationError('Usuario o contraseña incorrectos.')
            if not user.is_active or user.is_deleted or user.is_revoked:
                raise forms.ValidationError('Cuenta inactiva o revocada. Contacta al administrador.')
            cleaned['user'] = user
        return cleaned


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
            'role',
            'job_title',
            'onboarding_date',
            'mfa_enabled',
        ]
        widgets = {
            'onboarding_date': forms.DateInput(attrs={'type': 'date'}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['area'].queryset = Area.objects.order_by('name')
        self.fields['email'].help_text = 'Correo institucional válido.'
        self.fields['username'].help_text = 'Identificador único para el acceso.'

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
