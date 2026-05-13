from functools import wraps

from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.db.models import Q
from django.http import HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone

from .forms import (
    CollaboratorForm, CollaboratorSearchForm, LoginForm, OnboardingForm,
    SecurityQuestionSetupForm, PasswordRecoveryRequestForm,
    SecurityAnswerForm, PasswordRecoveryResetForm,
)
from .models import AuditLog, Collaborator, LoginAttempt, UserCertificate
from .certificates import (
    issue_encrypted_certificate,
    validate_encrypted_certificate,
    issue_coordinator_key_cert,
    validate_coordinator_cert_and_key,
    get_coordinator_key_bytes,
)


def get_client_ip(request):
    forwarded = request.META.get('HTTP_X_FORWARDED_FOR')
    if forwarded:
        return forwarded.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR')


def _is_onboarding_user(user):
    return hasattr(user, 'onboarding_status') and not user.is_system_admin() and (user.onboarding_pending or (user.onboarding_approved and not user.certificate_delivered_at))


def _is_onboarding_route(request):
    if not request.resolver_match:
        return False
    return request.resolver_match.url_name in ('onboarding', 'onboarding_download', 'logout')


def onboarding_required(view_func):
    @wraps(view_func)
    def _wrapped(request, *args, **kwargs):
        if request.user.is_authenticated and _is_onboarding_user(request.user):
            if not _is_onboarding_route(request):
                return redirect('iam:onboarding')
        return view_func(request, *args, **kwargs)
    return _wrapped


@login_required(login_url='iam:login')
@onboarding_required
def onboarding_view(request):
    user = request.user
    if user.is_system_admin():
        return redirect('iam:dashboard')
    if user.onboarding_status == Collaborator.ONBOARDING_STATUS_APPROVED and user.certificate_delivered_at:
        return redirect('iam:dashboard')

    certificate = getattr(user, 'certificate', None)
    cert_available = user.onboarding_approved and certificate is not None and certificate.is_valid

    if request.method == 'POST':
        form = OnboardingForm(request.POST, request.FILES, instance=user)
        if form.is_valid():
            collaborator = form.save(commit=False)
            collaborator.set_password(form.cleaned_data['new_password1'])
            collaborator.security_question = form.cleaned_data['security_question']
            collaborator.set_security_answer(form.cleaned_data['security_answer'])
            collaborator.save()
            messages.success(request, 'Tus datos fueron guardados. Espera la revisión del administrador.')
            return redirect('iam:onboarding')
    else:
        form = OnboardingForm(instance=user)

    return render(request, 'iam/onboarding.html', {
        'form': form,
        'certificate': certificate,
        'cert_available': cert_available,
        'certificate_filename': f'{user.username}.cert',
    })


@login_required(login_url='iam:login')
@onboarding_required
def onboarding_certificate_download_view(request):
    """Download the .cert file.  For coordinators also available separately."""
    user = request.user
    certificate = getattr(user, 'certificate', None)
    if not user.onboarding_approved or certificate is None or not certificate.is_valid:
        messages.error(request, 'Verificación pendiente. El certificado aún no está disponible.')
        return redirect('iam:onboarding')

    if not user.certificate_delivered_at:
        user.certificate_delivered_at = timezone.now()
        user.save(update_fields=['certificate_delivered_at'])

    response = HttpResponse(certificate.certificate_data, content_type='text/plain; charset=utf-8')
    response['Content-Disposition'] = f'attachment; filename="{user.username}.cert"'
    return response


@login_required(login_url='iam:login')
@onboarding_required
def onboarding_key_download_view(request):
    """Download the .key file (coordinators only)."""
    user = request.user
    if user.access_level != 2:
        messages.error(request, 'Este archivo solo está disponible para coordinadores.')
        return redirect('iam:onboarding')

    certificate = getattr(user, 'certificate', None)
    if not user.onboarding_approved or certificate is None or not certificate.is_valid:
        messages.error(request, 'Verificación pendiente. El certificado aún no está disponible.')
        return redirect('iam:onboarding')

    try:
        key_bytes = get_coordinator_key_bytes(certificate)
    except ValueError:
        messages.error(request, 'La llave privada no está disponible. Contacta al administrador.')
        return redirect('iam:onboarding')

    if not user.certificate_delivered_at:
        user.certificate_delivered_at = timezone.now()
        user.save(update_fields=['certificate_delivered_at'])

    response = HttpResponse(key_bytes, content_type='application/octet-stream')
    response['Content-Disposition'] = f'attachment; filename="{user.username}.key"'
    return response


@login_required(login_url='iam:login')
@onboarding_required
def pending_onboarding_view(request):
    if request.user.access_level not in (1, 2) and not request.user.is_staff:
        messages.error(request, 'No tienes permisos para ver los onboardings pendientes.')
        return redirect('iam:dashboard')

    collaborators = Collaborator.objects.filter(onboarding_status=Collaborator.ONBOARDING_STATUS_PENDING, is_deleted=False)
    return render(request, 'iam/pending_onboardings.html', {'collaborators': collaborators})


@login_required(login_url='iam:login')
@onboarding_required
def approve_onboarding_view(request, pk):
    if request.user.access_level not in (1, 2) and not request.user.is_staff:
        messages.error(request, 'No tienes permisos para aprobar onboardings.')
        return redirect('iam:dashboard')

    collaborator = get_object_or_404(Collaborator, pk=pk)
    if request.method == 'POST':
        collaborator.onboarding_status = Collaborator.ONBOARDING_STATUS_APPROVED
        collaborator.onboarding_approved_at = timezone.now()
        collaborator.onboarding_approved_by = request.user
        collaborator.save(update_fields=['onboarding_status', 'onboarding_approved_at', 'onboarding_approved_by'])
        try:
            if collaborator.access_level == 2:
                issue_coordinator_key_cert(collaborator, issued_by=request.user)
                msg = 'Onboarding aprobado. El coordinador podrá descargar los archivos .cert y .key desde su onboarding.'
            else:
                issue_encrypted_certificate(collaborator, issued_by=request.user)
                msg = 'Onboarding aprobado y certificado preparado. El usuario podrá descargar el archivo .cert desde su onboarding.'
        except PermissionError:
            msg = 'Onboarding aprobado (el certificado ya había sido emitido).'
        messages.success(request, msg)
        return redirect('iam:pending_onboarding')

    return render(request, 'iam/approve_onboarding.html', {'collaborator': collaborator})


def user_role_type_view(request):
    """
    AJAX endpoint: returns the role type for a given username.
    Used by the login form to show the appropriate certificate fields.
    Returns: {"role": "coordinator" | "admin" | "other" | "unknown"}
    """
    username = request.GET.get('u', '').strip()
    if not username:
        return JsonResponse({'role': 'unknown'})
    try:
        user = Collaborator.objects.get(username__iexact=username)
        if user.access_level == 1:
            role = 'admin'
        elif user.access_level == 2:
            role = 'coordinator'
        else:
            role = 'other'
    except Collaborator.DoesNotExist:
        role = 'unknown'
    return JsonResponse({'role': role})


def login_view(request):
    if request.user.is_authenticated:
        return redirect('iam:dashboard')

    form = LoginForm(request.POST or None, request.FILES or None)
    blocked = False

    if request.method == 'POST' and form.is_valid():
        username = form.cleaned_data['username']
        password = form.cleaned_data['password']
        otp = form.cleaned_data.get('otp')
        blocked = LoginAttempt.is_blocked(username)

        if blocked:
            messages.error(request, 'Demasiados intentos fallidos. Intenta de nuevo más tarde.')
        else:
            ip_address = get_client_ip(request)

            # Check account status before authenticating
            try:
                db_user = Collaborator.objects.get(username__iexact=username)
                if db_user.is_deleted:
                    LoginAttempt.objects.create(username=username, ip_address=ip_address, successful=False)
                    messages.error(request, 'Esta cuenta ha sido eliminada. Contacta al administrador.')
                    return render(request, 'iam/login.html', {'form': form, 'blocked': blocked})
                elif db_user.is_revoked:
                    LoginAttempt.objects.create(username=username, ip_address=ip_address, successful=False)
                    messages.error(request, 'Tu cuenta ha sido revocada. Contacta al administrador.')
                    return render(request, 'iam/login.html', {'form': form, 'blocked': blocked})
                elif not db_user.is_active:
                    LoginAttempt.objects.create(username=username, ip_address=ip_address, successful=False)
                    messages.error(request, 'Tu cuenta está inactiva. Contacta al administrador.')
                    return render(request, 'iam/login.html', {'form': form, 'blocked': blocked})
            except Collaborator.DoesNotExist:
                pass

            user = authenticate(request, username=username, password=password)
            if user is None:
                LoginAttempt.objects.create(username=username, ip_address=ip_address, successful=False)
                if Collaborator.objects.filter(username__iexact=username).exists():
                    messages.error(request, 'Contraseña incorrecta.')
                else:
                    messages.error(request, 'Usuario no encontrado.')
                return render(request, 'iam/login.html', {'form': form, 'blocked': blocked})

            # Redirect users mid-onboarding
            if not user.is_system_admin() and user.onboarding_pending:
                login(request, user)
                messages.info(request, 'Completa tu onboarding para continuar.')
                return redirect('iam:onboarding')

            if not user.is_system_admin() and user.onboarding_approved and not user.certificate_delivered_at:
                login(request, user)
                if getattr(user, 'certificate', None) and user.certificate.is_valid:
                    messages.info(request, 'Tu cuenta fue aprobada. Descarga tu certificado para acceder al sistema.')
                else:
                    messages.info(request, 'Tu cuenta fue aprobada. Espera la emisión del certificado.')
                return redirect('iam:onboarding')

            # MFA validation (applies to all roles)
            if user.mfa_enabled:
                if not otp or not user.verify_totp(otp):
                    LoginAttempt.objects.create(username=username, ip_address=ip_address, successful=False)
                    messages.error(request, 'Código MFA inválido.')
                    return render(request, 'iam/login.html', {'form': form, 'blocked': blocked})

            cert_validated = False

            # --- Coordinator: require both .cert and .key ---
            if user.access_level == 2:
                cert_file = form.cleaned_data.get('certificate')
                key_file = form.cleaned_data.get('key_file')
                if not cert_file or not key_file:
                    LoginAttempt.objects.create(username=username, ip_address=ip_address, successful=False)
                    messages.error(
                        request,
                        'Los coordinadores deben proporcionar el certificado digital (.cert) y la llave privada (.key).',
                    )
                    return render(request, 'iam/login.html', {'form': form, 'blocked': blocked})
                try:
                    cert_bytes = cert_file.read()
                    key_bytes = key_file.read()
                except Exception:
                    cert_bytes, key_bytes = b'', b''
                if not validate_coordinator_cert_and_key(user, cert_bytes, key_bytes):
                    LoginAttempt.objects.create(username=username, ip_address=ip_address, successful=False)
                    messages.error(request, 'El certificado digital o la llave privada son inválidos.')
                    return render(request, 'iam/login.html', {'form': form, 'blocked': blocked})
                cert_validated = True

            # --- Admin: optional legacy .cert (keep existing behavior) ---
            elif user.is_system_admin():
                certificate_file = form.cleaned_data.get('certificate')
                if certificate_file:
                    try:
                        certificate_str = certificate_file.read().decode('utf-8').strip()
                    except Exception:
                        certificate_str = ''
                    if certificate_str:
                        if not validate_encrypted_certificate(user, certificate_str):
                            LoginAttempt.objects.create(username=username, ip_address=ip_address, successful=False)
                            messages.error(request, 'Certificado inválido.')
                            return render(request, 'iam/login.html', {'form': form, 'blocked': blocked})
                        cert_validated = True

            # --- Other roles: no certificate required ---

            login(request, user)
            request.session['cert_validated'] = cert_validated
            LoginAttempt.objects.create(username=username, ip_address=ip_address, successful=True)

            audit_detail = 'Ingreso exitoso'
            if user.mfa_enabled:
                audit_detail += ' con MFA.'
            if cert_validated:
                audit_detail += ' Con certificado validado.'
            AuditLog.objects.create(actor=user, target=user, action='Inicio de sesión', details=audit_detail)
            return redirect('iam:dashboard')

    return render(request, 'iam/login.html', {'form': form, 'blocked': blocked})


@login_required(login_url='iam:login')
@onboarding_required
def logout_view(request):
    AuditLog.objects.create(actor=request.user, action='Cierre de sesión', details='Usuario cerró sesión.')
    logout(request)
    messages.success(request, 'Sesión cerrada correctamente.')
    return redirect('iam:login')


@login_required(login_url='iam:login')
@onboarding_required
def dashboard_view(request):
    if request.user.access_level == 1:
        collaborators = Collaborator.objects.filter(is_deleted=False)
    else:
        collaborators = Collaborator.objects.filter(is_deleted=False, area=request.user.area)

    if not request.user.is_system_admin() and (request.user.onboarding_pending or (request.user.onboarding_approved and not request.user.certificate_delivered_at)):
        return redirect('iam:onboarding')

    form = CollaboratorSearchForm(request.GET or None)
    if form.is_valid():
        query = form.cleaned_data.get('query')
        area = form.cleaned_data.get('area')
        access_level = form.cleaned_data.get('access_level')
        status = form.cleaned_data.get('status')
        if query:
            collaborators = collaborators.filter(
                Q(first_name__icontains=query)
                | Q(last_name__icontains=query)
                | Q(username__icontains=query)
                | Q(email__icontains=query)
            )
        if area:
            collaborators = collaborators.filter(area=area)
        if access_level:
            collaborators = collaborators.filter(access_level=access_level)
        if status:
            if status == 'active':
                collaborators = collaborators.filter(is_active=True, is_revoked=False, is_deleted=False)
            elif status == 'revoked':
                collaborators = collaborators.filter(is_revoked=True)
            elif status == 'inactive':
                collaborators = collaborators.filter(is_active=False, is_revoked=False, is_deleted=False)
            elif status == 'deleted':
                collaborators = collaborators.filter(is_deleted=True)

    total = collaborators.count()
    active = collaborators.filter(is_active=True, is_revoked=False, is_deleted=False).count()
    revoked = collaborators.filter(is_revoked=True).count()
    expired = collaborators.filter(is_deleted=True).count()

    pending_count = Collaborator.objects.filter(onboarding_status=Collaborator.ONBOARDING_STATUS_PENDING, is_deleted=False).count() if request.user.access_level in (1, 2) or request.user.is_staff else 0
    return render(request, 'iam/dashboard.html', {
        'collaborators': collaborators.select_related('area'),
        'form': form,
        'stats': {'total': total, 'active': active, 'revoked': revoked, 'deleted': expired},
        'pending_onboarding_count': pending_count,
    })


@login_required(login_url='iam:login')
@onboarding_required
def collaborator_detail_view(request, pk):
    collaborator = get_object_or_404(Collaborator, pk=pk)
    if not request.user.can_view(collaborator):
        messages.error(request, 'No tienes permisos para ver este colaborador.')
        return redirect('iam:dashboard')
    if collaborator == request.user and not request.user.is_system_admin() and (collaborator.onboarding_pending or (collaborator.onboarding_approved and not collaborator.certificate_delivered_at)):
        return redirect('iam:onboarding')
    logs = AuditLog.objects.filter(target=collaborator)[:20]
    certificate = getattr(collaborator, 'certificate', None)
    context = {
        'collaborator': collaborator,
        'logs': logs,
        'certificate': certificate,
        'can_edit': request.user.can_edit(collaborator),
        'can_activate': request.user.can_activate(collaborator),
        'can_delete': request.user.can_delete(collaborator),
        'can_issue_certificate': request.user.access_level >= 3 or request.user.is_staff,
    }
    return render(request, 'iam/collaborator_detail.html', context)


@login_required(login_url='iam:login')
@onboarding_required
def collaborator_create_view(request):
    if request.user.access_level not in (1, 2):
        messages.error(request, 'No tienes permisos para crear colaboradores.')
        return redirect('iam:dashboard')

    form = CollaboratorForm(request.POST or None)
    if request.method == 'POST' and form.is_valid():
        collaborator = form.save(commit=False)
        collaborator.created_by = request.user
        if not collaborator.password:
            collaborator.set_password('Temp2026!')
        collaborator.save()
        AuditLog.objects.create(
            actor=request.user,
            target=collaborator,
            action='Creación de colaborador',
            details=f'Nuevo colaborador creado por {request.user.username}.',
        )
        messages.success(request, 'Colaborador creado correctamente.')
        return redirect('iam:detail', pk=collaborator.pk)

    return render(request, 'iam/collaborator_form.html', {'form': form, 'title': 'Alta de colaborador'})


@login_required(login_url='iam:login')
@onboarding_required
def collaborator_edit_view(request, pk):
    collaborator = get_object_or_404(Collaborator, pk=pk)
    if not request.user.can_edit(collaborator):
        messages.error(request, 'No tienes permisos para editar este colaborador.')
        return redirect('iam:dashboard')

    form = CollaboratorForm(request.POST or None, instance=collaborator)
    if request.method == 'POST' and form.is_valid():
        collaborator = form.save(commit=False)
        collaborator.save()
        AuditLog.objects.create(
            actor=request.user,
            target=collaborator,
            action='Edición de colaborador',
            details=f'Colaborador editado por {request.user.username}.',
        )
        messages.success(request, 'Colaborador actualizado correctamente.')
        return redirect('iam:detail', pk=collaborator.pk)

    return render(request, 'iam/collaborator_form.html', {'form': form, 'title': 'Editar colaborador'})


@login_required(login_url='iam:login')
@onboarding_required
def collaborator_toggle_view(request, pk):
    collaborator = get_object_or_404(Collaborator, pk=pk)
    if not request.user.can_activate(collaborator):
        messages.error(request, 'No tienes permisos para cambiar el estado de este colaborador.')
        return redirect('iam:dashboard')

    if collaborator.is_deleted:
        messages.error(request, 'No se puede cambiar el estado de un colaborador eliminado.')
        return redirect('iam:detail', pk=collaborator.pk)

    if collaborator.is_active:
        collaborator.is_active = False
        collaborator.is_revoked = False
        action = 'Desactivación de acceso'
        messages.success(request, 'Colaborador desactivado correctamente.')
    else:
        collaborator.is_active = True
        collaborator.is_revoked = False
        collaborator.revoked_at = None
        collaborator.revoked_by = None
        action = 'Reactivación de acceso'
        messages.success(request, 'Acceso reactivado correctamente.')

    collaborator.save()
    AuditLog.objects.create(actor=request.user, target=collaborator, action=action, details=f'Proceso ejecutado por {request.user.username}.')
    return redirect('iam:detail', pk=collaborator.pk)


@login_required(login_url='iam:login')
@onboarding_required
def collaborator_revoke_view(request, pk):
    collaborator = get_object_or_404(Collaborator, pk=pk)
    if not request.user.can_activate(collaborator):
        messages.error(request, 'No tienes permisos para revocar el acceso de este colaborador.')
        return redirect('iam:dashboard')

    if collaborator.is_deleted:
        messages.error(request, 'No se puede revocar el acceso de un colaborador eliminado.')
        return redirect('iam:detail', pk=collaborator.pk)

    if collaborator.is_revoked:
        messages.error(request, 'El acceso de este colaborador ya está revocado.')
        return redirect('iam:detail', pk=collaborator.pk)

    collaborator.is_active = False
    collaborator.is_revoked = True
    collaborator.revoked_at = timezone.now()
    collaborator.revoked_by = request.user
    collaborator.save()
    AuditLog.objects.create(actor=request.user, target=collaborator, action='Revocación de acceso', details=f'Proceso ejecutado por {request.user.username}.')
    messages.success(request, 'Acceso revocado correctamente.')
    return redirect('iam:detail', pk=collaborator.pk)


@login_required(login_url='iam:login')
@onboarding_required
def collaborator_delete_view(request, pk):
    collaborator = get_object_or_404(Collaborator, pk=pk)
    if not request.user.can_delete(collaborator):
        messages.error(request, 'No tienes permisos para eliminar este colaborador.')
        return redirect('iam:dashboard')

    collaborator.is_deleted = True
    collaborator.is_active = False
    collaborator.deleted_at = timezone.now()
    collaborator.save()
    AuditLog.objects.create(
        actor=request.user,
        target=collaborator,
        action='Eliminación lógica',
        details=f'Colaborador marcado como eliminado por {request.user.username}.',
    )
    messages.success(request, 'Colaborador eliminado correctamente.')
    return redirect('iam:dashboard')


@login_required(login_url='iam:login')
@onboarding_required
def issue_certificate_view(request, pk):
    collaborator = get_object_or_404(Collaborator, pk=pk)
    if request.user.access_level < 3 and not request.user.is_staff:
        messages.error(request, 'No tienes permisos para expedir certificados.')
        return redirect('iam:dashboard')

    issued_certificate = None
    certificate_filename = None
    is_coordinator = collaborator.access_level == 2
    if request.method == 'POST':
        try:
            if is_coordinator:
                certificate = issue_coordinator_key_cert(collaborator, issued_by=request.user)
            else:
                certificate = issue_encrypted_certificate(collaborator, issued_by=request.user)
            issued_certificate = certificate.certificate_data
            certificate_filename = f'{collaborator.username}.cert'
            messages.success(request, 'Certificado emitido correctamente.')
        except PermissionError as exc:
            messages.error(request, str(exc))

    return render(request, 'iam/certificate_issue.html', {
        'collaborator': collaborator,
        'issued_certificate': issued_certificate,
        'certificate_filename': certificate_filename,
        'is_coordinator': is_coordinator,
    })


@login_required(login_url='iam:login')
@onboarding_required
def validate_certificate_view(request, pk):
    collaborator = get_object_or_404(Collaborator, pk=pk)
    certificate_string = ''
    if request.method == 'POST':
        certificate_string = request.POST.get('certificate', '').strip()
        if not certificate_string:
            messages.error(request, 'Debes proporcionar una cadena de certificado.')
        else:
            valid = validate_encrypted_certificate(collaborator, certificate_string)
            if valid:
                messages.success(request, 'Certificado validado correctamente.')
            else:
                messages.error(request, 'La validación del certificado falló.')

    return render(request, 'iam/certificate_validate.html', {
        'collaborator': collaborator,
        'certificate': certificate_string,
    })


@login_required(login_url='iam:login')
@onboarding_required
def revoke_certificate_view(request, pk):
    if request.method != 'POST':
        messages.error(request, 'Solicitud no válida.')
        return redirect('iam:detail', pk=pk)

    if not request.user.is_staff:
        messages.error(request, 'No tienes permisos para revocar certificados.')
        return redirect('iam:dashboard')

    collaborator = get_object_or_404(Collaborator, pk=pk)
    certificate = get_object_or_404(UserCertificate, collaborator=collaborator)
    certificate.is_revoked = True
    certificate.revoked_at = timezone.now()
    certificate.revoked_by = request.user
    certificate.save()
    AuditLog.objects.create(
        actor=request.user,
        target=collaborator,
        action='CERTIFICATE_REVOKED',
        details=certificate.fingerprint,
    )
    messages.success(request, 'Certificado revocado correctamente.')
    return redirect('iam:detail', pk=collaborator.pk)


@login_required(login_url='iam:login')
@onboarding_required
def audit_log_view(request):
    if request.user.access_level == 1:
        logs = AuditLog.objects.all()
    else:
        logs = AuditLog.objects.filter(actor__area=request.user.area) | AuditLog.objects.filter(target__area=request.user.area)
    logs = logs.select_related('actor', 'target')[:100]
    return render(request, 'iam/audit_log.html', {'logs': logs})


@login_required(login_url='iam:login')
def security_question_setup_view(request):
    user = request.user
    form = SecurityQuestionSetupForm(request.POST or None)
    if request.method == 'POST' and form.is_valid():
        user.security_question = form.cleaned_data['security_question']
        user.set_security_answer(form.cleaned_data['security_answer'])
        user.save(update_fields=['security_question', 'security_answer_hash'])
        AuditLog.objects.create(
            actor=user,
            target=user,
            action='Configuración pregunta de seguridad',
            details='El usuario configuró su pregunta de seguridad.',
        )
        messages.success(request, 'Pregunta de seguridad guardada correctamente.')
        return redirect('iam:dashboard')
    return render(request, 'iam/security_question_setup.html', {'form': form, 'already_set': bool(user.security_question)})


def password_recovery_request_view(request):
    if request.user.is_authenticated:
        return redirect('iam:dashboard')
    form = PasswordRecoveryRequestForm(request.POST or None)
    if request.method == 'POST' and form.is_valid():
        request.session['recovery_username'] = form.cleaned_data['username']
        request.session['recovery_step'] = 'answer'
        return redirect('iam:password_recovery_answer')
    return render(request, 'iam/password_recovery_request.html', {'form': form})


def password_recovery_answer_view(request):
    if request.user.is_authenticated:
        return redirect('iam:dashboard')
    username = request.session.get('recovery_username')
    if not username or request.session.get('recovery_step') != 'answer':
        return redirect('iam:password_recovery_request')
    try:
        user = Collaborator.objects.get(username__iexact=username, is_active=True, is_deleted=False, is_revoked=False)
    except Collaborator.DoesNotExist:
        return redirect('iam:password_recovery_request')

    question_label = dict(Collaborator.SECURITY_QUESTIONS).get(user.security_question, '')
    form = SecurityAnswerForm(request.POST or None)
    if request.method == 'POST' and form.is_valid():
        if user.check_security_answer(form.cleaned_data['answer']):
            request.session['recovery_step'] = 'reset'
            return redirect('iam:password_recovery_reset')
        messages.error(request, 'Respuesta incorrecta. Inténtalo de nuevo.')
    return render(request, 'iam/password_recovery_answer.html', {'form': form, 'question': question_label})


def password_recovery_reset_view(request):
    if request.user.is_authenticated:
        return redirect('iam:dashboard')
    username = request.session.get('recovery_username')
    if not username or request.session.get('recovery_step') != 'reset':
        return redirect('iam:password_recovery_request')
    try:
        user = Collaborator.objects.get(username__iexact=username, is_active=True, is_deleted=False, is_revoked=False)
    except Collaborator.DoesNotExist:
        return redirect('iam:password_recovery_request')

    form = PasswordRecoveryResetForm(request.POST or None)
    if request.method == 'POST' and form.is_valid():
        user.set_password(form.cleaned_data['new_password1'])
        user.save(update_fields=['password'])
        AuditLog.objects.create(
            actor=user,
            target=user,
            action='Recuperación de contraseña',
            details='El usuario restableció su contraseña mediante pregunta de seguridad.',
        )
        request.session.pop('recovery_username', None)
        request.session.pop('recovery_step', None)
        messages.success(request, 'Contraseña restablecida correctamente. Ya puedes iniciar sesión.')
        return redirect('iam:login')
    return render(request, 'iam/password_recovery_reset.html', {'form': form})
