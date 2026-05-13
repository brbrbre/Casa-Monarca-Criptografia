from functools import wraps

from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.db.models import Q
from django.http import HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone

from .decorators import require_access_level, require_admin, require_post
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


def _log(actor, action, details='', target=None, request=None):
    """Centralised audit helper that serialises IP, actor level and area into details."""
    ip = get_client_ip(request) if request else None
    actor_level = getattr(actor, 'access_level', None)
    actor_area_name = str(actor.area) if getattr(actor, 'area', None) else ''
    full_details = details
    if actor_level:
        full_details = f'[Nivel {actor_level}] {full_details}'
    if actor_area_name:
        full_details = f'[Área: {actor_area_name}] {full_details}'
    if ip:
        full_details = f'{full_details} | IP: {ip}'
    AuditLog.objects.create(actor=actor, target=target, action=action, details=full_details.strip())


# ─────────────────────────────────────────────
# ONBOARDING GATE — state machine
# ─────────────────────────────────────────────

def _coordinator_needs_relogin(user, request):
    """
    A coordinator who downloaded both files in this session must re-login.
    We detect this by checking that certificate_delivered_at is set
    but the current session was NOT authenticated with a cert (cert_validated=False).
    """
    return (
        user.access_level == 2
        and user.onboarding_approved
        and user.certificate_delivered_at
        and not request.session.get('cert_validated', False)
    )


def _is_onboarding_user(user, request=None):
    """Return True when the user must be kept behind the onboarding gate."""
    if not hasattr(user, 'onboarding_status') or user.is_system_admin():
        return False
    # Not yet submitted the form
    if user.onboarding_status == Collaborator.ONBOARDING_STATUS_PENDING:
        return True
    # Submitted but not yet approved
    if user.onboarding_status == Collaborator.ONBOARDING_STATUS_SUBMITTED:
        return True
    # Rejected — keep blocked until admin reactivates
    if user.onboarding_status == Collaborator.ONBOARDING_STATUS_REJECTED:
        return True
    # Approved but coordinator hasn't downloaded both credential files yet
    if user.onboarding_approved and not user.certificate_delivered_at:
        return True
    # Coordinator downloaded files in current session without a fresh cert-authenticated login
    if request and _coordinator_needs_relogin(user, request):
        return True
    return False


def _is_onboarding_route(request):
    if not request.resolver_match:
        return False
    return request.resolver_match.url_name in (
        'onboarding', 'onboarding_download', 'onboarding_key_download', 'logout',
    )


def onboarding_required(view_func):
    @wraps(view_func)
    def _wrapped(request, *args, **kwargs):
        if request.user.is_authenticated and _is_onboarding_user(request.user, request):
            if not _is_onboarding_route(request):
                return redirect('iam:onboarding')
        return view_func(request, *args, **kwargs)
    return _wrapped


# ─────────────────────────────────────────────
# ONBOARDING VIEWS
# ─────────────────────────────────────────────

@login_required(login_url='iam:login')
@onboarding_required
def onboarding_view(request):
    """
    Central onboarding hub. Shows a different screen depending on state:
      pending   → fill-in form
      submitted → waiting-for-approval screen (read-only data)
      approved + downloads pending → download .cert / .key
      approved + downloaded + no cert_validated session → re-login prompt
      rejected  → rejection notice
    """
    user = request.user

    if user.is_system_admin():
        return redirect('iam:dashboard')

    # Fully onboarded and authenticated with cert → go to dashboard
    if user.onboarding_approved and user.certificate_delivered_at and not _coordinator_needs_relogin(user, request):
        return redirect('iam:dashboard')

    is_coordinator = (user.access_level == 2)

    # ── State: re-login needed (coordinator downloaded credentials this session) ──
    if is_coordinator and _coordinator_needs_relogin(user, request):
        return render(request, 'iam/onboarding.html', {
            'onboarding_state': 'relogin_needed',
            'is_coordinator': True,
        })

    # ── State: approved + downloads pending ──
    if user.onboarding_approved and not user.certificate_delivered_at:
        certificate = getattr(user, 'certificate', None)
        cert_available = is_coordinator and certificate is not None and certificate.is_valid
        return render(request, 'iam/onboarding.html', {
            'onboarding_state': 'download',
            'is_coordinator': is_coordinator,
            'certificate': certificate,
            'cert_available': cert_available,
            'cert_file_downloaded': user.cert_file_downloaded,
            'key_file_downloaded': user.key_file_downloaded,
            'certificate_filename': f'{user.username}.cert',
        })

    # ── State: submitted, waiting for admin review ──
    if user.onboarding_submitted:
        return render(request, 'iam/onboarding.html', {
            'onboarding_state': 'submitted',
            'is_coordinator': is_coordinator,
            'submitted_at': user.onboarding_submitted_at,
        })

    # ── State: rejected ──
    if user.onboarding_rejected:
        return render(request, 'iam/onboarding.html', {
            'onboarding_state': 'rejected',
            'is_coordinator': is_coordinator,
        })

    # ── State: pending — show the onboarding form ──
    if request.method == 'POST':
        form = OnboardingForm(request.POST, request.FILES, instance=user)
        if form.is_valid():
            collaborator = form.save(commit=False)
            collaborator.set_password(form.cleaned_data['new_password1'])
            collaborator.security_question = form.cleaned_data['security_question']
            collaborator.set_security_answer(form.cleaned_data['security_answer'])
            collaborator.onboarding_status = Collaborator.ONBOARDING_STATUS_SUBMITTED
            collaborator.onboarding_submitted_at = timezone.now()
            collaborator.save()
            _log(user, 'Onboarding enviado', 'El colaborador completó y envió su formulario de onboarding.', target=user, request=request)
            messages.success(request, 'Tus datos fueron enviados. Espera la revisión del administrador.')
            return redirect('iam:onboarding')
    else:
        form = OnboardingForm(instance=user)

    return render(request, 'iam/onboarding.html', {
        'onboarding_state': 'pending',
        'form': form,
        'is_coordinator': is_coordinator,
    })


@login_required(login_url='iam:login')
@onboarding_required
def onboarding_certificate_download_view(request):
    """Download the .cert file. Only available after approval."""
    user = request.user
    certificate = getattr(user, 'certificate', None)

    if not user.onboarding_approved or certificate is None or not certificate.is_valid:
        messages.error(request, 'El certificado aún no está disponible.')
        return redirect('iam:onboarding')

    # Mark cert as downloaded
    if not user.cert_file_downloaded:
        user.cert_file_downloaded = True
        user.save(update_fields=['cert_file_downloaded'])

    # If both files now downloaded, mark delivered and force re-login
    if user.cert_file_downloaded and user.key_file_downloaded and not user.certificate_delivered_at:
        user.certificate_delivered_at = timezone.now()
        user.save(update_fields=['certificate_delivered_at'])
        _log(user, 'Credenciales descargadas', 'Coordinador descargó .cert y .key. Sesión requiere reautenticación.', target=user, request=request)

    response = HttpResponse(certificate.certificate_data, content_type='text/plain; charset=utf-8')
    response['Content-Disposition'] = f'attachment; filename="{user.username}.cert"'
    return response


@login_required(login_url='iam:login')
@onboarding_required
def onboarding_key_download_view(request):
    """Download the .key file. Coordinators only."""
    user = request.user
    if user.access_level != 2:
        messages.error(request, 'Este archivo solo está disponible para coordinadores.')
        return redirect('iam:onboarding')

    certificate = getattr(user, 'certificate', None)
    if not user.onboarding_approved or certificate is None or not certificate.is_valid:
        messages.error(request, 'El certificado aún no está disponible.')
        return redirect('iam:onboarding')

    try:
        key_bytes = get_coordinator_key_bytes(certificate)
    except ValueError:
        messages.error(request, 'La llave privada no está disponible. Contacta al administrador.')
        return redirect('iam:onboarding')

    # Mark key as downloaded
    if not user.key_file_downloaded:
        user.key_file_downloaded = True
        user.save(update_fields=['key_file_downloaded'])

    # If both files now downloaded, mark delivered and force re-login
    if user.cert_file_downloaded and user.key_file_downloaded and not user.certificate_delivered_at:
        user.certificate_delivered_at = timezone.now()
        user.save(update_fields=['certificate_delivered_at'])
        _log(user, 'Credenciales descargadas', 'Coordinador descargó .cert y .key. Sesión requiere reautenticación.', target=user, request=request)

    response = HttpResponse(key_bytes, content_type='application/octet-stream')
    response['Content-Disposition'] = f'attachment; filename="{user.username}.key"'
    return response


@login_required(login_url='iam:login')
@onboarding_required
def pending_onboarding_view(request):
    user = request.user
    if user.access_level not in (1, 2) and not user.is_staff:
        messages.error(request, 'No tienes permisos para ver los onboardings pendientes.')
        return redirect('iam:dashboard')

    # Show users in 'pending' (not yet submitted form) AND 'submitted' (ready for review)
    collaborators = Collaborator.objects.filter(
        onboarding_status__in=[
            Collaborator.ONBOARDING_STATUS_PENDING,
            Collaborator.ONBOARDING_STATUS_SUBMITTED,
        ],
        is_deleted=False,
    ).select_related('area').order_by('onboarding_submitted_at', 'onboarding_requested_at')

    if user.access_level == 2:
        collaborators = collaborators.filter(area=user.area)

    return render(request, 'iam/pending_onboardings.html', {'collaborators': collaborators})


@login_required(login_url='iam:login')
@onboarding_required
def approve_onboarding_view(request, pk):
    user = request.user
    if user.access_level not in (1, 2) and not user.is_staff:
        messages.error(request, 'No tienes permisos para aprobar onboardings.')
        return redirect('iam:dashboard')

    collaborator = get_object_or_404(Collaborator, pk=pk)

    # Level 2 can only approve within their area and cannot approve Level 1
    if user.access_level == 2:
        if collaborator.area != user.area:
            messages.error(request, 'No puedes aprobar onboardings de otras áreas.')
            return redirect('iam:pending_onboarding')
        if collaborator.access_level == 1:
            messages.error(request, 'No puedes aprobar cuentas de Nivel 1. Contacta al administrador.')
            return redirect('iam:pending_onboarding')

    if request.method == 'POST':
        # ── BLOCK: collaborator must have completed onboarding first ──
        if not collaborator.onboarding_complete:
            missing = []
            if collaborator.onboarding_status != Collaborator.ONBOARDING_STATUS_SUBMITTED:
                missing.append('el colaborador aún no envió el formulario de onboarding')
            else:
                if not collaborator.first_name.strip():
                    missing.append('nombre')
                if not collaborator.last_name.strip():
                    missing.append('apellidos')
                if not collaborator.official_id_document:
                    missing.append('identificación oficial (INE)')
                if not collaborator.security_question:
                    missing.append('pregunta de seguridad')
                if not collaborator.security_answer_hash:
                    missing.append('respuesta de seguridad')
            detail = '; '.join(missing) if missing else 'datos incompletos'
            messages.error(request, f'No se puede aprobar: {detail}.')
            return redirect('iam:approve_onboarding', pk=pk)

        collaborator.onboarding_status = Collaborator.ONBOARDING_STATUS_APPROVED
        collaborator.onboarding_approved_at = timezone.now()
        collaborator.onboarding_approved_by = user
        collaborator.save(update_fields=['onboarding_status', 'onboarding_approved_at', 'onboarding_approved_by'])

        if collaborator.access_level == 2:
            try:
                issue_coordinator_key_cert(collaborator, issued_by=user)
                msg = 'Onboarding aprobado. El coordinador recibirá el aviso para descargar sus archivos .cert y .key.'
            except PermissionError:
                msg = 'Onboarding aprobado (los archivos de firma ya habían sido emitidos).'
        else:
            collaborator.certificate_delivered_at = timezone.now()
            collaborator.save(update_fields=['certificate_delivered_at'])
            msg = 'Onboarding aprobado. El usuario ya puede acceder al sistema.'

        _log(user, 'Aprobación de onboarding', f'Onboarding aprobado para {collaborator.username}.', target=collaborator, request=request)
        messages.success(request, msg)
        return redirect('iam:pending_onboarding')

    # Check completeness to show warnings in the confirmation page
    return render(request, 'iam/approve_onboarding.html', {
        'collaborator': collaborator,
        'can_approve': collaborator.onboarding_complete,
        'missing_fields': _onboarding_missing_fields(collaborator),
    })


def _onboarding_missing_fields(collaborator):
    """Return a list of human-readable missing field names for the approval UI."""
    if collaborator.onboarding_status != Collaborator.ONBOARDING_STATUS_SUBMITTED:
        return ['formulario de onboarding no enviado']
    missing = []
    if not collaborator.first_name.strip():
        missing.append('Nombre')
    if not collaborator.last_name.strip():
        missing.append('Apellidos')
    if not collaborator.official_id_document:
        missing.append('Identificación oficial (INE)')
    if not collaborator.security_question:
        missing.append('Pregunta de seguridad')
    if not collaborator.security_answer_hash:
        missing.append('Respuesta de seguridad')
    return missing


# ─────────────────────────────────────────────
# AUTH
# ─────────────────────────────────────────────

def user_role_type_view(request):
    """AJAX: returns role type for a username (used by login form only)."""
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

    credentials_ready = request.GET.get('credentials_ready') == '1'
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
                return render(request, 'iam/login.html', {'form': form, 'blocked': blocked, 'credentials_ready': credentials_ready})

            # ── Coordinator still in onboarding (pending / submitted / approved but no cert) ──
            # Skip the cert+key check and redirect to the onboarding hub.
            if user.access_level == 2 and not user.is_system_admin():
                still_onboarding = (
                    user.onboarding_status in (
                        Collaborator.ONBOARDING_STATUS_PENDING,
                        Collaborator.ONBOARDING_STATUS_SUBMITTED,
                        Collaborator.ONBOARDING_STATUS_REJECTED,
                    )
                    or (user.onboarding_approved and not user.certificate_delivered_at)
                )
                if still_onboarding:
                    login(request, user)
                    request.session['cert_validated'] = False
                    LoginAttempt.objects.create(username=username, ip_address=ip_address, successful=True)
                    return redirect('iam:onboarding')

            # Non-coordinator onboarding redirect (level 3/4)
            if not user.is_system_admin() and user.access_level != 2:
                if user.onboarding_pending or user.onboarding_submitted:
                    login(request, user)
                    request.session['cert_validated'] = False
                    LoginAttempt.objects.create(username=username, ip_address=ip_address, successful=True)
                    return redirect('iam:onboarding')
                if user.onboarding_approved and not user.certificate_delivered_at:
                    user.certificate_delivered_at = timezone.now()
                    user.save(update_fields=['certificate_delivered_at'])

            # MFA
            if user.mfa_enabled:
                if not otp or not user.verify_totp(otp):
                    LoginAttempt.objects.create(username=username, ip_address=ip_address, successful=False)
                    messages.error(request, 'Código MFA inválido.')
                    return render(request, 'iam/login.html', {'form': form, 'blocked': blocked, 'credentials_ready': credentials_ready})

            cert_validated = False

            # ── Coordinator: require both .cert and .key (fully-onboarded sessions only) ──
            if user.access_level == 2:
                cert_file = form.cleaned_data.get('certificate')
                key_file = form.cleaned_data.get('key_file')
                if not cert_file or not key_file:
                    LoginAttempt.objects.create(username=username, ip_address=ip_address, successful=False)
                    messages.error(
                        request,
                        'Los coordinadores deben proporcionar el certificado digital (.cert) y la llave privada (.key).',
                    )
                    return render(request, 'iam/login.html', {'form': form, 'blocked': blocked, 'credentials_ready': credentials_ready})
                try:
                    cert_bytes = cert_file.read()
                    key_bytes = key_file.read()
                except Exception:
                    cert_bytes, key_bytes = b'', b''
                if not validate_coordinator_cert_and_key(user, cert_bytes, key_bytes):
                    LoginAttempt.objects.create(username=username, ip_address=ip_address, successful=False)
                    messages.error(request, 'El certificado digital o la llave privada son inválidos.')
                    return render(request, 'iam/login.html', {'form': form, 'blocked': blocked, 'credentials_ready': credentials_ready})
                cert_validated = True

            # ── Admin: optional legacy .cert ──
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
                            return render(request, 'iam/login.html', {'form': form, 'blocked': blocked, 'credentials_ready': credentials_ready})
                        cert_validated = True

            login(request, user)
            request.session['cert_validated'] = cert_validated
            LoginAttempt.objects.create(username=username, ip_address=ip_address, successful=True)

            audit_detail = 'Ingreso exitoso'
            if user.mfa_enabled:
                audit_detail += ' con MFA.'
            if cert_validated:
                audit_detail += ' Con certificado validado.'
            _log(user, 'Inicio de sesión', audit_detail, target=user, request=request)
            return redirect('iam:dashboard')

    return render(request, 'iam/login.html', {'form': form, 'blocked': blocked, 'credentials_ready': credentials_ready})


@login_required(login_url='iam:login')
@onboarding_required
def logout_view(request):
    _log(request.user, 'Cierre de sesión', 'Usuario cerró sesión.', request=request)
    logout(request)
    messages.success(request, 'Sesión cerrada correctamente.')
    return redirect('iam:login')


# ─────────────────────────────────────────────
# DASHBOARD
# ─────────────────────────────────────────────

@login_required(login_url='iam:login')
@onboarding_required
def dashboard_view(request):
    user = request.user

    # Level 4 (external) has no access to the internal dashboard
    if user.access_level == 4:
        messages.info(request, 'Tu perfil está disponible a continuación.')
        return redirect('iam:detail', pk=user.pk)

    if user.access_level == 1:
        collaborators = Collaborator.objects.filter(is_deleted=False)
    elif user.access_level == 2:
        collaborators = Collaborator.objects.filter(is_deleted=False, area=user.area)
    else:
        # Level 3: only themselves
        collaborators = Collaborator.objects.filter(pk=user.pk)

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
        # Non-admins cannot override area filter via URL
        if area and user.access_level == 1:
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

    if user.access_level == 1 or user.is_staff:
        pending_count = Collaborator.objects.filter(
            onboarding_status__in=[Collaborator.ONBOARDING_STATUS_PENDING, Collaborator.ONBOARDING_STATUS_SUBMITTED],
            is_deleted=False,
        ).count()
    elif user.access_level == 2:
        pending_count = Collaborator.objects.filter(
            onboarding_status__in=[Collaborator.ONBOARDING_STATUS_PENDING, Collaborator.ONBOARDING_STATUS_SUBMITTED],
            is_deleted=False,
            area=user.area,
        ).count()
    else:
        pending_count = 0

    return render(request, 'iam/dashboard.html', {
        'collaborators': collaborators.select_related('area'),
        'form': form,
        'stats': {'total': total, 'active': active, 'revoked': revoked, 'deleted': expired},
        'pending_onboarding_count': pending_count,
    })


# ─────────────────────────────────────────────
# COLLABORATOR CRUD
# ─────────────────────────────────────────────

@login_required(login_url='iam:login')
@onboarding_required
def collaborator_detail_view(request, pk):
    user = request.user
    collaborator = get_object_or_404(Collaborator, pk=pk)

    if not user.can_view(collaborator):
        messages.error(request, 'No tienes permisos para ver este colaborador.')
        return redirect('iam:dashboard')

    if collaborator == user and not user.is_system_admin() and (
        collaborator.onboarding_pending or collaborator.onboarding_submitted or
        (collaborator.onboarding_approved and not collaborator.certificate_delivered_at)
    ):
        return redirect('iam:onboarding')

    # Audit logs: only Level 1 (global) and Level 2 (own area)
    show_logs = user.access_level == 1 or (
        user.access_level == 2 and collaborator.area == user.area
    )
    logs = AuditLog.objects.filter(target=collaborator).select_related('actor')[:20] if show_logs else []

    # Onboarding data for admin review (no security Q/A, no hashes)
    show_onboarding_data = user.access_level <= 2
    onboarding_submitted_at = collaborator.onboarding_submitted_at if show_onboarding_data else None

    certificate = getattr(collaborator, 'certificate', None)
    context = {
        'collaborator': collaborator,
        'logs': logs,
        'show_logs': show_logs,
        'certificate': certificate,
        'can_edit': user.can_edit(collaborator),
        'can_activate': user.can_activate(collaborator),
        'can_delete': user.can_delete(collaborator),
        'can_issue_certificate': user.access_level == 1,
        'can_revoke_certificate': user.access_level == 1,
        'show_onboarding_data': show_onboarding_data,
        'onboarding_submitted_at': onboarding_submitted_at,
        'onboarding_missing_fields': _onboarding_missing_fields(collaborator) if show_onboarding_data else [],
    }
    return render(request, 'iam/collaborator_detail.html', context)


@login_required(login_url='iam:login')
@onboarding_required
def collaborator_create_view(request):
    user = request.user
    if user.access_level not in (1, 2):
        messages.error(request, 'No tienes permisos para crear colaboradores.')
        return redirect('iam:dashboard')

    form = CollaboratorForm(request.POST or None, current_user=user)
    if request.method == 'POST' and form.is_valid():
        collaborator = form.save(commit=False)
        collaborator.created_by = user
        if not collaborator.password:
            collaborator.set_password('Temp2026!')
        if user.access_level == 2:
            if collaborator.access_level < 3:
                collaborator.access_level = 3
            collaborator.area = user.area
        collaborator.save()
        _log(user, 'Creación de colaborador', f'Nuevo colaborador {collaborator.username} creado.', target=collaborator, request=request)
        messages.success(request, 'Colaborador creado correctamente.')
        return redirect('iam:detail', pk=collaborator.pk)

    return render(request, 'iam/collaborator_form.html', {'form': form, 'title': 'Alta de colaborador'})


@login_required(login_url='iam:login')
@onboarding_required
def collaborator_edit_view(request, pk):
    user = request.user
    collaborator = get_object_or_404(Collaborator, pk=pk)
    if not user.can_edit(collaborator):
        messages.error(request, 'No tienes permisos para editar este colaborador.')
        return redirect('iam:dashboard')

    form = CollaboratorForm(request.POST or None, instance=collaborator, current_user=user)
    if request.method == 'POST' and form.is_valid():
        updated = form.save(commit=False)
        if user.access_level == 2:
            # Prevent privilege escalation
            updated.access_level = collaborator.access_level
            updated.area = collaborator.area
        updated.save()
        _log(user, 'Edición de colaborador', f'Colaborador {collaborator.username} editado.', target=collaborator, request=request)
        messages.success(request, 'Colaborador actualizado correctamente.')
        return redirect('iam:detail', pk=collaborator.pk)

    return render(request, 'iam/collaborator_form.html', {'form': form, 'title': 'Editar colaborador'})


@login_required(login_url='iam:login')
@onboarding_required
@require_post
def collaborator_toggle_view(request, pk):
    user = request.user
    collaborator = get_object_or_404(Collaborator, pk=pk)
    if not user.can_activate(collaborator):
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
    _log(user, action, f'Estado de {collaborator.username} cambiado.', target=collaborator, request=request)
    return redirect('iam:detail', pk=collaborator.pk)


@login_required(login_url='iam:login')
@onboarding_required
@require_post
def collaborator_revoke_view(request, pk):
    user = request.user
    collaborator = get_object_or_404(Collaborator, pk=pk)
    if not user.can_activate(collaborator):
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
    collaborator.revoked_by = user
    collaborator.save()
    _log(user, 'Revocación de acceso', f'Acceso de {collaborator.username} revocado.', target=collaborator, request=request)
    messages.success(request, 'Acceso revocado correctamente.')
    return redirect('iam:detail', pk=collaborator.pk)


@login_required(login_url='iam:login')
@onboarding_required
@require_post
def collaborator_delete_view(request, pk):
    user = request.user
    collaborator = get_object_or_404(Collaborator, pk=pk)
    if not user.can_delete(collaborator):
        messages.error(request, 'No tienes permisos para eliminar este colaborador.')
        return redirect('iam:dashboard')

    collaborator.is_deleted = True
    collaborator.is_active = False
    collaborator.deleted_at = timezone.now()
    collaborator.save()
    _log(user, 'Eliminación lógica', f'Colaborador {collaborator.username} marcado como eliminado.', target=collaborator, request=request)
    messages.success(request, 'Colaborador eliminado correctamente.')
    return redirect('iam:dashboard')


# ─────────────────────────────────────────────
# CERTIFICATES
# ─────────────────────────────────────────────

@login_required(login_url='iam:login')
@onboarding_required
@require_admin
def issue_certificate_view(request, pk):
    collaborator = get_object_or_404(Collaborator, pk=pk)

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
            _log(request.user, 'CERTIFICATE_ISSUED', f'Certificado emitido para {collaborator.username}.', target=collaborator, request=request)
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
    user = request.user
    collaborator = get_object_or_404(Collaborator, pk=pk)

    if user.access_level == 4 and collaborator.pk != user.pk:
        messages.error(request, 'Solo puedes validar tu propio certificado.')
        return redirect('iam:detail', pk=user.pk)

    if not user.can_view(collaborator):
        messages.error(request, 'No tienes permisos para validar este certificado.')
        return redirect('iam:dashboard')

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

    if request.user.access_level != 1:
        messages.error(request, 'No tienes permisos para revocar certificados.')
        return redirect('iam:dashboard')

    collaborator = get_object_or_404(Collaborator, pk=pk)
    certificate = get_object_or_404(UserCertificate, collaborator=collaborator)
    certificate.is_revoked = True
    certificate.revoked_at = timezone.now()
    certificate.revoked_by = request.user
    certificate.save()
    _log(request.user, 'CERTIFICATE_REVOKED', certificate.fingerprint, target=collaborator, request=request)
    messages.success(request, 'Certificado revocado correctamente.')
    return redirect('iam:detail', pk=collaborator.pk)


# ─────────────────────────────────────────────
# AUDIT LOG
# ─────────────────────────────────────────────

@login_required(login_url='iam:login')
@onboarding_required
def audit_log_view(request):
    user = request.user
    if user.access_level > 2:
        messages.error(request, 'No tienes permisos para acceder a la auditoría.')
        return redirect('iam:dashboard')

    if user.access_level == 1:
        logs = AuditLog.objects.all()
    else:
        logs = (
            AuditLog.objects.filter(actor__area=user.area) |
            AuditLog.objects.filter(target__area=user.area)
        )
    logs = logs.select_related('actor', 'target')[:200]
    return render(request, 'iam/audit_log.html', {'logs': logs})


# ─────────────────────────────────────────────
# SECURITY QUESTION & PASSWORD RECOVERY
# ─────────────────────────────────────────────

@login_required(login_url='iam:login')
def security_question_setup_view(request):
    user = request.user
    form = SecurityQuestionSetupForm(request.POST or None)
    if request.method == 'POST' and form.is_valid():
        user.security_question = form.cleaned_data['security_question']
        user.set_security_answer(form.cleaned_data['security_answer'])
        user.save(update_fields=['security_question', 'security_answer_hash'])
        _log(user, 'Configuración pregunta de seguridad', 'El usuario configuró su pregunta de seguridad.', target=user, request=request)
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
