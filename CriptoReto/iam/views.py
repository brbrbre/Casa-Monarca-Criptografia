import secrets
from functools import wraps

from django.contrib import messages
from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.db.models import Q
from django.http import HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone

from .decorators import require_access_level, require_admin, require_post
from .forms import (
    CollaboratorForm, CollaboratorSearchForm, LoginForm, OnboardingForm,
    PasswordChangeAuthForm, SecurityQuestionSetupForm, PasswordRecoveryRequestForm,
    SecurityAnswerForm, PasswordRecoveryResetForm,
)
from .models import Area, AuditLog, CertificateAuditLog, Collaborator, LoginAttempt, UserCertificate
from .certificates import (
    issue_encrypted_certificate,
    validate_encrypted_certificate,
    issue_coordinator_key_cert,
    validate_coordinator_cert_and_key,
    get_coordinator_key_bytes,
    issue_cert_and_key,
    validate_cert_and_key,
    extract_cert_serial_number,
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

def _needs_cert_relogin(user, request):
    """
    A level-1 or level-2 user who downloaded both credential files must re-login
    with cert+key.  Detected by: certificate_delivered_at is set but the current
    session was NOT authenticated with a cert (cert_validated=False).
    """
    return (
        user.access_level <= 2
        and user.onboarding_approved
        and user.certificate_delivered_at
        and not request.session.get('cert_validated', False)
    )


# Keep old name as alias so any external references don't break immediately.
_coordinator_needs_relogin = _needs_cert_relogin


def _is_onboarding_user(user, request=None):
    """Return True when the user must be kept behind the onboarding gate."""
    if not hasattr(user, 'onboarding_status'):
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
    # Approved but level-1/2 user hasn't downloaded both credential files yet
    if user.onboarding_approved and not user.certificate_delivered_at:
        return True
    # Level-1/2 user downloaded files but hasn't re-logged in with cert+key
    if request and _needs_cert_relogin(user, request):
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

    # Fully onboarded and authenticated with cert → go to dashboard
    if user.onboarding_approved and user.certificate_delivered_at and not _needs_cert_relogin(user, request):
        return redirect('iam:dashboard')

    # True for both admin (1) and coordinator (2): they both need cert+key files
    is_coordinator = (user.access_level <= 2)

    # ── State: re-login needed (downloaded credentials but not yet cert-authenticated) ──
    if is_coordinator and _needs_cert_relogin(user, request):
        return render(request, 'iam/onboarding.html', {
            'onboarding_state': 'relogin_needed',
            'is_coordinator': is_coordinator,
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
    if user.access_level > 2:
        messages.error(request, 'Este archivo solo está disponible para usuarios con firma digital (nivel 1 o 2).')
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

    # Filters
    from .models import Area as AreaModel
    area_id = request.GET.get('area', '').strip()
    nivel = request.GET.get('nivel', '').strip()
    if area_id:
        collaborators = collaborators.filter(area_id=area_id)
    if nivel:
        collaborators = collaborators.filter(access_level=nivel)

    return render(request, 'iam/pending_onboardings.html', {
        'collaborators': collaborators,
        'areas': AreaModel.objects.order_by('name'),
        'access_level_choices': Collaborator.ACCESS_LEVEL_CHOICES,
        'filters': {'area': area_id, 'nivel': nivel},
    })


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
        # ── BLOCK 1: collaborator must have completed onboarding first (before crypto) ──
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

        # ── BLOCK 2: approving a level-1 account requires the approver to have a cert session ──
        if collaborator.access_level == 1 and not request.session.get('cert_validated'):
            messages.error(
                request,
                'Para aprobar una cuenta de Administrador debes haber iniciado sesión con tu certificado digital (.cert y .key).',
            )
            return redirect('iam:approve_onboarding', pk=pk)

        # ── BLOCK 3: validate approver password ──
        if not user.check_password(request.POST.get('password', '')):
            messages.error(request, 'Contraseña incorrecta. No se pudo firmar la aprobación.')
            return redirect('iam:approve_onboarding', pk=pk)

        # ── BLOCK 4: validate approver cert + key ──
        cert_file = request.FILES.get('cert_file')
        key_file = request.FILES.get('key_file')
        if not cert_file or not key_file:
            messages.error(request, 'Debes proporcionar tu certificado (.cert) y tu llave privada (.key) para firmar la aprobación.')
            return redirect('iam:approve_onboarding', pk=pk)
        try:
            cert_bytes = cert_file.read()
            key_bytes = key_file.read()
        except Exception:
            cert_bytes, key_bytes = b'', b''
        if not validate_cert_and_key(user, cert_bytes, key_bytes):
            messages.error(request, 'El certificado o la llave privada del aprobador son inválidos.')
            return redirect('iam:approve_onboarding', pk=pk)

        # ── Approval ──
        collaborator.onboarding_status = Collaborator.ONBOARDING_STATUS_APPROVED
        collaborator.onboarding_approved_at = timezone.now()
        collaborator.onboarding_approved_by = user
        collaborator.save(update_fields=['onboarding_status', 'onboarding_approved_at', 'onboarding_approved_by'])

        if collaborator.access_level <= 2:
            try:
                issue_cert_and_key(collaborator, issued_by=user)
                msg = 'Onboarding aprobado. El usuario recibirá el aviso para descargar sus archivos .cert y .key.'
            except PermissionError:
                msg = 'Onboarding aprobado (los archivos de firma ya habían sido emitidos).'
        else:
            collaborator.certificate_delivered_at = timezone.now()
            collaborator.save(update_fields=['certificate_delivered_at'])
            msg = 'Onboarding aprobado. El usuario ya puede acceder al sistema.'

        approver_fingerprint = getattr(getattr(user, 'certificate', None), 'fingerprint', 'unknown')
        AuditLog.objects.create(
            actor=user,
            target=collaborator,
            action='ONBOARDING_APPROVED_SIGNED',
            details=f'Aprobador fingerprint: {approver_fingerprint}',
        )
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
    if collaborator.onboarding_status in (
        Collaborator.ONBOARDING_STATUS_APPROVED,
        Collaborator.ONBOARDING_STATUS_REJECTED,
    ):
        return []
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

            # ── Level 1/2 still in onboarding (pending / submitted / approved but no cert) ──
            # Skip the cert+key check and redirect to the onboarding hub.
            if user.access_level <= 2:
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

            # Level 3/4: no cert files needed; just check basic onboarding state
            if user.access_level > 2:
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

            # ── Level 1 and 2: require both .cert and .key (RSA + X.509, fully-onboarded sessions only) ──
            if user.access_level <= 2:
                cert_file = form.cleaned_data.get('certificate')
                key_file = form.cleaned_data.get('key_file')
                if not cert_file or not key_file:
                    LoginAttempt.objects.create(username=username, ip_address=ip_address, successful=False)
                    messages.error(
                        request,
                        'Los administradores y coordinadores deben proporcionar el certificado digital (.cert) y la llave privada (.key).',
                    )
                    return render(request, 'iam/login.html', {'form': form, 'blocked': blocked, 'credentials_ready': credentials_ready})
                try:
                    cert_bytes = cert_file.read()
                    key_bytes = key_file.read()
                except Exception:
                    cert_bytes, key_bytes = b'', b''
                if not validate_cert_and_key(user, cert_bytes, key_bytes):
                    LoginAttempt.objects.create(username=username, ip_address=ip_address, successful=False)
                    messages.error(request, 'El certificado digital o la llave privada son inválidos.')
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
        temp_pw = secrets.token_urlsafe(12)
        collaborator.set_password(temp_pw)
        if user.access_level == 2:
            if collaborator.access_level < 3:
                collaborator.access_level = 3
            collaborator.area = user.area
        collaborator.save()
        _log(user, 'Creación de colaborador', f'Nuevo colaborador {collaborator.username} creado.', target=collaborator, request=request)
        # Store the temp password in session for one-time display only.
        request.session[f'just_created_{collaborator.pk}'] = temp_pw
        return redirect('iam:collaborator_created', pk=collaborator.pk)

    return render(request, 'iam/collaborator_form.html', {'form': form, 'title': 'Alta de colaborador'})


@login_required(login_url='iam:login')
@onboarding_required
@require_admin
def collaborator_created_view(request, pk):
    """One-time view showing the generated temp password for a newly created collaborator."""
    collaborator = get_object_or_404(Collaborator, pk=pk)
    session_key = f'just_created_{pk}'
    temp_pw = request.session.pop(session_key, None)
    if temp_pw is None:
        return redirect('iam:detail', pk=pk)
    return render(request, 'iam/collaborator_created.html', {
        'collaborator': collaborator,
        'temp_pw': temp_pw,
    })


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
    is_coordinator = collaborator.access_level <= 2
    if request.method == 'POST':
        try:
            if not is_coordinator:
                raise PermissionError(
                    f'El colaborador "{collaborator.username}" tiene nivel de acceso '
                    f'{collaborator.access_level}. Solo los niveles 1 (admin) y '
                    '2 (coordinador) reciben certificados digitales.'
                )
            certificate = issue_cert_and_key(collaborator, issued_by=request.user)
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

    if request.method == 'POST':
        cert_file = request.FILES.get('cert_file')
        key_file = request.FILES.get('key_file')
        
        if not cert_file or not key_file:
            messages.error(request, 'Debes proporcionar tanto el certificado (.cert) como la clave privada (.key).')
        else:
            try:
                cert_bytes = cert_file.read()
                key_bytes = key_file.read()
            except Exception as e:
                messages.error(request, f'Error al leer los archivos: {str(e)}')
                return render(request, 'iam/certificate_validate.html', {'collaborator': collaborator})
            
            if validate_cert_and_key(collaborator, cert_bytes, key_bytes):
                messages.success(request, 'Certificado validado correctamente. ✓')
            else:
                messages.error(request, 'La validación del certificado falló. Revisa los archivos.')

    return render(request, 'iam/certificate_validate.html', {'collaborator': collaborator})


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

    # Filters
    date_from = request.GET.get('date_from', '').strip()
    date_to = request.GET.get('date_to', '').strip()
    action = request.GET.get('action', '').strip()
    target_q = request.GET.get('target', '').strip()
    actor_q = request.GET.get('actor', '').strip()

    if date_from:
        logs = logs.filter(created_at__date__gte=date_from)
    if date_to:
        logs = logs.filter(created_at__date__lte=date_to)
    if action:
        logs = logs.filter(action__icontains=action)
    if target_q:
        logs = logs.filter(
            Q(target__first_name__icontains=target_q) |
            Q(target__last_name__icontains=target_q) |
            Q(target__username__icontains=target_q) |
            Q(target__email__icontains=target_q)
        )
    if actor_q:
        logs = logs.filter(
            Q(actor__first_name__icontains=actor_q) |
            Q(actor__last_name__icontains=actor_q) |
            Q(actor__username__icontains=actor_q) |
            Q(actor__email__icontains=actor_q)
        )

    logs = logs.select_related('actor', 'target').order_by('-created_at')[:500]
    return render(request, 'iam/audit_log.html', {
        'logs': logs,
        'filters': {
            'date_from': date_from,
            'date_to': date_to,
            'action': action,
            'target': target_q,
            'actor': actor_q,
        },
    })


# ─────────────────────────────────────────────
# SECURITY QUESTION & PASSWORD RECOVERY
# ─────────────────────────────────────────────

@login_required(login_url='iam:login')
@onboarding_required
def password_change_view(request):
    user = request.user
    form = PasswordChangeAuthForm(user, request.POST or None)
    if request.method == 'POST' and form.is_valid():
        user.set_password(form.cleaned_data['new_password1'])
        user.save(update_fields=['password'])
        update_session_auth_hash(request, user)
        _log(user, 'Cambio de contraseña', 'El usuario cambió su contraseña.', target=user, request=request)
        messages.success(request, 'Contraseña actualizada correctamente.')
        return redirect('iam:dashboard')
    return render(request, 'iam/password_change.html', {'form': form, 'title': 'Cambiar contraseña'})


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


# ─────────────────────────────────────────────
# CERTIFICATE MANAGEMENT (Admin-only, Level 1)
# ─────────────────────────────────────────────

def _flush_user_sessions(user_pk: int) -> None:
    """Delete all active sessions for the given user (called on certificate revocation)."""
    try:
        from django.contrib.sessions.models import Session
        now = timezone.now()
        to_delete = []
        for session in Session.objects.filter(expire_date__gte=now):
            try:
                if str(session.get_decoded().get('_auth_user_id', '')) == str(user_pk):
                    to_delete.append(session.pk)
            except Exception:
                pass
        if to_delete:
            Session.objects.filter(pk__in=to_delete).delete()
    except Exception:
        pass


def _cert_audit(certificate, action, performed_by, prev_status, new_status, metadata=None):
    CertificateAuditLog.objects.create(
        certificate=certificate,
        action=action,
        performed_by=performed_by,
        previous_status=prev_status,
        new_status=new_status,
        metadata=metadata or {},
    )


@login_required(login_url='iam:login')
@onboarding_required
@require_admin
def certificate_mgmt_list_view(request):
    now = timezone.now()
    qs = UserCertificate.objects.select_related(
        'collaborator', 'collaborator__area', 'issued_by',
    ).order_by('-issued_at')

    # Filters
    status_filter = request.GET.get('status', '')
    area_filter = request.GET.get('area', '')
    date_from = request.GET.get('date_from', '')
    date_to = request.GET.get('date_to', '')
    search = request.GET.get('search', '').strip()

    if status_filter == 'EXPIRED':
        qs = qs.filter(
            Q(status='EXPIRED') | Q(status='ACTIVE', expires_at__lte=now)
        )
    elif status_filter:
        qs = qs.filter(status=status_filter).exclude(
            status='ACTIVE', expires_at__lte=now
        )
    if area_filter:
        qs = qs.filter(collaborator__area__slug=area_filter)
    if date_from:
        qs = qs.filter(issued_at__date__gte=date_from)
    if date_to:
        qs = qs.filter(issued_at__date__lte=date_to)
    if search:
        qs = qs.filter(
            Q(collaborator__first_name__icontains=search)
            | Q(collaborator__last_name__icontains=search)
            | Q(collaborator__username__icontains=search)
            | Q(serial_number__icontains=search)
        )

    # Stats
    all_certs = UserCertificate.objects.all()
    stats = {
        'active': all_certs.filter(status='ACTIVE', expires_at__gt=now).count(),
        'suspended': all_certs.filter(status='SUSPENDED').count(),
        'revoked': all_certs.filter(status='REVOKED').count(),
        'expired': all_certs.filter(
            Q(status='EXPIRED') | Q(status='ACTIVE', expires_at__lte=now)
        ).count(),
        'inactive': all_certs.filter(status='INACTIVE').count(),
    }

    paginator = Paginator(qs, 20)
    page = request.GET.get('page', 1)
    certs_page = paginator.get_page(page)

    areas = Area.objects.all()
    filters = {
        'status': status_filter,
        'area': area_filter,
        'date_from': date_from,
        'date_to': date_to,
        'search': search,
    }
    return render(request, 'iam/certificate_mgmt_list.html', {
        'title': 'Gestión de certificados',
        'certs': certs_page,
        'stats': stats,
        'areas': areas,
        'filters': filters,
        'now': now,
    })


@login_required(login_url='iam:login')
@onboarding_required
@require_admin
def certificate_mgmt_detail_view(request, cert_id):
    cert = get_object_or_404(
        UserCertificate.objects.select_related(
            'collaborator', 'collaborator__area',
            'issued_by', 'revoked_by', 'suspended_by', 'deactivated_by',
        ),
        pk=cert_id,
    )
    audit_logs = CertificateAuditLog.objects.filter(
        certificate=cert,
    ).select_related('performed_by').order_by('-timestamp')
    return render(request, 'iam/certificate_mgmt_detail.html', {
        'title': 'Detalle de certificado',
        'cert': cert,
        'audit_logs': audit_logs,
        'now': timezone.now(),
    })


@login_required(login_url='iam:login')
@onboarding_required
@require_admin
def certificate_mgmt_audit_view(request, cert_id):
    cert = get_object_or_404(UserCertificate, pk=cert_id)
    audit_logs = CertificateAuditLog.objects.filter(
        certificate=cert,
    ).select_related('performed_by').order_by('-timestamp')
    return render(request, 'iam/certificate_mgmt_detail.html', {
        'title': 'Auditoría del certificado',
        'cert': cert,
        'audit_logs': audit_logs,
        'now': timezone.now(),
        'audit_only': True,
    })


@login_required(login_url='iam:login')
@onboarding_required
@require_admin
def certificate_mgmt_issue_view(request, user_id):
    """Link the existing onboarding-generated cert to the Certificate Management module."""
    if request.method != 'POST':
        return redirect('iam:certificate_mgmt_list')

    collaborator = get_object_or_404(Collaborator, pk=user_id)
    cert = getattr(collaborator, 'certificate', None)
    if not cert:
        messages.error(request, f'El colaborador {collaborator} no tiene ningún certificado emitido todavía.')
        return redirect('iam:detail', pk=user_id)

    if cert.status == UserCertificate.STATUS_REVOKED:
        messages.error(request, 'El certificado está revocado y no puede activarse.')
        return redirect('iam:certificate_mgmt_detail', cert_id=cert.pk)

    prev_status = cert.status
    serial = extract_cert_serial_number(cert.certificate_data)
    cert.serial_number = serial or cert.serial_number
    if cert.status not in (UserCertificate.STATUS_REVOKED, UserCertificate.STATUS_INACTIVE):
        now = timezone.now()
        if cert.expires_at <= now:
            cert.status = UserCertificate.STATUS_EXPIRED
        else:
            cert.status = UserCertificate.STATUS_ACTIVE
    cert.save(update_fields=['status', 'serial_number'])

    _cert_audit(cert, CertificateAuditLog.ACTION_ISSUED, request.user, prev_status, cert.status, {
        'serial_number': cert.serial_number,
        'fingerprint': cert.fingerprint,
        'expires_at': cert.expires_at.isoformat(),
    })
    _log(request.user, 'CERT_MGMT_ISSUED',
         f'Certificado vinculado al módulo de gestión. Serie: {cert.serial_number or cert.fingerprint[:12]}.',
         target=collaborator, request=request)
    messages.success(request, 'Certificado vinculado al sistema de gestión correctamente.')
    return redirect('iam:certificate_mgmt_detail', cert_id=cert.pk)


@login_required(login_url='iam:login')
@onboarding_required
@require_admin
def certificate_mgmt_revoke_view(request, cert_id):
    if request.method != 'POST':
        return redirect('iam:certificate_mgmt_list')

    cert = get_object_or_404(UserCertificate.objects.select_related('collaborator'), pk=cert_id)

    if cert.status == UserCertificate.STATUS_REVOKED:
        messages.error(request, 'El certificado ya está revocado.')
        return redirect('iam:certificate_mgmt_detail', cert_id=cert_id)

    if cert.status in (UserCertificate.STATUS_INACTIVE,):
        messages.error(request, 'Un certificado dado de baja no puede ser revocado.')
        return redirect('iam:certificate_mgmt_detail', cert_id=cert_id)

    reason = request.POST.get('reason', '').strip()
    if not reason:
        messages.error(request, 'Debes proporcionar un motivo de revocación.')
        return redirect('iam:certificate_mgmt_detail', cert_id=cert_id)

    prev_status = cert.status
    now = timezone.now()
    cert.status = UserCertificate.STATUS_REVOKED
    cert.is_revoked = True  # backward compat
    cert.revoked_at = now
    cert.revoked_by = request.user
    cert.revocation_reason = reason
    cert.save(update_fields=['status', 'is_revoked', 'revoked_at', 'revoked_by', 'revocation_reason'])

    _cert_audit(cert, CertificateAuditLog.ACTION_REVOKED, request.user, prev_status,
                UserCertificate.STATUS_REVOKED, {'reason': reason})
    _log(request.user, 'CERT_MGMT_REVOKED',
         f'Certificado {cert.fingerprint[:12]} revocado. Motivo: {reason}',
         target=cert.collaborator, request=request)
    _flush_user_sessions(cert.collaborator_id)
    messages.success(request, 'Certificado revocado correctamente. Las sesiones activas del usuario han sido cerradas.')
    return redirect('iam:certificate_mgmt_list')


@login_required(login_url='iam:login')
@onboarding_required
@require_admin
def certificate_mgmt_suspend_view(request, cert_id):
    if request.method != 'POST':
        return redirect('iam:certificate_mgmt_list')

    cert = get_object_or_404(UserCertificate.objects.select_related('collaborator'), pk=cert_id)

    if cert.status != UserCertificate.STATUS_ACTIVE:
        messages.error(request, 'Solo se puede suspender un certificado activo.')
        return redirect('iam:certificate_mgmt_detail', cert_id=cert_id)

    if cert.expires_at <= timezone.now():
        messages.error(request, 'El certificado ya está expirado.')
        return redirect('iam:certificate_mgmt_detail', cert_id=cert_id)

    reason = request.POST.get('reason', '').strip()
    if not reason:
        messages.error(request, 'Debes proporcionar un motivo de suspensión.')
        return redirect('iam:certificate_mgmt_detail', cert_id=cert_id)

    prev_status = cert.status
    cert.status = UserCertificate.STATUS_SUSPENDED
    cert.suspended_at = timezone.now()
    cert.suspended_by = request.user
    cert.suspension_reason = reason
    cert.save(update_fields=['status', 'suspended_at', 'suspended_by', 'suspension_reason'])

    _cert_audit(cert, CertificateAuditLog.ACTION_SUSPENDED, request.user, prev_status,
                UserCertificate.STATUS_SUSPENDED, {'reason': reason})
    _log(request.user, 'CERT_MGMT_SUSPENDED',
         f'Certificado {cert.fingerprint[:12]} suspendido. Motivo: {reason}',
         target=cert.collaborator, request=request)
    messages.success(request, 'Certificado suspendido correctamente.')
    return redirect('iam:certificate_mgmt_list')


@login_required(login_url='iam:login')
@onboarding_required
@require_admin
def certificate_mgmt_reactivate_view(request, cert_id):
    if request.method != 'POST':
        return redirect('iam:certificate_mgmt_list')

    cert = get_object_or_404(UserCertificate.objects.select_related('collaborator'), pk=cert_id)

    if cert.status != UserCertificate.STATUS_SUSPENDED:
        messages.error(request, 'Solo se puede reactivar un certificado suspendido.')
        return redirect('iam:certificate_mgmt_detail', cert_id=cert_id)

    if cert.expires_at <= timezone.now():
        messages.error(request, 'El certificado está expirado y no puede reactivarse. Emite uno nuevo.')
        return redirect('iam:certificate_mgmt_detail', cert_id=cert_id)

    prev_status = cert.status
    cert.status = UserCertificate.STATUS_ACTIVE
    cert.save(update_fields=['status'])

    _cert_audit(cert, CertificateAuditLog.ACTION_REACTIVATED, request.user, prev_status,
                UserCertificate.STATUS_ACTIVE, {})
    _log(request.user, 'CERT_MGMT_REACTIVATED',
         f'Certificado {cert.fingerprint[:12]} reactivado.',
         target=cert.collaborator, request=request)
    messages.success(request, 'Certificado reactivado correctamente.')
    return redirect('iam:certificate_mgmt_list')


@login_required(login_url='iam:login')
@onboarding_required
@require_admin
def certificate_mgmt_deactivate_view(request, cert_id):
    if request.method != 'POST':
        return redirect('iam:certificate_mgmt_list')

    cert = get_object_or_404(UserCertificate.objects.select_related('collaborator'), pk=cert_id)

    if cert.status in (UserCertificate.STATUS_REVOKED, UserCertificate.STATUS_INACTIVE):
        messages.error(request, 'El certificado ya está dado de baja o revocado.')
        return redirect('iam:certificate_mgmt_detail', cert_id=cert_id)

    reason = request.POST.get('reason', '').strip()
    if not reason:
        messages.error(request, 'Debes proporcionar un motivo de baja.')
        return redirect('iam:certificate_mgmt_detail', cert_id=cert_id)

    prev_status = cert.status
    cert.status = UserCertificate.STATUS_INACTIVE
    cert.deactivated_at = timezone.now()
    cert.deactivated_by = request.user
    cert.deactivation_reason = reason
    cert.save(update_fields=['status', 'deactivated_at', 'deactivated_by', 'deactivation_reason'])

    _cert_audit(cert, CertificateAuditLog.ACTION_DEACTIVATED, request.user, prev_status,
                UserCertificate.STATUS_INACTIVE, {'reason': reason})
    _log(request.user, 'CERT_MGMT_DEACTIVATED',
         f'Certificado {cert.fingerprint[:12]} dado de baja. Motivo: {reason}',
         target=cert.collaborator, request=request)
    messages.success(request, 'Certificado dado de baja correctamente.')
    return redirect('iam:certificate_mgmt_list')
