import io
import json
from functools import wraps

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.messages import get_messages
from django.http import FileResponse, Http404, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views.decorators.http import require_POST

from iam.models import AuditLog
from iam.views import onboarding_required
from iam.certificates import validate_coordinator_cert_and_key, validate_encrypted_certificate
from .forms import ArcoRequestForm, MigrantRegistrationForm, WorkflowApprovalForm, WorkflowUpdateRequestForm
from .models import (
    ArcoRequest, MigrantRegistration, MigrantRegistrationSignature,
    Notification, Ticket, WorkflowRequest, PRIVACY_NOTICE_VERSION,
)
from .services import (
    batch_sign_actions, get_public_key_pem,
    sign_registration, verify_registration, verify_action_chain,
)
from .workflow import (
    approve_request, can_act_directly, create_workflow_request,
    execute_request, pending_requests_for, reject_request,
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _get_ip(request):
    forwarded = request.META.get('HTTP_X_FORWARDED_FOR')
    return forwarded.split(',')[0].strip() if forwarded else request.META.get('REMOTE_ADDR')


def _log(actor, action, details='', request=None):
    ip = _get_ip(request) if request else None
    level = getattr(actor, 'access_level', '')
    full = f'[Nivel {level}] {details}'
    if ip:
        full = f'{full} | IP: {ip}'
    AuditLog.objects.create(actor=actor, action=action, details=full.strip())


def _remove_permission_messages(request):
    storage = get_messages(request)
    kept = []
    for message in storage:
        if 'permiso' in message.message.lower():
            continue
        kept.append(message)
    for message in kept:
        messages.add_message(request, message.level, message.message, extra_tags=message.tags)


def require_level(max_level, redirect_to='registros:registro_new'):
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped(request, *args, **kwargs):
            if request.user.access_level > max_level:
                messages.error(request, 'No tienes permisos para acceder a esta sección.')
                return redirect(redirect_to)
            return view_func(request, *args, **kwargs)
        return _wrapped
    return decorator


def _build_review_sections(form):
    sections = [
        ('Datos personales', [
            'full_name', 'birth_date', 'gender', 'nationality',
            'country_of_origin', 'document_type', 'document_number',
        ]),
        ('Contacto', ['phone', 'email']),
        ('Información de ingreso', [
            'entry_date', 'entry_point', 'transit_countries', 'intended_destination',
        ]),
        ('Grupo familiar', [
            'marital_status', 'travels_alone', 'group_size', 'minors_in_group',
        ]),
        ('Necesidades y situación', [
            'assistance_requested', 'migration_reason',
            'current_legal_status', 'shelter_name',
        ]),
        ('Contacto de emergencia', [
            'emergency_contact_name', 'emergency_contact_phone',
            'emergency_contact_relationship',
        ]),
        ('Observaciones', ['observations']),
    ]
    result = []
    for title, field_names in sections:
        rows = []
        for name in field_names:
            if name not in form.fields:
                continue
            field = form.fields[name]
            value = form.cleaned_data.get(name)
            label = field.label or name
            choice_map = dict(getattr(field, 'choices', []))
            if value in choice_map:
                value = choice_map[value]
            if isinstance(value, bool):
                value = 'Sí' if value else 'No'
            if value is None or value == '':
                value = '—'
            rows.append((label, value))
        if rows:
            result.append((title, rows))
    return result


# ══════════════════════════════════════════════════════════════════════════════
# REGISTRATION CREATION WORKFLOW  (3 steps)
# ══════════════════════════════════════════════════════════════════════════════

@login_required(login_url='iam:login')
@onboarding_required
def registro_new(request):
    """Step 1 — Fill the registration form.  All authenticated roles may create."""
    if request.method == 'POST':
        request.session['registro_draft'] = {k: v for k, v in request.POST.lists()}
        form = MigrantRegistrationForm(request.POST)
        if form.is_valid():
            if request.user.access_level > 2:
                payload = {}
                for field, value in form.cleaned_data.items():
                    payload[field] = value.isoformat() if hasattr(value, 'isoformat') else value
                payload['privacy_accepted_at'] = timezone.now().isoformat()
                payload['privacy_accepted_ip'] = _get_ip(request)
                payload['privacy_notice_version'] = PRIVACY_NOTICE_VERSION
                try:
                    wf = create_workflow_request(
                        action_type='create_registration',
                        requester=request.user,
                        payload=payload,
                        notes='Solicitud de nuevo registro migrante',
                    )
                    Ticket.create_for_workflow_request(wf, request.user)
                    request.session.pop('registro_draft', None)
                    _remove_permission_messages(request)
                    messages.success(
                        request,
                        'Tu solicitud fue enviada al Coordinador. Puedes seguir su estado en Tickets.',
                    )
                    return redirect('registros:ticket_list')
                except ValueError as exc:
                    messages.error(request, str(exc))
            else:
                return redirect('registros:registro_review')
    else:
        draft = request.session.get('registro_draft')
        from django.http import QueryDict
        qd = QueryDict(mutable=True)
        if draft:
            for k, vals in draft.items():
                for v in vals:
                    qd.appendlist(k, v)
            form = MigrantRegistrationForm(qd)
        else:
            form = MigrantRegistrationForm()

    return render(request, 'registros/form.html', {
        'form': form,
        'title': 'Nuevo Registro Migrante',
    })


@login_required(login_url='iam:login')
@onboarding_required
def registro_review(request):
    """Step 2 — Review + password confirmation → create + sign."""
    draft = request.session.get('registro_draft')
    if not draft:
        messages.error(request, 'No hay datos pendientes. Por favor llena el formulario.')
        return redirect('registros:registro_new')

    from django.http import QueryDict
    qd = QueryDict(mutable=True)
    for k, vals in draft.items():
        for v in vals:
            qd.appendlist(k, v)

    form = MigrantRegistrationForm(qd)
    if not form.is_valid():
        messages.error(request, 'Los datos contienen errores. Por favor regresa y corrígelos.')
        return redirect('registros:registro_new')

    if request.user.access_level > 2:
        return redirect('registros:registro_new')

    if request.method == 'POST':
        password = request.POST.get('password', '')
        if not request.user.check_password(password):
            messages.error(request, 'Contraseña incorrecta. Intenta de nuevo.')
            return render(request, 'registros/review.html', {
                'form': form,
                'review_sections': _build_review_sections(form),
                'title': 'Revisar Registro',
            })

        # ── Create record ──────────────────────────────────────────────────
        registration = form.save(commit=False)
        registration.created_by = request.user
        registration.created_by_role = request.user.access_level
        # Privacy consent audit trail
        registration.privacy_accepted_at = timezone.now()
        registration.privacy_accepted_ip = _get_ip(request)
        registration.privacy_notice_version = PRIVACY_NOTICE_VERSION
        registration.save()

        # ── Ticket ──────────────────────────────────────────────────────────
        Ticket.create_for_registration(registration, request.user)

        # ── Sign ────────────────────────────────────────────────────────────
        sig_data = sign_registration(registration)
        MigrantRegistrationSignature.objects.create(
            registration=registration,
            signed_by=request.user,
            signed_by_role=request.user.access_level,
            **sig_data,
        )

        _log(request.user, 'registro_migrante_creado_y_firmado',
             f'Registro #{registration.pk} ({registration.full_name}) | '
             f'hash: {sig_data["message_hash"][:16]}… | '
             f'Consentimiento v{PRIVACY_NOTICE_VERSION} aceptado',
             request=request)

        request.session.pop('registro_draft', None)
        return redirect('registros:registro_exito', pk=registration.pk)

    return render(request, 'registros/review.html', {
        'form': form,
        'review_sections': _build_review_sections(form),
        'title': 'Revisar Registro',
    })


@login_required(login_url='iam:login')
@onboarding_required
def registro_exito(request, pk):
    registration = get_object_or_404(MigrantRegistration, pk=pk, is_deleted=False)
    if registration.created_by != request.user and request.user.access_level > 2:
        messages.error(request, 'No tienes acceso a este registro.')
        return redirect('registros:registro_new')

    try:
        sig = registration.signature
        verify_result = verify_registration(registration, sig)
    except MigrantRegistrationSignature.DoesNotExist:
        sig = None
        verify_result = None

    return render(request, 'registros/exito.html', {
        'registration': registration,
        'sig': sig,
        'verify_result': verify_result,
        'title': f'Registro #{registration.pk} creado',
    })


# ══════════════════════════════════════════════════════════════════════════════
# LIST / DETAIL / EDIT / DELETE
# ══════════════════════════════════════════════════════════════════════════════

@login_required(login_url='iam:login')
@onboarding_required
@require_level(3)
def registro_list(request):
    qs = MigrantRegistration.objects.filter(is_deleted=False)
    q = request.GET.get('q', '').strip()
    if q:
        from django.db.models import Q
        qs = qs.filter(
            Q(full_name__icontains=q) |
            Q(nationality__icontains=q) |
            Q(document_number__icontains=q)
        )
    return render(request, 'registros/list.html', {
        'registrations': qs, 'q': q, 'title': 'Registros Migrantes',
    })


@login_required(login_url='iam:login')
@onboarding_required
@require_level(3)
def registro_detail(request, pk):
    registration = get_object_or_404(MigrantRegistration, pk=pk, is_deleted=False)
    try:
        sig = registration.signature
        verify_result = verify_registration(registration, sig)
    except MigrantRegistrationSignature.DoesNotExist:
        sig = None
        verify_result = None

    return render(request, 'registros/detail.html', {
        'registration': registration,
        'sig': sig,
        'verify_result': verify_result,
        'title': f'Registro #{registration.pk}',
    })


@login_required(login_url='iam:login')
@onboarding_required
def registro_edit(request, pk):
    """
    Direct edit (Level 1–2).
    Level 3–4 are redirected to create a WorkflowRequest instead.
    """
    registration = get_object_or_404(MigrantRegistration, pk=pk, is_deleted=False)

    # Level 3–4: must use the workflow
    if not can_act_directly('update_registration', request.user.access_level):
        messages.info(request,
                      'Tu nivel de acceso requiere aprobación para modificar registros. '
                      'Se ha iniciado una solicitud de actualización.')
        return redirect('registros:workflow_request_create',
                        pk=pk, action='update_registration')

    form = MigrantRegistrationForm(request.POST or None, instance=registration)
    if request.method == 'POST' and form.is_valid():
        form.save()
        _log(request.user, 'registro_migrante_editado',
             f'Registro #{registration.pk} editado directamente.', request=request)
        messages.success(request, f'Registro #{registration.pk} actualizado.')
        return redirect('registros:registro_detail', pk=registration.pk)

    return render(request, 'registros/form.html', {
        'form': form, 'registration': registration,
        'editing': True, 'title': f'Editar Registro #{registration.pk}',
    })


@login_required(login_url='iam:login')
@onboarding_required
@require_POST
def registro_delete(request, pk):
    """
    Direct soft-delete (Level 1 only).
    Level 2–4 are redirected to create a WorkflowRequest.
    """
    registration = get_object_or_404(MigrantRegistration, pk=pk, is_deleted=False)

    if not can_act_directly('delete_registration', request.user.access_level):
        messages.info(request,
                      'Tu nivel de acceso requiere aprobación para eliminar registros. '
                      'Se ha creado una solicitud.')
        return redirect('registros:workflow_request_create',
                        pk=pk, action='delete_registration')

    registration.soft_delete(request.user)
    _log(request.user, 'registro_migrante_eliminado',
         f'Registro #{registration.pk} eliminado por Nivel 1.', request=request)
    messages.success(request, f'Registro #{registration.pk} eliminado.')
    return redirect('registros:registro_list')


# ══════════════════════════════════════════════════════════════════════════════
# SIGNATURE VERIFICATION
# ══════════════════════════════════════════════════════════════════════════════

@login_required(login_url='iam:login')
@onboarding_required
def registro_verify(request, pk):
    registration = get_object_or_404(MigrantRegistration, pk=pk)
    try:
        sig = registration.signature
        result = verify_registration(registration, sig)
    except MigrantRegistrationSignature.DoesNotExist:
        result = {'is_valid': False, 'error': 'no_signature'}
    return JsonResponse(result, json_dumps_params={'default': str})


@login_required(login_url='iam:login')
@onboarding_required
def export_public_key(request):
    from django.http import HttpResponse
    pem = get_public_key_pem()
    response = HttpResponse(pem, content_type='application/x-pem-file')
    response['Content-Disposition'] = 'attachment; filename="casa-monarca-ecc-pubkey.pem"'
    return response


@login_required(login_url='iam:login')
@require_level(2)
def chain_audit_view(request):
    """Show the hash-chain verification report for ActionSignatures."""
    start = int(request.GET.get('start', 0))
    count = int(request.GET.get('count', 50))
    chain_results = verify_action_chain(start_position=start, count=count)
    broken = [r for r in chain_results if not r['chain_intact'] or not r['signature_valid']]
    return render(request, 'registros/chain_audit.html', {
        'chain_results': chain_results,
        'broken': broken,
        'start': start,
        'count': count,
        'title': 'Auditoría de Cadena Criptográfica',
    })


# ══════════════════════════════════════════════════════════════════════════════
# WORKFLOW VIEWS
# ══════════════════════════════════════════════════════════════════════════════

def _build_diff_data(wf):
    """Return a list of {label, current, proposed, changed} dicts for update requests."""
    if wf.action_type != 'update_registration' or not wf.payload or not wf.registration:
        return []
    reg = wf.registration
    field_labels = {
        f.name: str(f.verbose_name)
        for f in MigrantRegistration._meta.get_fields()
        if hasattr(f, 'verbose_name')
    }
    rows = []
    for field, proposed in wf.payload.items():
        if not hasattr(reg, field):
            continue
        current = getattr(reg, field)
        if hasattr(current, 'isoformat'):
            current = current.isoformat()
        current_str = str(current) if current is not None else ''
        proposed_str = str(proposed) if proposed is not None else ''
        rows.append({
            'label': field_labels.get(field, field),
            'current': current_str,
            'proposed': proposed_str,
            'changed': current_str != proposed_str,
        })
    return rows

@login_required(login_url='iam:login')
@onboarding_required
@require_level(3)
def workflow_list(request):
    """All workflow requests visible to the current user."""
    user = request.user
    if user.access_level == 1:
        qs = WorkflowRequest.objects.all()
    elif user.access_level == 2:
        qs = WorkflowRequest.objects.all()
    else:
        # Operativo sees requests they can act on + requests they created
        qs = WorkflowRequest.objects.filter(
            current_approver_level=user.access_level
        ) | WorkflowRequest.objects.filter(requested_by=user)

    all_requests = list(qs.select_related('requested_by', 'registration').order_by('-created_at'))
    pending = pending_requests_for(user)
    pending_pks = {wf.pk for wf in all_requests if wf.is_pending_for(user)}
    executable_pks = {wf.pk for wf in all_requests if wf.can_execute_by(user)}
    unread_notifications = Notification.objects.filter(
        recipient=user, is_read=False,
    ).select_related('workflow_request').order_by('-created_at')
    return render(request, 'registros/workflow_list.html', {
        'requests': all_requests,
        'pending_count': pending.count(),
        'pending_pks': pending_pks,
        'executable_pks': executable_pks,
        'unread_notifications': unread_notifications,
        'title': 'Solicitudes de Flujo de Trabajo',
    })


@login_required(login_url='iam:login')
@onboarding_required
@require_level(3)
def workflow_detail(request, pk):
    wf = get_object_or_404(WorkflowRequest, pk=pk)
    steps = wf.approval_steps.select_related('actor').order_by('created_at')
    form = WorkflowApprovalForm() if wf.is_pending_for(request.user) else None
    diff_data = _build_diff_data(wf)
    return render(request, 'registros/workflow_detail.html', {
        'wf': wf, 'steps': steps, 'form': form,
        'can_act': wf.is_pending_for(request.user),
        'can_execute': wf.can_execute_by(request.user),
        'diff_data': diff_data,
        'title': f'Solicitud #{wf.pk}',
    })


@login_required(login_url='iam:login')
@onboarding_required
@require_level(3)
def workflow_registration_preview(request, pk):
    wf = get_object_or_404(WorkflowRequest, pk=pk)
    if wf.action_type != WorkflowRequest.ACTION_CREATE_REGISTRATION:
        messages.error(request, 'Esta vista solo está disponible para solicitudes de creación de registro.')
        return redirect('registros:workflow_detail', pk=pk)

    if wf.registration:
        return redirect('registros:registro_detail', pk=wf.registration.pk)

    payload = wf.payload or {}
    field_labels = {
        'full_name': 'Nombre completo',
        'birth_date': 'Fecha de nacimiento',
        'gender': 'Género',
        'nationality': 'Nacionalidad',
        'country_of_origin': 'País de origen',
        'document_type': 'Tipo de documento',
        'document_number': 'Número de documento',
        'phone': 'Teléfono',
        'email': 'Correo electrónico',
        'entry_date': 'Fecha de ingreso al país',
        'entry_point': 'Punto de ingreso',
        'transit_countries': 'Países de tránsito',
        'intended_destination': 'Destino final deseado',
        'marital_status': 'Estado civil',
        'travels_alone': 'Viaja solo/a',
        'group_size': 'Personas en el grupo',
        'minors_in_group': 'Menores en el grupo',
        'assistance_requested': 'Tipo de asistencia solicitada',
        'migration_reason': 'Motivo de migración',
        'current_legal_status': 'Situación migratoria actual',
        'shelter_name': 'Nombre del albergue/alojamiento',
        'emergency_contact_name': 'Nombre del contacto de emergencia',
        'emergency_contact_phone': 'Teléfono del contacto de emergencia',
        'emergency_contact_relationship': 'Parentesco del contacto de emergencia',
        'observations': 'Observaciones adicionales',
    }
    field_order = [
        'full_name', 'birth_date', 'gender', 'nationality', 'country_of_origin',
        'document_type', 'document_number', 'phone', 'email',
        'entry_date', 'entry_point', 'transit_countries', 'intended_destination',
        'marital_status', 'travels_alone', 'group_size', 'minors_in_group',
        'assistance_requested', 'migration_reason', 'current_legal_status', 'shelter_name',
        'emergency_contact_name', 'emergency_contact_phone', 'emergency_contact_relationship',
        'observations',
    ]
    rows = [
        {
            'label': field_labels.get(field, field),
            'value': payload.get(field, '—') if payload.get(field, '') not in [None, ''] else '—',
        }
        for field in field_order
    ]
    return render(request, 'registros/workflow_registration_preview.html', {
        'wf': wf,
        'rows': rows,
        'title': f'Previsualizar registro para solicitud #{wf.pk}',
    })


@login_required(login_url='iam:login')
@onboarding_required
@require_level(3)
def workflow_decide(request, pk):
    """GET: show decision form. POST: approve or reject a workflow request."""
    wf = get_object_or_404(WorkflowRequest, pk=pk)

    if not wf.is_pending_for(request.user):
        messages.error(request, 'No tienes autorización para decidir sobre esta solicitud.')
        return redirect('registros:workflow_detail', pk=pk)

    diff_data = _build_diff_data(wf)
    if request.method == 'GET':
        form = WorkflowApprovalForm()
        return render(request, 'registros/workflow_decide.html', {
            'wf': wf, 'form': form, 'diff_data': diff_data,
        })

    form = WorkflowApprovalForm(request.POST)
    if not form.is_valid():
        return render(request, 'registros/workflow_decide.html', {
            'wf': wf, 'form': form, 'diff_data': diff_data,
        })

    if not request.user.check_password(form.cleaned_data['password']):
        form.add_error('password', 'Contraseña incorrecta.')
        return render(request, 'registros/workflow_decide.html', {
            'wf': wf, 'form': form, 'diff_data': diff_data,
        })

    decision = form.cleaned_data['decision']
    notes = form.cleaned_data.get('notes', '')

    if decision == 'approved' and request.user.access_level <= 2:
        cert_file = request.FILES.get('cert_file')
        if not cert_file:
            messages.error(request, 'Debes subir tu certificado digital para aprobar esta solicitud.')
            return render(request, 'registros/workflow_decide.html', {
                'wf': wf, 'form': form, 'diff_data': diff_data,
            })

        if request.user.access_level == 2:
            key_file = request.FILES.get('key_file')
            if not key_file:
                messages.error(request, 'Debes subir tu llave privada para aprobar esta solicitud.')
                return render(request, 'registros/workflow_decide.html', {
                    'wf': wf, 'form': form, 'diff_data': diff_data,
                })
            cert_bytes = cert_file.read()
            key_bytes = key_file.read()
            if not validate_coordinator_cert_and_key(request.user, cert_bytes, key_bytes):
                messages.error(request, 'Certificado o llave inválidos. Usa el .cert y la .key originales descargados, y no los conviertas a otro formato.')
                return render(request, 'registros/workflow_decide.html', {
                    'wf': wf, 'form': form, 'diff_data': diff_data,
                })
        else:
            cert_content = cert_file.read().decode('utf-8', errors='ignore').strip()
            if not validate_encrypted_certificate(request.user, cert_content):
                messages.error(request, 'Certificado inválido. Revisa tu archivo e intenta de nuevo.')
                return render(request, 'registros/workflow_decide.html', {
                    'wf': wf, 'form': form, 'diff_data': diff_data,
                })

    if decision == 'approved':
        ok = approve_request(wf, request.user, notes=notes)
        if ok:
            messages.success(request, f'Solicitud #{wf.pk} aprobada.')
        else:
            messages.error(request, 'No tienes autorización para aprobar esta solicitud.')
    else:
        ok = reject_request(wf, request.user, notes=notes)
        if ok:
            messages.success(request, f'Solicitud #{wf.pk} rechazada.')
        else:
            messages.error(request, 'No tienes autorización para rechazar esta solicitud.')

    return redirect('registros:workflow_list')


@login_required(login_url='iam:login')
@onboarding_required
@require_level(2)
def workflow_execute(request, pk):
    """GET: show execution form. POST: execute an APPROVED workflow request (Level 1–2 only)."""
    wf = get_object_or_404(WorkflowRequest, pk=pk)

    if wf.state != 'approved':
        messages.error(request, 'Esta solicitud no está en estado aprobado.')
        return redirect('registros:workflow_detail', pk=pk)

    if request.method == 'GET':
        return render(request, 'registros/workflow_execute.html', {'wf': wf})

    if not request.user.check_password(request.POST.get('password', '')):
        messages.error(request, 'Contraseña incorrecta.')
        return render(request, 'registros/workflow_execute.html', {'wf': wf})

    if request.user.access_level <= 2:
        cert_file = request.FILES.get('cert_file')
        if not cert_file:
            messages.error(request, 'Debes subir tu certificado digital para ejecutar esta solicitud.')
            return render(request, 'registros/workflow_execute.html', {'wf': wf})

        if request.user.access_level == 2:
            key_file = request.FILES.get('key_file')
            if not key_file:
                messages.error(request, 'Debes subir tu llave privada para ejecutar esta solicitud.')
                return render(request, 'registros/workflow_execute.html', {'wf': wf})
            cert_bytes = cert_file.read()
            key_bytes = key_file.read()
            if not validate_coordinator_cert_and_key(request.user, cert_bytes, key_bytes):
                messages.error(request, 'Certificado o llave inválidos. Usa el .cert y la .key originales descargados, y no los conviertas a otro formato.')
                return render(request, 'registros/workflow_execute.html', {'wf': wf})
        else:
            cert_content = cert_file.read().decode('utf-8', errors='ignore').strip()
            if not validate_encrypted_certificate(request.user, cert_content):
                messages.error(request, 'Certificado inválido. Revisa tu archivo e intenta de nuevo.')
                return render(request, 'registros/workflow_execute.html', {'wf': wf})

    ok = execute_request(wf, request.user, password_verified=True,
                         notes=request.POST.get('notes', ''))
    if ok:
        messages.success(request, f'Solicitud #{wf.pk} ejecutada exitosamente.')
    else:
        messages.error(request, 'No se pudo ejecutar la solicitud. Verifica el estado y tus permisos.')

    return redirect('registros:workflow_list')


@login_required(login_url='iam:login')
@onboarding_required
def workflow_request_create(request, pk, action):
    """
    Create a WorkflowRequest for an action the current user cannot perform directly.
    """
    registration = get_object_or_404(MigrantRegistration, pk=pk, is_deleted=False)

    if can_act_directly(action, request.user.access_level):
        if action == 'update_registration':
            return redirect('registros:registro_edit', pk=pk)
        return redirect('registros:registro_detail', pk=pk)

    # Block duplicate pending requests from the same user for the same record+action
    existing = WorkflowRequest.objects.filter(
        registration=registration,
        action_type=action,
        state__in=[
            WorkflowRequest.STATE_SUBMITTED,
            WorkflowRequest.STATE_PENDING_REVIEW,
            WorkflowRequest.STATE_ESCALATED,
        ],
        requested_by=request.user,
    ).first()
    if existing:
        messages.warning(
            request,
            f'Ya tienes una solicitud pendiente (#{existing.pk}) para este registro. '
            'Espera a que sea revisada antes de enviar otra.',
        )
        return redirect('registros:workflow_detail', pk=existing.pk)

    from .workflow import get_approval_chain
    chain = get_approval_chain(action, request.user.access_level)
    level_labels = {1: 'Admin', 2: 'Coordinador', 3: 'Operativo', 4: 'Voluntario'}
    chain_display = ' → '.join(level_labels.get(lvl, str(lvl)) for lvl in chain)

    update_form = None
    if action == 'update_registration':
        update_form = WorkflowUpdateRequestForm(
            request.POST if request.method == 'POST' else None,
            instance=registration,
        )

    action_labels = dict(WorkflowRequest.ACTION_CHOICES)
    ctx = {
        'registration': registration,
        'action': action,
        'action_type': action,
        'action_label': action_labels.get(action, action),
        'chain_display': chain_display,
        'form': update_form,
        'title': 'Solicitar: ' + action_labels.get(action, action),
    }

    if request.method == 'POST':
        notes = request.POST.get('notes', '')
        payload = {}

        if action == 'update_registration':
            if not update_form.is_valid():
                return render(request, 'registros/workflow_request_create.html', ctx)
            for field, value in update_form.cleaned_data.items():
                payload[field] = value.isoformat() if hasattr(value, 'isoformat') else value

        try:
            wf = create_workflow_request(
                action_type=action,
                requester=request.user,
                registration=registration,
                payload=payload,
                notes=notes,
            )
            if action == 'update_registration':
                messages.success(
                    request,
                    f'Tu solicitud #{wf.pk} fue enviada. '
                    'Será revisada por el coordinador.',
                )
            else:
                messages.success(
                    request,
                    f'Tu solicitud de eliminación #{wf.pk} fue enviada para aprobación.',
                )
            return redirect('registros:workflow_detail', pk=wf.pk)
        except ValueError as exc:
            messages.error(request, str(exc))

    return render(request, 'registros/workflow_request_create.html', ctx)


# ══════════════════════════════════════════════════════════════════════════════
# BATCH SIGNING
# ══════════════════════════════════════════════════════════════════════════════

@login_required(login_url='iam:login')
@onboarding_required
@require_level(2)
def batch_sign_view(request):
    """
    Allow Coordinador / Admin to select multiple approved WorkflowRequests
    and sign them in a single password-confirmation step.
    """
    pending_approved = WorkflowRequest.objects.filter(
        state=WorkflowRequest.STATE_APPROVED,
        current_approver_level=0,
    ).select_related('requested_by', 'registration')

    if request.method == 'POST':
        ids = request.POST.getlist('request_ids')
        password = request.POST.get('password', '')

        if not ids:
            messages.error(request, 'Selecciona al menos una solicitud.')
            return redirect('registros:batch_sign')

        if not request.user.check_password(password):
            messages.error(request, 'Contraseña incorrecta.')
            return redirect('registros:batch_sign')

        items = [
            {
                'subject_type': 'workflow_step',
                'subject_id': int(wf_id),
                'extra': {'action': 'batch_approve'},
            }
            for wf_id in ids
        ]
        batch, sigs = batch_sign_actions(items, request.user, ip_address=_get_ip(request))

        # Execute each approved request
        executed = 0
        for wf_id in ids:
            try:
                wf = WorkflowRequest.objects.get(pk=int(wf_id),
                                                 state=WorkflowRequest.STATE_APPROVED)
                execute_request(wf, request.user, password_verified=True,
                                notes=f'Firma masiva #{batch.pk}')
                executed += 1
            except WorkflowRequest.DoesNotExist:
                pass

        messages.success(request,
                         f'Firma masiva #{batch.pk}: {executed} solicitudes ejecutadas, '
                         f'{len(sigs)} firmas generadas.')
        return redirect('registros:workflow_list')

    return render(request, 'registros/batch_sign.html', {
        'pending': pending_approved,
        'title': 'Firma Masiva',
    })


# ══════════════════════════════════════════════════════════════════════════════
# ARCO VIEWS
# ══════════════════════════════════════════════════════════════════════════════

def _generate_access_pdf(arco) -> bytes:
    """Generate a printable PDF with the migrant's data for an Acceso ARCO request."""
    from reportlab.lib.pagesizes import LETTER
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    from reportlab.lib import colors

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=LETTER,
        leftMargin=2 * cm,
        rightMargin=2 * cm,
        topMargin=2 * cm,
        bottomMargin=2 * cm,
    )
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle('title', parent=styles['Heading1'], fontSize=14, spaceAfter=6)
    label_style = ParagraphStyle('label', parent=styles['Normal'], fontSize=9, textColor=colors.grey)
    value_style = ParagraphStyle('value', parent=styles['Normal'], fontSize=10, spaceAfter=4)

    reg = arco.registration
    elements = [
        Paragraph('Casa Monarca — Respuesta a Solicitud ARCO (Acceso)', title_style),
        Paragraph(f'ID de caso: {arco.case_id}', value_style),
        Paragraph(f'Fecha de emisión: {timezone.now().strftime("%d/%m/%Y %H:%M")}', value_style),
        Spacer(1, 0.4 * cm),
    ]

    sections = [
        ('Identificación', [
            ('Identificador interno', reg.internal_id or '—'),
            ('Nombre completo', reg.full_name),
            ('Fecha de nacimiento', str(reg.birth_date)),
            ('Género', reg.get_gender_display()),
            ('Nacionalidad', reg.nationality),
            ('País de origen', reg.country_of_origin),
            ('Tipo de documento', reg.get_document_type_display()),
            ('Número de documento', reg.document_number or '—'),
        ]),
        ('Contacto', [
            ('Teléfono', reg.phone or '—'),
            ('Correo electrónico', reg.email or '—'),
        ]),
        ('Ingreso', [
            ('Fecha de ingreso', str(reg.entry_date)),
            ('Punto de ingreso', reg.entry_point),
            ('Países de tránsito', reg.transit_countries or '—'),
            ('Destino final', reg.intended_destination or '—'),
        ]),
        ('Grupo familiar', [
            ('Estado civil', reg.get_marital_status_display()),
            ('Viaja solo/a', 'Sí' if reg.travels_alone else 'No'),
            ('Tamaño del grupo', str(reg.group_size)),
            ('Menores en el grupo', str(reg.minors_in_group)),
        ]),
        ('Situación', [
            ('Situación migratoria', reg.get_current_legal_status_display()),
            ('Motivo de migración', reg.migration_reason),
            ('Asistencia solicitada', reg.assistance_requested),
            ('Nombre del albergue', reg.shelter_name or '—'),
        ]),
        ('Observaciones', [
            ('Observaciones', reg.observations or '—'),
        ]),
    ]

    for section_title, rows in sections:
        elements.append(Paragraph(section_title, styles['Heading3']))
        table_data = [[Paragraph(label, label_style), Paragraph(str(val), value_style)]
                      for label, val in rows]
        t = Table(table_data, colWidths=[5 * cm, 12 * cm])
        t.setStyle(TableStyle([
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('ROWBACKGROUNDS', (0, 0), (-1, -1), [colors.white, colors.Color(0.96, 0.96, 0.98)]),
            ('GRID', (0, 0), (-1, -1), 0.3, colors.lightgrey),
            ('LEFTPADDING', (0, 0), (-1, -1), 6),
            ('RIGHTPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]))
        elements.append(t)
        elements.append(Spacer(1, 0.3 * cm))

    elements.append(Spacer(1, 0.6 * cm))
    elements.append(Paragraph(
        f'Ejecutado por: {arco.executed_by.get_full_name() or arco.executed_by.username} '
        f'(Nivel {arco.executed_by.access_level})',
        value_style,
    ))
    if arco.action_signature:
        elements.append(Paragraph(
            f'Firma digital (hash): {arco.action_signature.message_hash}',
            label_style,
        ))

    doc.build(elements)
    return buffer.getvalue()


@login_required(login_url='iam:login')
@onboarding_required
@require_level(3)
def arco_list(request):
    user = request.user
    if user.access_level <= 2:
        qs = ArcoRequest.objects.all()
    else:
        qs = ArcoRequest.objects.filter(requested_by=user)
    qs = qs.select_related('requested_by', 'registration', 'executed_by').order_by('-created_at')
    return render(request, 'registros/arco_list.html', {
        'requests': qs, 'title': 'Solicitudes ARCO',
    })


@login_required(login_url='iam:login')
@onboarding_required
@require_level(3)
def arco_create(request, pk):
    """File an ARCO request for a specific migrant registration."""
    registration = get_object_or_404(MigrantRegistration, pk=pk, is_deleted=False)
    form = ArcoRequestForm(request.POST or None, request.FILES or None)

    if request.method == 'POST' and form.is_valid():
        arco = form.save(commit=False)
        arco.registration = registration
        arco.requested_by = request.user
        arco.state = ArcoRequest.STATE_SUBMITTED

        from datetime import timedelta
        arco.legal_deadline = (timezone.now() + timedelta(days=28)).date()

        # Only store attached PDF for Rectificación; clear it for all other types
        if arco.arco_type != ArcoRequest.ARCO_RECTIFICATION:
            arco.attached_document = None

        action_map = {
            ArcoRequest.ARCO_ACCESS: WorkflowRequest.ACTION_ARCO_ACCESS,
            ArcoRequest.ARCO_RECTIFICATION: WorkflowRequest.ACTION_ARCO_RECTIFICATION,
            ArcoRequest.ARCO_CANCELLATION: WorkflowRequest.ACTION_ARCO_CANCELLATION,
            ArcoRequest.ARCO_OPPOSITION: WorkflowRequest.ACTION_ARCO_OPPOSITION,
        }
        wf_action = action_map[arco.arco_type]

        try:
            wf = create_workflow_request(
                action_type=wf_action,
                requester=request.user,
                registration=registration,
                payload={'arco_type': arco.arco_type, 'description': arco.description},
                notes=arco.description,
            )
            arco.workflow_request = wf
        except ValueError:
            # User has direct authority — mark as in_review immediately
            arco.state = ArcoRequest.STATE_IN_REVIEW

        arco.save()

        # Create linked Ticket
        ticket = Ticket.create_for_arco(arco, request.user)
        arco.ticket = ticket
        arco.save(update_fields=['ticket'])

        _log(request.user, 'arco_request_created',
             f'{arco.case_id} {arco.get_arco_type_display()} para Registro #{registration.pk}',
             request=request)

        messages.success(request, f'Solicitud ARCO {arco.case_id} registrada.')
        return redirect('registros:arco_detail', pk=arco.pk)

    return render(request, 'registros/arco_form.html', {
        'form': form,
        'registration': registration,
        'title': f'Solicitud ARCO — Registro #{registration.pk}',
    })


@login_required(login_url='iam:login')
@onboarding_required
@require_level(3)
def arco_detail(request, pk):
    """Detail view for a single ARCO case."""
    arco = get_object_or_404(ArcoRequest, pk=pk)
    user = request.user

    # Operativo can only see their own requests
    if user.access_level == 3 and arco.requested_by != user:
        messages.error(request, 'No tienes acceso a esta solicitud ARCO.')
        return redirect('registros:arco_list')

    can_execute = (
        user.access_level <= 2
        and arco.can_execute(user)
        and arco.state not in (ArcoRequest.STATE_EXECUTED, ArcoRequest.STATE_REJECTED)
    )
    can_cancel_data = (user.access_level == 1)

    return render(request, 'registros/arco_detail.html', {
        'arco': arco,
        'can_execute': can_execute,
        'can_cancel_data': can_cancel_data,
        'title': f'Caso ARCO {arco.case_id}',
    })


@login_required(login_url='iam:login')
@onboarding_required
@require_level(2)
def arco_execute(request, pk):
    """Coordinador/Admin executes (fulfils) an ARCO request."""
    arco = get_object_or_404(ArcoRequest, pk=pk)

    if arco.state == ArcoRequest.STATE_EXECUTED:
        messages.error(request, 'Esta solicitud ya fue ejecutada.')
        return redirect('registros:arco_detail', pk=pk)

    if not arco.can_execute(request.user):
        messages.error(request, 'No tienes autorización para ejecutar esta solicitud ARCO.')
        return redirect('registros:arco_detail', pk=pk)

    if request.method == 'GET':
        return render(request, 'registros/arco_detail.html', {
            'arco': arco,
            'can_execute': True,
            'show_execute_modal': True,
            'title': f'Ejecutar {arco.case_id}',
        })

    # ── POST: validate credentials ────────────────────────────────────────────
    if not request.user.check_password(request.POST.get('password', '')):
        messages.error(request, 'Contraseña incorrecta.')
        return redirect('registros:arco_detail', pk=pk)

    cert_file = request.FILES.get('cert_file')
    key_file = request.FILES.get('key_file')

    if not cert_file:
        messages.error(request, 'Debes subir tu certificado digital (.cert) para ejecutar.')
        return redirect('registros:arco_detail', pk=pk)

    if request.user.access_level == 2:
        if not key_file:
            messages.error(request, 'Debes subir tu llave privada (.key) para ejecutar.')
            return redirect('registros:arco_detail', pk=pk)
        cert_bytes = cert_file.read()
        key_bytes = key_file.read()
        if not validate_coordinator_cert_and_key(request.user, cert_bytes, key_bytes):
            messages.error(request, 'Certificado o llave inválidos. Usa los archivos .cert y .key originales.')
            return redirect('registros:arco_detail', pk=pk)
    else:
        # Admin: encrypted certificate
        cert_content = cert_file.read().decode('utf-8', errors='ignore').strip()
        if not validate_encrypted_certificate(request.user, cert_content):
            messages.error(request, 'Certificado inválido. Revisa tu archivo.')
            return redirect('registros:arco_detail', pk=pk)

    # ── Extra restriction: Cancelación → Admin only ───────────────────────────
    if arco.arco_type == ArcoRequest.ARCO_CANCELLATION and request.user.access_level > 1:
        messages.error(request, 'Solo el Administrador puede ejecutar una Cancelación ARCO.')
        return redirect('registros:arco_detail', pk=pk)

    notes = request.POST.get('notes', '')

    # ── Sign closure ─────────────────────────────────────────────────────────
    from .services import sign_action as _sign_action
    action_sig = _sign_action(
        subject_type='arco_request',
        subject_id=arco.pk,
        extra={
            'case_id': arco.case_id,
            'arco_type': arco.arco_type,
            'registration_id': arco.registration_id,
            'actor_id': request.user.pk,
            'actor_role': request.user.access_level,
            'executed_at': timezone.now().isoformat(),
        },
        signer=request.user,
    )

    # ── Type-specific action ──────────────────────────────────────────────────
    if arco.arco_type == ArcoRequest.ARCO_ACCESS:
        arco.executed_by = request.user
        arco.executed_at = timezone.now()
        pdf_bytes = _generate_access_pdf(arco)
        from django.core.files.base import ContentFile
        arco.generated_document.save(
            f'{arco.case_id}_acceso.pdf',
            ContentFile(pdf_bytes),
            save=False,
        )

    elif arco.arco_type == ArcoRequest.ARCO_RECTIFICATION:
        # Apply field changes from workflow payload if present
        if arco.workflow_request and arco.workflow_request.payload:
            payload = arco.workflow_request.payload
            reg = arco.registration
            import datetime
            from django.db.models import DateField
            date_fields = {f.name for f in reg._meta.get_fields() if isinstance(f, DateField)}
            skip = {'arco_type', 'description'}
            for field, value in payload.items():
                if field in skip or not hasattr(reg, field):
                    continue
                if field in date_fields and isinstance(value, str):
                    try:
                        value = datetime.date.fromisoformat(value)
                    except (ValueError, TypeError):
                        continue
                setattr(reg, field, value)
            reg.save()

    elif arco.arco_type == ArcoRequest.ARCO_CANCELLATION:
        arco.registration.soft_delete(request.user)

    elif arco.arco_type == ArcoRequest.ARCO_OPPOSITION:
        reg = arco.registration
        note = f'[ARCO Oposición {arco.case_id}] {notes or arco.description}'
        reg.observations = (reg.observations + '\n' + note).strip() if reg.observations else note
        reg.save(update_fields=['observations'])

    # ── Finalize ─────────────────────────────────────────────────────────────
    arco.state = ArcoRequest.STATE_EXECUTED
    arco.executed_by = request.user
    arco.executed_at = timezone.now()
    arco.execution_notes = notes
    arco.action_signature = action_sig
    arco.save(update_fields=[
        'state', 'executed_by', 'executed_at', 'execution_notes',
        'action_signature', 'generated_document',
    ])

    # Close linked ticket
    if arco.ticket:
        arco.ticket.status = Ticket.STATUS_CERRADO
        arco.ticket.save(update_fields=['status', 'updated_at'])

    # Notify requester
    from .models import Notification
    Notification.objects.create(
        recipient=arco.requested_by,
        workflow_request=arco.workflow_request,
        message=(
            f'Tu solicitud ARCO {arco.case_id} '
            f'({arco.get_arco_type_display()}) fue ejecutada.'
            + (f' Notas: {notes}' if notes else '')
        ),
    )

    _log(request.user, 'arco_request_executed',
         f'{arco.case_id} {arco.get_arco_type_display()} | '
         f'firma: {action_sig.message_hash[:16]}…',
         request=request)

    messages.success(request, f'Solicitud ARCO {arco.case_id} ejecutada y firmada.')
    return redirect('registros:arco_detail', pk=pk)


@login_required(login_url='iam:login')
@onboarding_required
@require_level(3)
def arco_download(request, pk):
    """Download the generated PDF for an Acceso ARCO case."""
    arco = get_object_or_404(ArcoRequest, pk=pk)
    user = request.user

    if user.access_level == 3 and arco.requested_by != user:
        messages.error(request, 'No tienes acceso a este documento.')
        return redirect('registros:arco_list')

    if not arco.generated_document:
        raise Http404('No hay documento generado para esta solicitud.')

    return FileResponse(
        arco.generated_document.open('rb'),
        as_attachment=True,
        filename=f'{arco.case_id}_acceso.pdf',
        content_type='application/pdf',
    )


# ══════════════════════════════════════════════════════════════════════════════
# NOTIFICATIONS
# ══════════════════════════════════════════════════════════════════════════════

@login_required(login_url='iam:login')
@require_POST
def notifications_mark_read(request):
    """Mark all unread notifications for the current user as read."""
    Notification.objects.filter(recipient=request.user, is_read=False).update(is_read=True)
    return redirect(request.POST.get('next', 'registros:workflow_list'))


# ══════════════════════════════════════════════════════════════════════════════
# TICKETS
# ══════════════════════════════════════════════════════════════════════════════

@login_required(login_url='iam:login')
@onboarding_required
def ticket_list(request):
    tickets = Ticket.objects.select_related('registration', 'created_by')
    if request.user.access_level > 2:
        tickets = tickets.filter(created_by=request.user)

    q = request.GET.get('q', '').strip()
    if q:
        tickets = tickets.filter(
            ticket_id__icontains=q
        ) | tickets.filter(
            summary__icontains=q
        ) | tickets.filter(
            registration__full_name__icontains=q
        )

    priority = request.GET.get('priority', '').strip()
    if priority:
        tickets = tickets.filter(priority=priority)

    status = request.GET.get('status', '').strip()
    if status:
        tickets = tickets.filter(status=status)

    return render(request, 'registros/ticket_list.html', {
        'title': 'Tickets de soporte',
        'tickets': tickets.order_by('-created_at'),
        'q': q,
        'priority': priority,
        'status': status,
        'priority_choices': Ticket.PRIORITY_CHOICES,
        'status_choices': Ticket.STATUS_CHOICES,
    })


@login_required(login_url='iam:login')
@onboarding_required
def ticket_detail(request, ticket_id):
    ticket = get_object_or_404(Ticket, ticket_id=ticket_id)
    if request.user.access_level > 2 and ticket.created_by != request.user:
        messages.error(request, 'No tienes acceso a este ticket.')
        return redirect('registros:ticket_list')

    if request.method == 'POST' and request.user.access_level <= 2:
        new_status = request.POST.get('status')
        if new_status in dict(Ticket.STATUS_CHOICES):
            ticket.status = new_status
            ticket.save(update_fields=['status', 'updated_at'])
            messages.success(request, 'Estado del ticket actualizado.')

    return render(request, 'registros/ticket_detail.html', {
        'title': f'Ticket {ticket.ticket_id}',
        'ticket': ticket,
        'status_choices': Ticket.STATUS_CHOICES,
        'can_update_status': request.user.access_level <= 2,
    })
