"""
Django views for migrant record management, ARCO rights, and workflow — subsystems (b), (d), (e).

View categories:
  - MigrantRegistration CRUD:  create, list, detail, soft-delete with audit trail.
  - Document signing:          sign at creation (ECDSA), verify from expediente view.
  - Workflow:                  request creation, approval/rejection, execution (multi-level).
  - Batch signing:             sign multiple workflow requests in a single session.
  - ARCO rights:               access, rectification, cancellation, opposition flows.
  - ArcoTicket:                dedicated ARCO case management with legal deadline.
  - Chain audit:               public view showing hash-chain integrity status.
  - External verification:     verify document signatures without authentication.
"""

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
from iam.certificates import validate_coordinator_cert_and_key, validate_cert_and_key
from .forms import ArcoRequestForm, MigrantRegistrationForm, WorkflowApprovalForm, WorkflowUpdateRequestForm
from .models import (
    ArcoRequest, ArcoTicket, MigrantRegistration, MigrantRegistrationSignature,
    Notification, RegistrationEvent, Ticket, WorkflowRequest, PRIVACY_NOTICE_VERSION,
)

# ── Tracked fields for coordinator edits before execution ─────────────────────
_TRACKED_FIELDS = [
    'first_name', 'first_surname', 'second_surname', 'birth_date',
    'gender', 'country_of_origin', 'state_or_region', 'phone',
    'service_date', 'marital_status', 'age_group', 'population_group',
]

_FIELD_META = [
    ('first_name',        'Nombre',                'text',   None),
    ('first_surname',     'Primer apellido',        'text',   None),
    ('second_surname',    'Segundo apellido',       'text',   None),
    ('birth_date',        'Fecha de nacimiento',    'date',   None),
    ('gender',            'Género',                 'select', MigrantRegistration.GENDER_CHOICES),
    ('country_of_origin', 'País de origen',         'text',   None),
    ('state_or_region',   'Departamento/Estado',    'text',   None),
    ('phone',             'Teléfono',               'text',   None),
    ('service_date',      'Fecha de servicio',      'date',   None),
    ('marital_status',    'Estado civil',           'select', MigrantRegistration.MARITAL_STATUS_CHOICES),
    ('age_group',         'Grupo de edad',          'select', MigrantRegistration.AGE_GROUP_CHOICES),
    ('population_group',  'Grupo poblacional',      'select', MigrantRegistration.POPULATION_GROUP_CHOICES),
]


def _build_editable_payload_fields(payload):
    """Return template-ready list of field dicts for coordinator edits."""
    return [
        {
            'field': field,
            'label': label,
            'value': payload.get(field, ''),
            'input_type': input_type,
            'choices': choices or [],
        }
        for field, label, input_type, choices in _FIELD_META
    ]


def _extract_payload_modifications(old_payload, post_data):
    """
    Compare POST values (prefixed with 'edit_') against old_payload.
    Returns {field: {before, after}} for changed fields only.
    """
    mods = {}
    for field in _TRACKED_FIELDS:
        old_val = str(old_payload.get(field, '') or '')
        new_val = post_data.get(f'edit_{field}', '').strip()
        if new_val and old_val != new_val:
            mods[field] = {'before': old_val, 'after': new_val}
    return mods
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


def _reg_event(registration, event_type, actor, details='', request=None):
    """Create a RegistrationEvent entry for the per-expediente audit trail."""
    RegistrationEvent.objects.create(
        registration=registration,
        event_type=event_type,
        actor=actor,
        actor_role=getattr(actor, 'access_level', None),
        details=details,
        ip_address=_get_ip(request) if request else None,
    )


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
            'first_name', 'first_surname', 'second_surname',
            'birth_date', 'gender',
        ]),
        ('Origen', [
            'country_of_origin', 'state_or_region',
        ]),
        ('Contacto', ['phone']),
        ('Fecha de servicio', ['service_date']),
        ('Grupo familiar', ['marital_status']),
        ('Clasificación', ['age_group', 'population_group']),
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
                    if request.user.access_level == 4:
                        messages.success(
                            request,
                            'Tu solicitud fue enviada. El operador la revisará pronto.',
                        )
                        return redirect('registros:registro_new')
                    else:
                        messages.success(
                            request,
                            'Tu solicitud fue enviada. Puedes seguir su estado en el flujo de trabajo.',
                        )
                        return redirect('registros:workflow_list')
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
        _reg_event(registration, RegistrationEvent.EVENT_CREATE, request.user,
                   details=f'Creado y firmado. Hash: {sig_data["message_hash"][:16]}…', request=request)
        _reg_event(registration, RegistrationEvent.EVENT_CONSENT, request.user,
                   details=f'Consentimiento v{PRIVACY_NOTICE_VERSION} | método: {registration.consent_method} | proxy: {registration.consent_by_proxy}',
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
    from django.core.paginator import Paginator
    
    qs = MigrantRegistration.objects.filter(
        is_deleted=False, arco_cancelled_at__isnull=True
    ).select_related('created_by').prefetch_related('signature')
    
    q = request.GET.get('q', '').strip()
    if q:
        qs = qs.filter(internal_id__icontains=q)
    
    # Paginar: 20 registros por página
    paginator = Paginator(qs, 20)
    page_num = request.GET.get('page', 1)
    page_obj = paginator.get_page(page_num)
    
    return render(request, 'registros/list.html', {
        'registrations': page_obj.object_list,
        'page_obj': page_obj,
        'q': q,
        'title': 'Registros Migrantes',
    })


@login_required(login_url='iam:login')
@onboarding_required
@require_level(3)
def registro_detail(request, pk):
    registration = get_object_or_404(MigrantRegistration, pk=pk, is_deleted=False)

    # ARCO-cancelled records: only admin can see (redirected to audit list)
    if registration.arco_cancelled_at:
        if request.user.access_level == 1:
            messages.info(
                request,
                f'El registro {registration.internal_id} fue cancelado por ARCO '
                f'el {registration.arco_cancelled_at:%d/%m/%Y}. '
                'Solo se muestra el identificador.',
            )
            return redirect('registros:arco_cancelled_list')
        raise Http404('Este registro fue cancelado por una solicitud ARCO y no es accesible.')

    try:
        sig = registration.signature
        verify_result = verify_registration(registration, sig)
    except MigrantRegistrationSignature.DoesNotExist:
        sig = None
        verify_result = None

    _reg_event(registration, RegistrationEvent.EVENT_VIEW, request.user,
               details=f'Consultado desde {request.path}', request=request)

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
        registration = form.save()
        # Re-sign so the stored ECDSA signature stays valid after field changes
        sig_data = sign_registration(registration)
        from .models import MigrantRegistrationSignature
        updated = MigrantRegistrationSignature.objects.filter(
            registration=registration
        ).update(
            message_hash=sig_data['message_hash'],
            signature_r=sig_data['signature_r'],
            signature_s=sig_data['signature_s'],
            public_key=sig_data['public_key'],
            curve_name=sig_data['curve_name'],
            signed_by=request.user,
            signed_by_role=request.user.access_level,
            signed_at=timezone.now(),
        )
        if not updated:
            MigrantRegistrationSignature.objects.create(
                registration=registration,
                signed_by=request.user,
                signed_by_role=request.user.access_level,
                **sig_data,
            )
        _log(request.user, 'registro_migrante_editado',
             f'Registro #{registration.pk} editado. Firma actualizada: {sig_data["message_hash"][:16]}…',
             request=request)
        _reg_event(registration, RegistrationEvent.EVENT_UPDATE, request.user,
                   details=f'Editado directamente. Firma re-calculada.', request=request)
        messages.success(request, f'Registro #{registration.pk} actualizado.')
        return redirect('registros:registro_detail', pk=registration.pk)

    return render(request, 'registros/form.html', {
        'form': form, 'registration': registration,
        'editing': True, 'title': f'Editar Registro #{registration.pk}',
    })


@login_required(login_url='iam:login')
@onboarding_required
def registro_delete(request, pk):
    """
    Soft-delete with mandatory cryptographic authentication (Level 1 only).
    Level 2–4 are redirected to create a WorkflowRequest.
    GET: show confirmation form with password + cert + key.
    POST: validate all credentials, sign, then soft-delete.
    """
    registration = get_object_or_404(MigrantRegistration, pk=pk, is_deleted=False)

    if not can_act_directly('delete_registration', request.user.access_level):
        messages.info(request,
                      'Tu nivel de acceso requiere aprobación para eliminar registros. '
                      'Se ha creado una solicitud.')
        return redirect('registros:workflow_request_create',
                        pk=pk, action='delete_registration')

    if request.method == 'GET':
        return render(request, 'registros/registro_delete_confirm.html', {
            'registration': registration,
            'title': f'Eliminar Registro #{registration.internal_id or registration.pk}',
        })

    # ── POST: validate credentials ────────────────────────────────────────────
    if not request.user.check_password(request.POST.get('password', '')):
        messages.error(request, 'Contraseña incorrecta.')
        return render(request, 'registros/registro_delete_confirm.html', {
            'registration': registration,
            'title': f'Eliminar Registro #{registration.internal_id or registration.pk}',
        })

    cert_file = request.FILES.get('cert_file')
    key_file = request.FILES.get('key_file')
    if not cert_file or not key_file:
        messages.error(request, 'Debes subir tu certificado digital (.cert) y tu llave privada (.key).')
        return render(request, 'registros/registro_delete_confirm.html', {
            'registration': registration,
            'title': f'Eliminar Registro #{registration.internal_id or registration.pk}',
        })

    try:
        cert_bytes = cert_file.read()
        key_bytes = key_file.read()
    except Exception:
        cert_bytes, key_bytes = b'', b''

    if not validate_cert_and_key(request.user, cert_bytes, key_bytes):
        messages.error(request, 'Certificado o llave inválidos. Usa los archivos .cert y .key originales.')
        return render(request, 'registros/registro_delete_confirm.html', {
            'registration': registration,
            'title': f'Eliminar Registro #{registration.internal_id or registration.pk}',
        })

    # ── Sign the deletion ─────────────────────────────────────────────────────
    from .services import sign_action as _sign_action
    action_sig = _sign_action(
        subject_type='registration',
        subject_id=registration.pk,
        extra={
            'action': 'delete_registration',
            'internal_id': registration.internal_id,
            'actor_id': request.user.pk,
            'actor_role': request.user.access_level,
            'deleted_at': timezone.now().isoformat(),
        },
        signer=request.user,
    )

    _reg_event(registration, RegistrationEvent.EVENT_DELETE, request.user,
               details=f'Eliminado con autenticación criptográfica. Firma: {action_sig.message_hash[:16]}…',
               request=request)
    registration.soft_delete(request.user)
    _log(request.user, 'registro_migrante_eliminado',
         f'Registro #{registration.pk} eliminado. Firma: {action_sig.message_hash[:16]}…',
         request=request)
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
    """All workflow requests visible to the current user, excluding ARCO (managed in their own panel)."""
    user = request.user
    _arco_types = [
        WorkflowRequest.ACTION_ARCO_ACCESS,
        WorkflowRequest.ACTION_ARCO_RECTIFICATION,
        WorkflowRequest.ACTION_ARCO_CANCELLATION,
        WorkflowRequest.ACTION_ARCO_OPPOSITION,
    ]
    if user.access_level == 1:
        qs = WorkflowRequest.objects.exclude(action_type__in=_arco_types)
    elif user.access_level == 2:
        qs = WorkflowRequest.objects.exclude(action_type__in=_arco_types)
    else:
        # Operativo sees requests they can act on + requests they created
        qs = (
            WorkflowRequest.objects.filter(current_approver_level=user.access_level)
            | WorkflowRequest.objects.filter(requested_by=user)
        ).exclude(action_type__in=_arco_types)

    all_requests = list(qs.select_related('requested_by', 'registration').order_by('-created_at'))
    pending = pending_requests_for(user)
    pending_pks = {wf.pk for wf in all_requests if wf.is_pending_for(user)}
    executable_pks = {wf.pk for wf in all_requests if wf.can_execute_by(user)}
    unread_notifications = Notification.objects.filter(
        recipient=user, is_read=False,
    ).exclude(message__icontains='ARCO').select_related('workflow_request').order_by('-created_at')
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
        'first_name': 'Nombre',
        'first_surname': 'Primer apellido',
        'second_surname': 'Segundo apellido',
        'birth_date': 'Fecha de nacimiento',
        'gender': 'Género',
        'country_of_origin': 'País de origen',
        'state_or_region': 'Departamento/Estado',
        'phone': 'Teléfono',
        'service_date': 'Fecha de servicio',
        'marital_status': 'Estado civil',
        'age_group': 'Grupo de edad',
        'population_group': 'Grupo poblacional',
    }
    field_order = [
        'first_name', 'first_surname', 'second_surname',
        'birth_date', 'gender',
        'country_of_origin', 'state_or_region',
        'phone', 'service_date',
        'marital_status', 'age_group', 'population_group',
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
    """
    GET: show decision form.
    POST: approve or reject a workflow request.

    Cambio 1: If the user is the final executor and the action involves registration
    data, editable payload fields are shown so they can correct data before signing.

    Cambio 2: If the user is the final executor (no more levels after this approval),
    the request is approved AND executed in one step — no second 'execute' visit.
    """
    wf = get_object_or_404(WorkflowRequest, pk=pk)

    if not wf.is_pending_for(request.user):
        messages.error(request, 'No tienes autorización para decidir sobre esta solicitud.')
        return redirect('registros:workflow_detail', pk=pk)

    # Detect if this actor is the last approver in the chain (= final executor)
    is_final_executor = (
        len(wf.pending_levels) == 1
        and wf.pending_levels[0] == request.user.access_level
        and request.user.access_level <= 2
    )
    # Editable payload fields are only relevant for registration-data actions
    show_edit_fields = is_final_executor and wf.action_type in (
        WorkflowRequest.ACTION_CREATE_REGISTRATION,
        WorkflowRequest.ACTION_UPDATE_REGISTRATION,
    )
    editable_payload_fields = _build_editable_payload_fields(wf.payload) if show_edit_fields else []

    diff_data = _build_diff_data(wf)

    ctx = {
        'wf': wf,
        'diff_data': diff_data,
        'is_final_executor': is_final_executor,
        'show_edit_fields': show_edit_fields,
        'editable_payload_fields': editable_payload_fields,
    }

    if request.method == 'GET':
        ctx['form'] = WorkflowApprovalForm()
        return render(request, 'registros/workflow_decide.html', ctx)

    form = WorkflowApprovalForm(request.POST)
    ctx['form'] = form
    if not form.is_valid():
        return render(request, 'registros/workflow_decide.html', ctx)

    if not request.user.check_password(form.cleaned_data['password']):
        form.add_error('password', 'Contraseña incorrecta.')
        return render(request, 'registros/workflow_decide.html', ctx)

    decision = form.cleaned_data['decision']
    notes = form.cleaned_data.get('notes', '')

    # Cert + key always required for level 1–2 when approving
    if decision == 'approved' and request.user.access_level <= 2:
        cert_file = request.FILES.get('cert_file')
        key_file = request.FILES.get('key_file')
        if not cert_file or not key_file:
            messages.error(
                request,
                'Debes subir tu certificado digital (.cert) y tu llave privada (.key) para aprobar.',
            )
            return render(request, 'registros/workflow_decide.html', ctx)
        try:
            cert_bytes = cert_file.read()
            key_bytes = key_file.read()
        except Exception:
            cert_bytes, key_bytes = b'', b''
        if not validate_cert_and_key(request.user, cert_bytes, key_bytes):
            messages.error(
                request,
                'Certificado o llave inválidos. Usa el .cert y la .key originales descargados.',
            )
            return render(request, 'registros/workflow_decide.html', ctx)

    if decision == 'approved':
        # Cambio 1: capture edits to payload before signing
        mods = {}
        if show_edit_fields:
            mods = _extract_payload_modifications(wf.payload, request.POST)
            if mods:
                new_payload = dict(wf.payload)
                for field, change in mods.items():
                    new_payload[field] = change['after']
                wf.modifications_before_execution = mods
                wf.payload = new_payload
                wf.save(update_fields=['modifications_before_execution', 'payload', 'updated_at'])

        ok = approve_request(wf, request.user, notes=notes)
        if ok:
            # Cambio 2: auto-execute if this was the final approval step
            if wf.state == WorkflowRequest.STATE_APPROVED:
                exec_ok = execute_request(wf, request.user, password_verified=True, notes=notes)
                if exec_ok:
                    if mods and wf.registration:
                        changes_str = ', '.join(
                            f'{k}: {v["before"]} → {v["after"]}' for k, v in mods.items()
                        )
                        _reg_event(
                            wf.registration,
                            RegistrationEvent.EVENT_WORKFLOW_APPROVED_WITH_CHANGES,
                            request.user,
                            details=f'Aceptado con cambios realizados: {changes_str}',
                            request=request,
                        )
                    messages.success(request, f'Solicitud #{wf.pk} aprobada y ejecutada.')
                else:
                    messages.warning(
                        request,
                        f'Solicitud #{wf.pk} aprobada pero no se pudo ejecutar automáticamente. '
                        'Procede a ejecutarla manualmente.',
                    )
            else:
                messages.success(request, f'Solicitud #{wf.pk} aprobada y escalada.')
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
    """
    GET: show execution form (with editable payload fields for Cambio 1).
    POST: optionally apply payload modifications, then execute the APPROVED request.

    This view is the fallback for APPROVED workflows not yet executed.
    New workflows are approved+executed in one step via workflow_decide (Cambio 2).
    """
    wf = get_object_or_404(WorkflowRequest, pk=pk)

    if wf.state != WorkflowRequest.STATE_APPROVED:
        messages.error(request, 'Esta solicitud no está en estado aprobado.')
        return redirect('registros:workflow_detail', pk=pk)

    show_edit_fields = wf.action_type in (
        WorkflowRequest.ACTION_CREATE_REGISTRATION,
        WorkflowRequest.ACTION_UPDATE_REGISTRATION,
    )
    editable_payload_fields = _build_editable_payload_fields(wf.payload) if show_edit_fields else []

    ctx = {
        'wf': wf,
        'show_edit_fields': show_edit_fields,
        'editable_payload_fields': editable_payload_fields,
    }

    if request.method == 'GET':
        return render(request, 'registros/workflow_execute.html', ctx)

    # ── POST: validate credentials ────────────────────────────────────────────
    if not request.user.check_password(request.POST.get('password', '')):
        messages.error(request, 'Contraseña incorrecta.')
        return render(request, 'registros/workflow_execute.html', ctx)

    if request.user.access_level <= 2:
        cert_file = request.FILES.get('cert_file')
        key_file = request.FILES.get('key_file')
        if not cert_file or not key_file:
            messages.error(
                request,
                'Debes subir tu certificado digital (.cert) y tu llave privada (.key).',
            )
            return render(request, 'registros/workflow_execute.html', ctx)
        try:
            cert_bytes = cert_file.read()
            key_bytes = key_file.read()
        except Exception:
            cert_bytes, key_bytes = b'', b''
        if not validate_cert_and_key(request.user, cert_bytes, key_bytes):
            messages.error(
                request,
                'Certificado o llave inválidos. Usa el .cert y la .key originales descargados.',
            )
            return render(request, 'registros/workflow_execute.html', ctx)

    # ── Cambio 1: capture payload modifications ───────────────────────────────
    mods = {}
    if show_edit_fields:
        mods = _extract_payload_modifications(wf.payload, request.POST)
        if mods:
            new_payload = dict(wf.payload)
            for field, change in mods.items():
                new_payload[field] = change['after']
            wf.modifications_before_execution = mods
            wf.payload = new_payload
            wf.save(update_fields=['modifications_before_execution', 'payload', 'updated_at'])

    ok = execute_request(
        wf, request.user,
        password_verified=True,
        notes=request.POST.get('notes', ''),
    )
    if ok:
        if mods and wf.registration:
            changes_str = ', '.join(
                f'{k}: {v["before"]} → {v["after"]}' for k, v in mods.items()
            )
            _reg_event(
                wf.registration,
                RegistrationEvent.EVENT_WORKFLOW_APPROVED_WITH_CHANGES,
                request.user,
                details=f'Aceptado con cambios realizados: {changes_str}',
                request=request,
            )
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

    second = reg.second_surname or ''
    second_display = second if second.upper() != 'X' else '—'
    sections = [
        ('Identificación', [
            ('Identificador interno', reg.internal_id or '—'),
            ('Nombre', reg.first_name),
            ('Primer apellido', reg.first_surname),
            ('Segundo apellido', second_display),
            ('Fecha de nacimiento', str(reg.birth_date)),
            ('Género', reg.get_gender_display()),
        ]),
        ('Origen', [
            ('País de origen', reg.country_of_origin),
            ('Departamento/Estado', reg.state_or_region or '—'),
        ]),
        ('Contacto', [
            ('Teléfono', reg.phone or '—'),
        ]),
        ('Servicio', [
            ('Fecha de servicio', str(reg.service_date)),
            ('Estado civil', reg.get_marital_status_display()),
            ('Grupo de edad', reg.get_age_group_display()),
            ('Grupo poblacional', reg.get_population_group_display()),
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
def arco_select_registration(request):
    """Picker step: choose which migrant to file an ARCO request for."""
    from django.core.paginator import Paginator
    
    qs = MigrantRegistration.objects.filter(
        is_deleted=False, arco_cancelled_at__isnull=True
    ).select_related('created_by')
    q = request.GET.get('q', '').strip()
    if q:
        qs = qs.filter(internal_id__icontains=q)
    
    # Paginar: 20 registros por página
    paginator = Paginator(qs, 20)
    page_num = request.GET.get('page', 1)
    page_obj = paginator.get_page(page_num)
    
    return render(request, 'registros/arco_select_registration.html', {
        'registrations': page_obj.object_list,
        'page_obj': page_obj,
        'q': q,
        'title': 'Nueva solicitud ARCO — Seleccionar migrante',
    })


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
    arco_notifications = Notification.objects.filter(
        recipient=user, is_read=False, message__icontains='ARCO',
    ).order_by('-created_at')
    return render(request, 'registros/arco_list.html', {
        'requests': qs,
        'arco_notifications': arco_notifications,
        'title': 'Solicitudes ARCO',
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

        # For Rectificación: store field + new value directly on the ArcoRequest
        if arco.arco_type == ArcoRequest.ARCO_RECTIFICATION:
            arco.rectif_field = form.cleaned_data.get('rectif_field', '')
            arco.rectif_value = form.cleaned_data.get('rectif_value', '')

        # ARCO requests do NOT create workflow entries — they have their own independent flow.
        # Coordinador/Admin can execute directly; Operativo creates and Coordinador executes.
        arco.save()

        # Create ARCO-specific ticket (NOT a generic Ticket)
        ArcoTicket.objects.create(arco_request=arco, created_by=request.user)

        # Audit log — for Rectificación include the specific field requested
        if arco.arco_type == ArcoRequest.ARCO_RECTIFICATION:
            rectif_detail = (
                f'{arco.case_id} Rectificación — campo: {arco.rectif_field} '
                f'→ "{arco.rectif_value}" | Registro #{registration.pk}'
            )
        else:
            rectif_detail = f'{arco.case_id} {arco.get_arco_type_display()} para Registro #{registration.pk}'

        _log(request.user, 'arco_request_created', rectif_detail, request=request)
        _reg_event(registration, RegistrationEvent.EVENT_ARCO_CREATED, request.user,
                   details=f'{arco.case_id} — {arco.get_arco_type_display()}'
                           + (f' | {arco.rectif_field} → "{arco.rectif_value}"'
                              if arco.arco_type == ArcoRequest.ARCO_RECTIFICATION else ''),
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

    # Transition to in_review when a Coordinator/Admin opens the case
    if user.access_level <= 2 and arco.state == ArcoRequest.STATE_SUBMITTED:
        arco.state = ArcoRequest.STATE_IN_REVIEW
        arco.reviewed_by = user
        arco.reviewed_at = timezone.now()
        arco.save(update_fields=['state', 'reviewed_by', 'reviewed_at'])
        _reg_event(arco.registration, RegistrationEvent.EVENT_ARCO_REVIEWED, user,
                   details=f'{arco.case_id} ({arco.get_arco_type_display()}) marcado en revisión',
                   request=request)

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

    if not cert_file or not key_file:
        messages.error(request, 'Debes subir tu certificado digital (.cert) y tu llave privada (.key) para ejecutar.')
        return redirect('registros:arco_detail', pk=pk)

    try:
        cert_bytes = cert_file.read()
        key_bytes = key_file.read()
    except Exception:
        cert_bytes, key_bytes = b'', b''
    if not validate_cert_and_key(request.user, cert_bytes, key_bytes):
        messages.error(request, 'Certificado o llave inválidos. Usa los archivos .cert y .key originales.')
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
        # Apply the field change stored directly on the ArcoRequest
        rectif_field = (arco.rectif_field or '').strip()
        rectif_value = (arco.rectif_value or '').strip()
        reg = arco.registration
        if rectif_field and hasattr(reg, rectif_field):
            import datetime
            if rectif_field == 'birth_date' and isinstance(rectif_value, str):
                try:
                    rectif_value = datetime.date.fromisoformat(rectif_value)
                except (ValueError, TypeError):
                    rectif_value = None
            if rectif_value is not None and rectif_value != '':
                old_val = getattr(reg, rectif_field, None)
                setattr(reg, rectif_field, rectif_value)
                reg.save(update_fields=[rectif_field])
                # Specific audit entry for the field mutation (outer _reg_event covers closure)
                _log(request.user, 'arco_rectification_applied',
                     f'{arco.case_id} — campo "{rectif_field}": "{old_val}" → "{rectif_value}" | '
                     f'Registro #{reg.pk}',
                     request=request)

    elif arco.arco_type == ArcoRequest.ARCO_CANCELLATION:
        # Cambio 4: mark as ARCO-cancelled (not soft-deleted) so only internal_id remains visible
        arco.registration.mark_arco_cancelled('cancellation', request.user)

    elif arco.arco_type == ArcoRequest.ARCO_OPPOSITION:
        # Cambio 4: opposition also removes PII access — mark as ARCO-cancelled
        arco.registration.mark_arco_cancelled('opposition', request.user)

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
        workflow_request=None,
        message=(
            f'Tu solicitud ARCO {arco.case_id} '
            f'({arco.get_arco_type_display()}) fue ejecutada.'
            + (f' Notas: {notes}' if notes else '')
        ),
    )

    _rectif_suffix = ''
    if arco.arco_type == ArcoRequest.ARCO_RECTIFICATION and arco.rectif_field:
        _rectif_suffix = f' | campo: {arco.rectif_field} → "{arco.rectif_value}"'

    _log(request.user, 'arco_request_executed',
         f'{arco.case_id} {arco.get_arco_type_display()}{_rectif_suffix} | '
         f'firma: {action_sig.message_hash[:16]}…',
         request=request)
    _reg_event(arco.registration, RegistrationEvent.EVENT_ARCO_EXECUTED, request.user,
               details=(f'{arco.case_id} — {arco.get_arco_type_display()}{_rectif_suffix} | '
                        f'firma: {action_sig.message_hash[:16]}…'),
               request=request)
    if arco.arco_type == ArcoRequest.ARCO_ACCESS:
        _reg_event(arco.registration, RegistrationEvent.EVENT_EXPORT, request.user,
                   details=f'PDF de Acceso generado: {arco.case_id}', request=request)

    messages.success(request, f'Solicitud ARCO {arco.case_id} ejecutada y firmada.')
    return redirect('registros:arco_detail', pk=pk)


@login_required(login_url='iam:login')
@onboarding_required
@require_level(1)
def arco_cancelled_list(request):
    """
    Admin-only: list of registrations cancelled by ARCO Cancelación or Oposición.

    Per LFPDPPP (derecho al olvido): PII is suppressed — only internal_id,
    reason, date, and executor are shown. Search is restricted to internal_id.
    """
    qs = MigrantRegistration.objects.filter(
        arco_cancelled_at__isnull=False,
    ).select_related('arco_cancelled_by').order_by('-arco_cancelled_at')

    q = request.GET.get('q', '').strip()
    if q:
        qs = qs.filter(internal_id__icontains=q)

    return render(request, 'registros/arco_cancelled_list.html', {
        'registrations': qs,
        'q': q,
        'title': 'Registros cancelados por ARCO',
    })


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
# EXPEDIENTE — consolidated per-registration timeline (ARCO compliance)
# ══════════════════════════════════════════════════════════════════════════════

@login_required(login_url='iam:login')
@onboarding_required
@require_level(2)
def registro_expediente(request, pk):
    """
    Full audit timeline for one MigrantRegistration.
    Satisfies LFPDPPP Requisito 4 & 5: trazabilidad + bitácora de actividades.
    Level 1–2 only — Operativo has no business need for the full history.
    """
    registration = get_object_or_404(MigrantRegistration, pk=pk)
    events = registration.events.select_related('actor').order_by('created_at')
    arcos = registration.arco_requests.select_related('requested_by', 'executed_by').order_by('created_at')
    workflow_requests = registration.workflow_requests.select_related(
        'requested_by'
    ).prefetch_related('approval_steps__actor').order_by('created_at')

    return render(request, 'registros/expediente.html', {
        'registration': registration,
        'events': events,
        'arcos': arcos,
        'workflow_requests': workflow_requests,
        'title': f'Expediente — {registration.full_name}',
    })


@login_required(login_url='iam:login')
@onboarding_required
@require_level(1)
def registro_deleted_list(request):
    """
    Admin-only: list of soft-deleted (cancelled) registrations.
    Required for ARCO Cancelación compliance verification — the audit evidence
    must remain accessible even after the beneficiary's data is suppressed.
    """
    qs = MigrantRegistration.objects.filter(is_deleted=True).select_related(
        'deleted_by', 'created_by'
    ).order_by('-deleted_at')
    return render(request, 'registros/registro_eliminados.html', {
        'registrations': qs,
        'title': 'Registros cancelados (ARCO)',
    })


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
            registration__internal_id__icontains=q
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


# ══════════════════════════════════════════════════════════════════════════════
# ARCO TICKET VIEWS  (separate from generic Tickets — ARCO-only authorization)
# ══════════════════════════════════════════════════════════════════════════════

@login_required(login_url='iam:login')
@onboarding_required
@require_level(2)
def arco_ticket_list(request):
    """List ARCO tickets. COORDINADOR sees submitted + own; ADMIN sees all."""
    user = request.user
    if user.access_level == 1:
        qs = ArcoTicket.objects.all()
    else:
        from django.db.models import Q
        qs = ArcoTicket.objects.filter(
            Q(created_by=user) | Q(state=ArcoTicket.STATE_SUBMITTED)
        )
    qs = qs.select_related('arco_request__registration', 'created_by').order_by('-created_at')
    return render(request, 'registros/arco_ticket_list.html', {
        'tickets': qs,
        'title': 'Tickets ARCO',
    })


@login_required(login_url='iam:login')
@onboarding_required
@require_level(2)
def arco_ticket_detail(request, ticket_id):
    """Detail view for a single ARCO ticket."""
    ticket = get_object_or_404(ArcoTicket, ticket_id=ticket_id)
    user = request.user
    can_review = ticket.can_review(user) and ticket.state == ArcoTicket.STATE_SUBMITTED
    can_approve = ticket.can_approve(user) and ticket.state == ArcoTicket.STATE_ESCALATED
    can_execute = ticket.can_approve(user) and ticket.state == ArcoTicket.STATE_ADMIN_APPROVAL
    return render(request, 'registros/arco_ticket_detail.html', {
        'ticket': ticket,
        'arco': ticket.arco_request,
        'can_review': can_review,
        'can_approve': can_approve,
        'can_execute': can_execute,
    })


@login_required(login_url='iam:login')
@onboarding_required
@require_POST
@require_level(2)
def arco_ticket_escalate(request, ticket_id):
    """Coordinator reviews and escalates an ARCO ticket to Admin."""
    user = request.user
    ticket = get_object_or_404(ArcoTicket, ticket_id=ticket_id)

    if ticket.state != ArcoTicket.STATE_SUBMITTED:
        messages.error(request, 'El ticket no está en estado para revisar.')
        return redirect('registros:arco_ticket_detail', ticket_id=ticket_id)

    cert_file = request.FILES.get('cert_file')
    key_file = request.FILES.get('key_file')
    notes = request.POST.get('notes', '')

    if not cert_file or not key_file:
        messages.error(request, 'Debes subir tu certificado y llave privada.')
        return redirect('registros:arco_ticket_detail', ticket_id=ticket_id)

    cert_bytes = cert_file.read()
    key_bytes = key_file.read()

    if not validate_cert_and_key(user, cert_bytes, key_bytes):
        messages.error(request, 'Certificado o llave inválidos.')
        return redirect('registros:arco_ticket_detail', ticket_id=ticket_id)

    from .services import sign_action as _sign_action
    sig = _sign_action(
        subject_type='arco_request',
        subject_id=ticket.arco_request.pk,
        extra={'action': 'coordinator_escalate', 'ticket_id': ticket_id},
        signer=user,
    )

    try:
        ticket.mark_coordinator_reviewed(user, notes=notes, signature=sig)
    except PermissionError as exc:
        messages.error(request, str(exc))
        return redirect('registros:arco_ticket_detail', ticket_id=ticket_id)

    _log(user, 'arco_ticket_escalate', f'ArcoTicket:{ticket_id}', request=request)
    messages.success(request, f'Ticket {ticket_id} escalado a Administración.')
    return redirect('registros:arco_ticket_detail', ticket_id=ticket_id)


@login_required(login_url='iam:login')
@onboarding_required
@require_POST
@require_level(1)
def arco_ticket_approve_and_execute(request, ticket_id):
    """Admin approves, signs, and executes an ARCO ticket."""
    user = request.user
    ticket = get_object_or_404(ArcoTicket, ticket_id=ticket_id)

    if ticket.state != ArcoTicket.STATE_ESCALATED:
        messages.error(request, 'El ticket no está listo para aprobación admin.')
        return redirect('registros:arco_ticket_detail', ticket_id=ticket_id)

    cert_file = request.FILES.get('cert_file')
    key_file = request.FILES.get('key_file')
    notes = request.POST.get('notes', '')

    if not cert_file or not key_file:
        messages.error(request, 'Debes subir tu certificado y llave privada.')
        return redirect('registros:arco_ticket_detail', ticket_id=ticket_id)

    cert_bytes = cert_file.read()
    key_bytes = key_file.read()

    if not validate_cert_and_key(user, cert_bytes, key_bytes):
        messages.error(request, 'Certificado o llave inválidos.')
        return redirect('registros:arco_ticket_detail', ticket_id=ticket_id)

    from .services import sign_action as _sign_action
    sig = _sign_action(
        subject_type='arco_request',
        subject_id=ticket.arco_request.pk,
        extra={'action': 'admin_approve_execute', 'ticket_id': ticket_id},
        signer=user,
    )

    try:
        ticket.mark_admin_approved(user, notes=notes, signature=sig)
        ticket.mark_executed()
    except PermissionError as exc:
        messages.error(request, str(exc))
        return redirect('registros:arco_ticket_detail', ticket_id=ticket_id)

    # Mark underlying ArcoRequest as executed too
    arco = ticket.arco_request
    arco.state = ArcoRequest.STATE_EXECUTED
    arco.executed_by = user
    arco.executed_at = timezone.now()
    arco.action_signature = sig
    arco.save(update_fields=['state', 'executed_by', 'executed_at', 'action_signature'])

    _log(user, 'arco_ticket_executed', f'ArcoTicket:{ticket_id} | caso:{arco.case_id}', request=request)
    messages.success(request, f'Ticket ARCO {ticket_id} ejecutado y firmado.')
    return redirect('registros:arco_ticket_detail', ticket_id=ticket_id)


@login_required(login_url='iam:login')
@onboarding_required
@require_POST
@require_level(2)
def arco_ticket_reject(request, ticket_id):
    """Reject an ARCO ticket."""
    ticket = get_object_or_404(ArcoTicket, ticket_id=ticket_id)
    reason = request.POST.get('reason', 'Sin especificar')
    ticket.mark_rejected(reason)
    _log(request.user, 'arco_ticket_rejected', f'ArcoTicket:{ticket_id} | motivo:{reason}', request=request)
    messages.info(request, f'Ticket ARCO {ticket_id} rechazado.')
    return redirect('registros:arco_ticket_list')
