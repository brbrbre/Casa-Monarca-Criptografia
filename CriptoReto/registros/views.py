import json
from functools import wraps

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views.decorators.http import require_POST

from iam.models import AuditLog
from iam.views import onboarding_required
from .forms import ArcoRequestForm, MigrantRegistrationForm, WorkflowApprovalForm
from .models import (
    ArcoRequest, MigrantRegistration, MigrantRegistrationSignature,
    WorkflowRequest, PRIVACY_NOTICE_VERSION,
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

    qs = qs.select_related('requested_by', 'registration').order_by('-created_at')
    pending = pending_requests_for(user)
    return render(request, 'registros/workflow_list.html', {
        'requests': qs,
        'pending': pending,
        'title': 'Solicitudes de Flujo de Trabajo',
    })


@login_required(login_url='iam:login')
@onboarding_required
@require_level(3)
def workflow_detail(request, pk):
    wf = get_object_or_404(WorkflowRequest, pk=pk)
    steps = wf.approval_steps.select_related('actor').order_by('created_at')
    form = WorkflowApprovalForm() if wf.is_pending_for(request.user) else None
    return render(request, 'registros/workflow_detail.html', {
        'wf': wf, 'steps': steps, 'form': form,
        'can_act': wf.is_pending_for(request.user),
        'title': f'Solicitud #{wf.pk}',
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

    if request.method == 'GET':
        form = WorkflowApprovalForm()
        return render(request, 'registros/workflow_decide.html', {'wf': wf, 'form': form})

    form = WorkflowApprovalForm(request.POST)
    if not form.is_valid():
        return render(request, 'registros/workflow_decide.html', {'wf': wf, 'form': form})

    if not request.user.check_password(form.cleaned_data['password']):
        form.add_error('password', 'Contraseña incorrecta.')
        return render(request, 'registros/workflow_decide.html', {'wf': wf, 'form': form})

    decision = form.cleaned_data['decision']
    notes = form.cleaned_data.get('notes', '')

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

    # If the user CAN do it directly, redirect to the direct view
    if can_act_directly(action, request.user.access_level):
        if action == 'update_registration':
            return redirect('registros:registro_edit', pk=pk)
        if action == 'delete_registration':
            return redirect('registros:registro_detail', pk=pk)

    if request.method == 'POST':
        notes = request.POST.get('notes', '')
        payload = {}

        try:
            wf = create_workflow_request(
                action_type=action,
                requester=request.user,
                registration=registration,
                payload=payload,
                notes=notes,
            )
            messages.success(request,
                             f'Solicitud #{wf.pk} creada. Será revisada por el nivel correspondiente.')
            return redirect('registros:workflow_detail', pk=wf.pk)
        except ValueError as exc:
            messages.error(request, str(exc))

    action_labels = dict(WorkflowRequest.ACTION_CHOICES)
    return render(request, 'registros/workflow_request_create.html', {
        'registration': registration,
        'action': action,
        'action_label': action_labels.get(action, action),
        'title': 'Crear Solicitud',
    })


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

@login_required(login_url='iam:login')
@onboarding_required
@require_level(3)
def arco_list(request):
    user = request.user
    if user.access_level == 1:
        qs = ArcoRequest.objects.all()
    elif user.access_level == 2:
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
    form = ArcoRequestForm(request.POST or None)

    if request.method == 'POST' and form.is_valid():
        arco = form.save(commit=False)
        arco.registration = registration
        arco.requested_by = request.user
        arco.state = ArcoRequest.STATE_SUBMITTED

        # Compute legal deadline (20 business days ≈ 28 calendar days — simplified)
        from datetime import timedelta
        arco.legal_deadline = (timezone.now() + timedelta(days=28)).date()

        # Create matching WorkflowRequest
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

        _log(request.user, 'arco_request_created',
             f'ARCO#{arco.pk} {arco.get_arco_type_display()} para Registro #{registration.pk}',
             request=request)

        messages.success(request, f'Solicitud ARCO #{arco.pk} registrada.')
        return redirect('registros:arco_list')

    return render(request, 'registros/arco_form.html', {
        'form': form,
        'registration': registration,
        'title': f'Solicitud ARCO — Registro #{registration.pk}',
    })


@login_required(login_url='iam:login')
@onboarding_required
@require_level(2)
@require_POST
def arco_execute(request, pk):
    """Coordinador/Admin executes (fulfils) an approved ARCO request."""
    arco = get_object_or_404(ArcoRequest, pk=pk)

    if not arco.can_execute(request.user):
        messages.error(request, 'No tienes autorización para ejecutar esta solicitud ARCO.')
        return redirect('registros:arco_list')

    if not request.user.check_password(request.POST.get('password', '')):
        messages.error(request, 'Contraseña incorrecta.')
        return redirect('registros:arco_list')

    notes = request.POST.get('notes', '')
    arco.state = ArcoRequest.STATE_EXECUTED
    arco.executed_by = request.user
    arco.executed_at = timezone.now()
    arco.execution_notes = notes
    arco.save(update_fields=['state', 'executed_by', 'executed_at', 'execution_notes'])

    _log(request.user, 'arco_request_executed',
         f'ARCO#{arco.pk} {arco.get_arco_type_display()} ejecutado.', request=request)

    messages.success(request, f'Solicitud ARCO #{arco.pk} marcada como ejecutada.')
    return redirect('registros:arco_list')
