from functools import wraps

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST

from iam.models import AuditLog
from iam.views import onboarding_required
from .forms import MigrantRegistrationForm
from .models import MigrantRegistration, MigrantRegistrationSignature
from .services import get_public_key_pem, sign_registration, verify_registration


# ── Permission helpers ────────────────────────────────────────────────────────

def require_level(max_level, redirect_to='registros:registro_new'):
    """Decorator: only users with access_level <= max_level may proceed."""
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped(request, *args, **kwargs):
            if request.user.access_level > max_level:
                messages.error(request, 'No tienes permisos para acceder a esta sección.')
                return redirect(redirect_to)
            return view_func(request, *args, **kwargs)
        return _wrapped
    return decorator


def _log(actor, action, details='', request=None):
    ip = None
    if request:
        forwarded = request.META.get('HTTP_X_FORWARDED_FOR')
        ip = forwarded.split(',')[0].strip() if forwarded else request.META.get('REMOTE_ADDR')
    level = getattr(actor, 'access_level', '')
    full = f'[Nivel {level}] {details}'
    if ip:
        full = f'{full} | IP: {ip}'
    AuditLog.objects.create(actor=actor, action=action, details=full.strip())


# ── Step 1 – Fill form ────────────────────────────────────────────────────────

@login_required(login_url='iam:login')
@onboarding_required
def registro_new(request):
    """Fill the migrant registration form.  All authenticated roles may access."""
    if request.method == 'POST':
        # Store raw POST lists so we can reconstruct the form in the review step
        request.session['registro_draft'] = {k: v for k, v in request.POST.lists()}
        form = MigrantRegistrationForm(request.POST)
        if form.is_valid():
            return redirect('registros:registro_review')
        # Validation failed – re-render with errors
    else:
        # Pre-fill from session draft if the user came back
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


# ── Step 2 – Review + password confirmation ───────────────────────────────────

@login_required(login_url='iam:login')
@onboarding_required
def registro_review(request):
    """Show a read-only summary, prompt for password, create + sign on confirmation."""
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
        messages.error(request, 'Los datos del formulario contienen errores. Regresa y corrígelos.')
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
        registration.save()

        # ── Sign ────────────────────────────────────────────────────────────
        sig_data = sign_registration(registration)
        MigrantRegistrationSignature.objects.create(
            registration=registration,
            signed_by=request.user,
            signed_by_role=request.user.access_level,
            **sig_data,
        )

        _log(
            request.user,
            'registro_migrante_creado_y_firmado',
            f'Registro #{registration.pk} ({registration.full_name}) — hash: {sig_data["message_hash"][:16]}…',
            request=request,
        )

        # Clear draft
        request.session.pop('registro_draft', None)
        return redirect('registros:registro_exito', pk=registration.pk)

    return render(request, 'registros/review.html', {
        'form': form,
        'review_sections': _build_review_sections(form),
        'title': 'Revisar Registro',
    })


def _build_review_sections(form):
    """Group form fields into labelled sections for the review page."""
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
        ('Observaciones y consentimiento', ['observations', 'data_consent']),
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
            # Human-readable value
            if hasattr(field, 'choices') and not isinstance(
                field.widget, (type(None),)
            ):
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


# ── Success page ──────────────────────────────────────────────────────────────

@login_required(login_url='iam:login')
@onboarding_required
def registro_exito(request, pk):
    """Post-creation success screen with signature status."""
    registration = get_object_or_404(MigrantRegistration, pk=pk, is_deleted=False)
    # Only the creator or staff may see this success page
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


# ── List ──────────────────────────────────────────────────────────────────────

@login_required(login_url='iam:login')
@onboarding_required
@require_level(3)
def registro_list(request):
    """List all registrations.  Level 1–3 only."""
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
        'registrations': qs,
        'q': q,
        'title': 'Registros Migrantes',
    })


# ── Detail ────────────────────────────────────────────────────────────────────

@login_required(login_url='iam:login')
@onboarding_required
@require_level(3)
def registro_detail(request, pk):
    """Read-only detail view.  Level 1–3 only."""
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


# ── Edit ──────────────────────────────────────────────────────────────────────

@login_required(login_url='iam:login')
@onboarding_required
@require_level(2, redirect_to='registros:registro_list')
def registro_edit(request, pk):
    """Edit a registration.  Level 1–2 only."""
    registration = get_object_or_404(MigrantRegistration, pk=pk, is_deleted=False)
    form = MigrantRegistrationForm(request.POST or None, instance=registration)

    if request.method == 'POST' and form.is_valid():
        form.save()
        _log(
            request.user,
            'registro_migrante_editado',
            f'Registro #{registration.pk} editado.',
            request=request,
        )
        messages.success(request, f'Registro #{registration.pk} actualizado correctamente.')
        return redirect('registros:registro_detail', pk=registration.pk)

    return render(request, 'registros/form.html', {
        'form': form,
        'registration': registration,
        'editing': True,
        'title': f'Editar Registro #{registration.pk}',
    })


# ── Delete (soft) ─────────────────────────────────────────────────────────────

@login_required(login_url='iam:login')
@onboarding_required
@require_POST
def registro_delete(request, pk):
    """Soft-delete.  Level 1 only."""
    if request.user.access_level != 1:
        messages.error(request, 'Solo los administradores pueden eliminar registros.')
        return redirect('registros:registro_list')

    registration = get_object_or_404(MigrantRegistration, pk=pk, is_deleted=False)
    registration.soft_delete(request.user)
    _log(
        request.user,
        'registro_migrante_eliminado',
        f'Registro #{registration.pk} ({registration.full_name}) eliminado lógicamente.',
        request=request,
    )
    messages.success(request, f'Registro #{registration.pk} eliminado.')
    return redirect('registros:registro_list')


# ── Signature verification (JSON) ─────────────────────────────────────────────

@login_required(login_url='iam:login')
@onboarding_required
def registro_verify(request, pk):
    """Return JSON with signature verification result."""
    registration = get_object_or_404(MigrantRegistration, pk=pk)
    try:
        sig = registration.signature
        result = verify_registration(registration, sig)
    except MigrantRegistrationSignature.DoesNotExist:
        result = {'is_valid': False, 'error': 'no_signature'}

    return JsonResponse(result, json_dumps_params={'default': str})


# ── Public key export ─────────────────────────────────────────────────────────

@login_required(login_url='iam:login')
@onboarding_required
def export_public_key(request):
    """Return the server's ECC public key as a plain-text download."""
    from django.http import HttpResponse
    pem = get_public_key_pem()
    response = HttpResponse(pem, content_type='application/x-pem-file')
    response['Content-Disposition'] = 'attachment; filename="casa-monarca-ecc-pubkey.pem"'
    return response
