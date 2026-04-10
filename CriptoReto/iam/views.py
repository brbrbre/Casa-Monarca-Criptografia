from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.db.models import Q
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone

from .forms import CollaboratorForm, CollaboratorSearchForm, LoginForm
from .models import AuditLog, Collaborator, LoginAttempt


def get_client_ip(request):
    forwarded = request.META.get('HTTP_X_FORWARDED_FOR')
    if forwarded:
        return forwarded.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR')


def login_view(request):
    if request.user.is_authenticated:
        return redirect('iam:dashboard')

    form = LoginForm(request.POST or None)
    blocked = False
    if request.method == 'POST' and form.is_valid():
        username = form.cleaned_data['username']
        password = form.cleaned_data['password']
        otp = form.cleaned_data.get('otp')
        blocked = LoginAttempt.is_blocked(username)
        if blocked:
            messages.error(request, 'Demasiados intentos fallidos. Intenta de nuevo más tarde.')
        else:
            user = authenticate(request, username=username, password=password)
            ip_address = get_client_ip(request)
            if user is None:
                LoginAttempt.objects.create(username=username, ip_address=ip_address, successful=False)
                messages.error(request, 'Usuario o contraseña incorrectos.')
            elif not user.is_active or user.is_deleted or user.is_revoked:
                LoginAttempt.objects.create(username=username, ip_address=ip_address, successful=False)
                messages.error(request, 'Cuenta inactiva o revocada. Contacta al administrador.')
            else:
                if user.mfa_enabled:
                    if not otp or not user.verify_totp(otp):
                        LoginAttempt.objects.create(username=username, ip_address=ip_address, successful=False)
                        messages.error(request, 'Código MFA inválido.')
                    else:
                        login(request, user)
                        LoginAttempt.objects.create(username=username, ip_address=ip_address, successful=True)
                        AuditLog.objects.create(actor=user, target=user, action='Inicio de sesión', details='Ingreso exitoso con MFA.')
                        return redirect('iam:dashboard')
                else:
                    login(request, user)
                    LoginAttempt.objects.create(username=username, ip_address=ip_address, successful=True)
                    AuditLog.objects.create(actor=user, target=user, action='Inicio de sesión', details='Ingreso exitoso.')
                    return redirect('iam:dashboard')

    return render(request, 'iam/login.html', {'form': form, 'blocked': blocked})


@login_required(login_url='iam:login')
def logout_view(request):
    AuditLog.objects.create(actor=request.user, action='Cierre de sesión', details='Usuario cerró sesión.')
    logout(request)
    messages.success(request, 'Sesión cerrada correctamente.')
    return redirect('iam:login')


@login_required(login_url='iam:login')
def dashboard_view(request):
    if request.user.access_level == 1:
        collaborators = Collaborator.objects.filter(is_deleted=False)
    else:
        collaborators = Collaborator.objects.filter(is_deleted=False, area=request.user.area)

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

    return render(request, 'iam/dashboard.html', {
        'collaborators': collaborators.select_related('area'),
        'form': form,
        'stats': {'total': total, 'active': active, 'revoked': revoked, 'deleted': expired},
    })


@login_required(login_url='iam:login')
def collaborator_detail_view(request, pk):
    collaborator = get_object_or_404(Collaborator, pk=pk)
    if not request.user.can_view(collaborator):
        messages.error(request, 'No tienes permisos para ver este colaborador.')
        return redirect('iam:dashboard')
    logs = AuditLog.objects.filter(target=collaborator)[:20]
    context = {
        'collaborator': collaborator,
        'logs': logs,
        'can_edit': request.user.can_edit(collaborator),
        'can_activate': request.user.can_activate(collaborator),
        'can_delete': request.user.can_delete(collaborator),
    }
    return render(request, 'iam/collaborator_detail.html', context)


@login_required(login_url='iam:login')
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
def collaborator_toggle_view(request, pk):
    collaborator = get_object_or_404(Collaborator, pk=pk)
    if not request.user.can_activate(collaborator):
        messages.error(request, 'No tienes permisos para cambiar el estado de este colaborador.')
        return redirect('iam:dashboard')

    if collaborator.is_deleted:
        messages.error(request, 'No se puede cambiar el estado de un colaborador eliminado.')
        return redirect('iam:detail', pk=collaborator.pk)

    if collaborator.is_active and not collaborator.is_revoked:
        collaborator.is_active = False
        collaborator.is_revoked = True
        collaborator.revoked_at = timezone.now()
        collaborator.revoked_by = request.user
        action = 'Revocación de acceso'
        messages.success(request, 'Acceso revocado correctamente.')
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
def audit_log_view(request):
    if request.user.access_level == 1:
        logs = AuditLog.objects.all()
    else:
        logs = AuditLog.objects.filter(actor__area=request.user.area) | AuditLog.objects.filter(target__area=request.user.area)
    logs = logs.select_related('actor', 'target')[:100]
    return render(request, 'iam/audit_log.html', {'logs': logs})
