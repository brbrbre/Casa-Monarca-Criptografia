from functools import wraps

from django.contrib import messages
from django.shortcuts import redirect


def require_cert_validation(view_func):
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        if not request.session.get('cert_validated'):
            messages.error(request, 'Certificate validation required.')
            return redirect('iam:login')
        return view_func(request, *args, **kwargs)
    return _wrapped_view


def require_access_level(max_level):
    """Allow only users whose access_level <= max_level (Level 1 = most privileged)."""
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped(request, *args, **kwargs):
            if not hasattr(request.user, 'access_level') or request.user.access_level > max_level:
                messages.error(request, 'No tienes permisos para acceder a esta sección.')
                return redirect('iam:dashboard')
            return view_func(request, *args, **kwargs)
        return _wrapped
    return decorator


def require_admin(view_func):
    """Restrict view to Level 1 (Administrador del sistema) only."""
    @wraps(view_func)
    def _wrapped(request, *args, **kwargs):
        if not hasattr(request.user, 'access_level') or request.user.access_level != 1:
            messages.error(request, 'Esta acción está reservada para administradores del sistema.')
            return redirect('iam:dashboard')
        return view_func(request, *args, **kwargs)
    return _wrapped


def require_post(view_func):
    """Reject GET requests on state-changing views to prevent CSRF via URL."""
    @wraps(view_func)
    def _wrapped(request, *args, **kwargs):
        if request.method != 'POST':
            messages.error(request, 'Solicitud no válida.')
            pk = kwargs.get('pk')
            if pk:
                return redirect('iam:detail', pk=pk)
            return redirect('iam:dashboard')
        return view_func(request, *args, **kwargs)
    return _wrapped
