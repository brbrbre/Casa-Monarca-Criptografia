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
