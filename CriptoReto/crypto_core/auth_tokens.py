"""
JWT para autenticación HTTP en Django.

Completamente separado de las firmas digitales.
- Un JWT responde: "¿quién eres?" (autenticación de sesión)
- Una firma digital responde: "¿autorizas esta acción crítica?" (no repudio)

Usa PyJWT para la generación/verificación de tokens.
La SECRET_KEY del token JWT debe ser independiente de SECRET_KEY de Django
y de las claves criptográficas de la CA.
"""

import os
from datetime import datetime, timezone as dt_timezone, timedelta
from functools import wraps
from typing import Optional

JWT_EXPIRY_SECONDS = int(os.environ.get('JWT_ACCESS_TOKEN_EXPIRES', 8 * 3600))
JWT_ALGORITHM = 'HS256'


def _get_jwt_secret() -> str:
    secret = os.environ.get('JWT_SECRET_KEY')
    if not secret:
        from django.conf import settings
        secret = getattr(settings, 'JWT_SECRET_KEY', None)
    if not secret:
        raise RuntimeError(
            'JWT_SECRET_KEY no está configurada. '
            'Genera una con: python -c "import secrets; print(secrets.token_hex(32))"'
        )
    return secret


def _get_jwt_library():
    try:
        import jwt as pyjwt
        return pyjwt
    except ImportError:
        raise ImportError(
            "PyJWT no está instalado. Ejecuta: pip install PyJWT"
        )


def generate_token(
    user_id: int,
    username: str,
    role: str,
    area: str,
    has_certificate: bool,
    extra_claims: dict = None,
) -> str:
    """
    Genera un JWT de sesión para el usuario.

    Args:
        user_id         — ID del usuario en la BD
        username        — nombre de usuario
        role            — 'admin', 'coordinador', 'operativo', o 'externo'
        area            — área del colaborador
        has_certificate — True si el usuario tiene un certificado X.509 activo
        extra_claims    — claims adicionales opcionales

    NOTA: El token NO contiene claves privadas ni datos del certificado.
    """
    pyjwt = _get_jwt_library()
    now = datetime.now(dt_timezone.utc)
    payload = {
        'sub': str(user_id),
        'username': username,
        'role': role,
        'area': area,
        'has_certificate': has_certificate,
        'iat': now,
        'exp': now + timedelta(seconds=JWT_EXPIRY_SECONDS),
    }
    if extra_claims:
        # Sanity check: nunca incluir claves criptográficas
        forbidden = {'private_key', 'cert_pem', 'ca_key', 'password', 'secret'}
        for k in extra_claims:
            if k.lower() in forbidden:
                raise ValueError(f"El claim '{k}' no puede incluirse en el JWT.")
        payload.update(extra_claims)

    return pyjwt.encode(payload, _get_jwt_secret(), algorithm=JWT_ALGORITHM)


def verify_token(token: str) -> dict:
    """
    Verifica y decodifica un JWT de sesión.

    Retorna el payload decodificado.

    Raises:
        jwt.ExpiredSignatureError si el token expiró
        jwt.InvalidTokenError si el token es inválido
    """
    pyjwt = _get_jwt_library()
    return pyjwt.decode(token, _get_jwt_secret(), algorithms=[JWT_ALGORITHM])


def get_token_from_request(request) -> Optional[str]:
    """Extrae el token JWT del header Authorization o de la cookie de sesión."""
    auth_header = request.META.get('HTTP_AUTHORIZATION', '')
    if auth_header.startswith('Bearer '):
        return auth_header[7:]
    return request.COOKIES.get('jwt_token')


def get_current_user_payload(request) -> Optional[dict]:
    """
    Obtiene el payload del JWT del request actual.
    Retorna None si no hay token válido.
    """
    token = get_token_from_request(request)
    if not token:
        return None
    try:
        return verify_token(token)
    except Exception:
        return None


def require_role(*roles):
    """
    Decorador para vistas Django que requieren un rol específico vía JWT.

    Uso:
        @require_role('admin', 'coordinador')
        def mi_vista(request, ...):
            ...

    Si el proyecto usa Django sessions en vez de JWT, este decorador
    puede combinarse con @login_required verificando request.user.access_level.
    """
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped(request, *args, **kwargs):
            # Soporte para Django sessions (el flujo actual del sistema)
            if hasattr(request, 'user') and request.user.is_authenticated:
                user = request.user
                # Mapeo de access_level a role string
                level_to_role = {1: 'admin', 2: 'coordinador', 3: 'operativo', 4: 'externo'}
                user_role = level_to_role.get(getattr(user, 'access_level', 4), 'externo')
                if user_role in roles:
                    return view_func(request, *args, **kwargs)
                from django.http import JsonResponse
                return JsonResponse({'error': f'Se requiere uno de los roles: {list(roles)}'}, status=403)

            # Soporte para JWT puro (API sin sesiones Django)
            payload = get_current_user_payload(request)
            if not payload:
                from django.http import JsonResponse
                return JsonResponse({'error': 'Autenticación requerida'}, status=401)
            if payload.get('role') not in roles:
                from django.http import JsonResponse
                return JsonResponse({'error': f'Se requiere uno de los roles: {list(roles)}'}, status=403)
            request.jwt_payload = payload
            return view_func(request, *args, **kwargs)
        return _wrapped
    return decorator


def require_certificate(view_func):
    """
    Decorador para vistas que requieren que el usuario tenga un certificado activo.
    Complementa require_role para flujos finales.
    """
    @wraps(view_func)
    def _wrapped(request, *args, **kwargs):
        if hasattr(request, 'user') and request.user.is_authenticated:
            try:
                cert = request.user.certificate
                if not cert.is_valid:
                    from django.http import JsonResponse
                    return JsonResponse({'error': 'Certificado inválido o revocado'}, status=403)
            except Exception:
                from django.http import JsonResponse
                return JsonResponse({'error': 'Se requiere certificado válido para esta acción'}, status=403)
        return view_func(request, *args, **kwargs)
    return _wrapped
