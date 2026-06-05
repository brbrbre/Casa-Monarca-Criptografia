"""
Custom Django model fields for transparent AES-256-GCM encryption.

The DB stores encrypted base64url data; Python code sees plaintext.

IMPORTANT: ORM lookups (.filter(field__icontains=x)) will NOT return results
on encrypted columns — you cannot search inside encrypted data.
Use non-encrypted identifiers (internal_id, status, pk) for filtering.
"""

import logging
from datetime import date as date_type
from functools import lru_cache

from django.db import models

logger = logging.getLogger(__name__)


@lru_cache(maxsize=1)
def _get_key():
    from .encryption import get_encryption_key_from_env
    return get_encryption_key_from_env()


class EncryptedTextField(models.TextField):
    """
    TextField that transparently encrypts on DB write and decrypts on DB read.
    Underlying DB column is TEXT (stores base64url AES-256-GCM ciphertext).
    """

    def from_db_value(self, value, expression, connection):
        if not value:
            return value
        try:
            from .encryption import decrypt_field
            return decrypt_field(value, _get_key())
        except Exception:
            # Graceful fallback: return as-is for unencrypted legacy data
            return value

    def get_prep_value(self, value):
        if value is None or value == '':
            return value
        try:
            from .encryption import encrypt_field
            return encrypt_field(str(value), _get_key())
        except RuntimeError:
            logger.warning(
                'DB_ENCRYPTION_MASTER_PASSWORD not set — field stored as plaintext. '
                'Set DB_ENCRYPTION_MASTER_PASSWORD and DB_ENCRYPTION_SALT in .env.'
            )
            return value


class EncryptedDateField(models.TextField):
    """
    DateField-compatible encrypted field.
    DB stores encrypted ISO-8601 date string (TEXT column).
    Python sees datetime.date objects. Forms use DateInput correctly.
    """

    def from_db_value(self, value, expression, connection):
        if not value:
            return value
        try:
            from .encryption import decrypt_field
            decrypted = decrypt_field(value, _get_key())
            return date_type.fromisoformat(decrypted)
        except Exception:
            # Try plain ISO string for unencrypted legacy data
            try:
                return date_type.fromisoformat(str(value))
            except Exception:
                return value

    def get_prep_value(self, value):
        if value is None:
            return value
        if isinstance(value, date_type):
            value = value.isoformat()
        elif not isinstance(value, str):
            value = str(value)
        if not value:
            return value
        try:
            from .encryption import encrypt_field
            return encrypt_field(value, _get_key())
        except RuntimeError:
            logger.warning(
                'DB_ENCRYPTION_MASTER_PASSWORD not set — date stored as plaintext.'
            )
            return value

    def to_python(self, value):
        if isinstance(value, date_type) or value is None:
            return value
        if isinstance(value, str):
            try:
                return date_type.fromisoformat(value)
            except ValueError:
                return value
        return value

    def formfield(self, **kwargs):
        from django.forms import DateField
        from django.db.models.fields import Field as ModelField
        # TextField.formfield() adds max_length, which forms.DateField rejects.
        # Bypass TextField.formfield and go straight to models.Field.formfield.
        kwargs.pop('max_length', None)
        kwargs.setdefault('form_class', DateField)
        return ModelField.formfield(self, **kwargs)
