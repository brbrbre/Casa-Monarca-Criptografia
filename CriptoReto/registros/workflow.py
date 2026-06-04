"""
Workflow state machine and escalation engine.

Design principles:
  • Permissions are NOT hardcoded — they derive from ESCALATION_RULES.
  • Each (action_type, requester_level) pair maps to an ordered list of approver
    levels.  The first entry is the immediate next approver; the list shrinks as
    each level approves, until the last entry executes the action.
  • ApprovalStep records are immutable audit entries with a hash chain.
  • Transitions validate the actor's role before mutating state.
"""

from django.db import transaction
from django.utils import timezone

from iam.models import AuditLog

# ── Escalation rules ─────────────────────────────────────────────────────────
#
# Format:
#   (action_type, requester_access_level) → [level_1_approver, ..., level_n_executor]
#
# The LAST entry in the list is the level that actually EXECUTES the action.
# All prior entries are intermediate approvers (approve/reject, not execute).
#
# access_level semantics:
#   1 = Administrador
#   2 = Coordinador
#   3 = Operativo
#   4 = Voluntario / Externo

ESCALATION_RULES: dict[tuple, list[int]] = {
    # ── UPDATE registration ──────────────────────────────────────────────────
    # Voluntario requests update → Operativo approves → Coordinador executes
    ('update_registration', 4): [3, 2],
    # Operativo requests update → Coordinador executes directly
    ('update_registration', 3): [2],
    # Coordinador requests update → they execute it themselves (no workflow needed,
    # but if submitted, Admin can review)
    ('update_registration', 2): [1],

    # ── DELETE registration ──────────────────────────────────────────────────
    ('delete_registration', 4): [3, 2, 1],
    ('delete_registration', 3): [2, 1],
    ('delete_registration', 2): [1],

    # ── ARCO — Acceso (read request) ─────────────────────────────────────────
    # Voluntario (4) cannot create ARCO cases — rule removed.
    # Operativo (3) creates; Coordinador (2) executes.
    ('arco_access', 3): [2],

    # ── ARCO — Rectificación (update data) ───────────────────────────────────
    ('arco_rectification', 3): [2],

    # ── ARCO — Cancelación (delete data — Admin only) ────────────────────────
    ('arco_cancellation', 3): [2, 1],
    ('arco_cancellation', 2): [1],

    # ── CREACIÓN DE REGISTRO ─────────────────────────────────────────────────
    # Chain meaning: all entries before the last REVIEW (approve/reject without executing);
    # the LAST entry EXECUTES the action (sign + perform the DB mutation).
    # Voluntario (4) → Operativo (3) revisa → Coordinador (2) ejecuta
    ('create_registration', 4): [3, 2],
    # Operativo (3) → Coordinador (2) ejecuta
    ('create_registration', 3): [2],

    # ── ARCO — Oposición ─────────────────────────────────────────────────────
    # Voluntario (4) cannot create ARCO cases — rule removed.
    ('arco_opposition', 3): [2],
}


def get_approval_chain(action_type: str, requester_level: int) -> list[int]:
    """
    Return the ordered list of approver/executor levels for the given
    (action, requester_level) pair.

    Returns [] if the user already has sufficient permissions (no workflow needed).
    """
    return list(ESCALATION_RULES.get((action_type, requester_level), []))


def can_act_directly(action_type: str, user_level: int) -> bool:
    """
    Return True when the user's level is high enough to execute the action
    without creating a WorkflowRequest.
    """
    direct_map = {
        'update_registration': 2,  # Coordinador and above
        'delete_registration': 1,  # Admin only
        'create_registration': 2,  # Coordinador and above
        'arco_access': 3,
        'arco_rectification': 2,
        'arco_cancellation': 1,
        'arco_opposition': 2,
    }
    threshold = direct_map.get(action_type, 1)
    return user_level <= threshold


# ── WorkflowRequest factory ───────────────────────────────────────────────────

def create_workflow_request(action_type: str, requester, registration=None,
                             payload: dict = None, notes: str = '') -> 'WorkflowRequest':
    """
    Create and persist a new WorkflowRequest with the correct routing.

    Raises ValueError if the requester already has direct permission (no workflow needed).
    """
    from .models import WorkflowRequest

    if can_act_directly(action_type, requester.access_level):
        raise ValueError(
            f'El usuario de nivel {requester.access_level} puede ejecutar '
            f'"{action_type}" directamente sin solicitud de flujo.'
        )

    chain = get_approval_chain(action_type, requester.access_level)
    if not chain:
        raise ValueError(
            f'No se encontró una regla de escalada para ({action_type}, {requester.access_level}).'
        )

    wf = WorkflowRequest.objects.create(
        action_type=action_type,
        state=WorkflowRequest.STATE_SUBMITTED,
        requested_by=requester,
        requested_by_role=requester.access_level,
        registration=registration,
        payload=payload or {},
        notes=notes,
        current_approver_level=chain[0],
        pending_levels=chain,
    )

    AuditLog.objects.create(
        actor=requester,
        action='workflow_request_created',
        details=f'[Nivel {requester.access_level}] WF#{wf.pk} {action_type} '
                f'para Registro #{registration.pk if registration else "—"} | '
                f'Cadena: {chain}',
    )
    return wf


# ── Transition: approve ───────────────────────────────────────────────────────

@transaction.atomic
def approve_request(wf, actor, notes: str = '') -> bool:
    """
    Actor approves the current step.

    If more levels remain, the request is ESCALATED to the next level.
    If no more intermediate approvers remain, the request is set to APPROVED
    (ready for execution by the last level in the chain).

    Returns True on success, False if actor is not authorised.
    """
    from .models import WorkflowRequest, ApprovalStep

    if not wf.is_pending_for(actor):
        return False

    # Pop the current level
    remaining = list(wf.pending_levels)
    remaining.pop(0)  # remove the level that just approved

    # Compute hash chain
    prev = ApprovalStep.objects.filter(request=wf).order_by('-created_at').first()
    prev_hash = prev.step_hash if prev else ''

    step = ApprovalStep(
        request=wf,
        action=ApprovalStep.ACTION_APPROVED,
        actor=actor,
        actor_role=actor.access_level,
        notes=notes,
        prev_step_hash=prev_hash,
        created_at=timezone.now(),
    )
    step.step_hash = step.compute_hash()
    step.save()

    if remaining:
        # More approvers in the chain — escalate
        wf.pending_levels = remaining
        wf.current_approver_level = remaining[0]
        wf.state = WorkflowRequest.STATE_ESCALATED
    else:
        # All approvers signed off — ready for execution
        wf.pending_levels = []
        wf.current_approver_level = 0
        wf.state = WorkflowRequest.STATE_APPROVED

    wf.save(update_fields=['state', 'pending_levels', 'current_approver_level', 'updated_at'])

    AuditLog.objects.create(
        actor=actor,
        action='workflow_step_approved',
        details=f'[Nivel {actor.access_level}] WF#{wf.pk} aprobado. '
                f'Estado: {wf.state}. Pendiente: {wf.pending_levels}',
    )
    return True


# ── Transition: reject ────────────────────────────────────────────────────────

@transaction.atomic
def reject_request(wf, actor, notes: str = '') -> bool:
    """
    Actor rejects the request.  Terminal state — no further action possible.
    Returns True on success, False if actor is not authorised.
    """
    from .models import WorkflowRequest, ApprovalStep

    if not wf.is_pending_for(actor):
        return False

    prev = ApprovalStep.objects.filter(request=wf).order_by('-created_at').first()
    prev_hash = prev.step_hash if prev else ''

    step = ApprovalStep(
        request=wf,
        action=ApprovalStep.ACTION_REJECTED,
        actor=actor,
        actor_role=actor.access_level,
        notes=notes,
        prev_step_hash=prev_hash,
        created_at=timezone.now(),
    )
    step.step_hash = step.compute_hash()
    step.save()

    wf.state = WorkflowRequest.STATE_REJECTED
    wf.save(update_fields=['state', 'updated_at'])

    AuditLog.objects.create(
        actor=actor,
        action='workflow_step_rejected',
        details=f'[Nivel {actor.access_level}] WF#{wf.pk} rechazado.',
    )
    _notify(
        wf.requested_by,
        wf,
        f'Tu solicitud #{wf.pk} ({wf.get_action_type_display()}) fue rechazada.'
        + (f' Notas: {notes}' if notes else ''),
    )
    return True


# ── Transition: execute (sign + execute) ──────────────────────────────────────

@transaction.atomic
def execute_request(wf, actor, password_verified: bool = False, notes: str = '') -> bool:
    """
    Execute an APPROVED request — perform the actual action and sign it.

    password_verified must be True (caller is responsible for check_password).
    Returns True on success.
    """
    from .models import WorkflowRequest, ApprovalStep
    from .services import sign_action

    if wf.state != WorkflowRequest.STATE_APPROVED:
        return False
    if not can_act_directly(wf.action_type, actor.access_level):
        return False
    if not password_verified:
        return False

    # Sign the execution
    action_sig = sign_action(
        subject_type='workflow_step',
        subject_id=wf.pk,
        extra={
            'action_type': wf.action_type,
            'registration_id': wf.registration_id or 0,
            'actor_id': actor.pk,
            'actor_role': actor.access_level,
            'executed_at': timezone.now().isoformat(),
        },
        signer=actor,
    )

    # Record final step
    prev = ApprovalStep.objects.filter(request=wf).order_by('-created_at').first()
    prev_hash = prev.step_hash if prev else ''
    step = ApprovalStep(
        request=wf,
        action=ApprovalStep.ACTION_APPROVED,
        actor=actor,
        actor_role=actor.access_level,
        notes=f'[EJECUTADO] {notes}',
        prev_step_hash=prev_hash,
        created_at=timezone.now(),
    )
    step.step_hash = step.compute_hash()
    step.save()

    wf.action_signature = action_sig
    wf.state = WorkflowRequest.STATE_EXECUTED
    wf.save(update_fields=['state', 'action_signature', 'updated_at'])

    _perform_action(wf, actor)

    AuditLog.objects.create(
        actor=actor,
        action='workflow_request_executed',
        details=f'[Nivel {actor.access_level}] WF#{wf.pk} ejecutado. '
                f'Firma: {action_sig.message_hash[:16]}…',
    )
    _ARCO_TYPES = {'arco_access', 'arco_rectification', 'arco_cancellation', 'arco_opposition'}
    if wf.action_type not in _ARCO_TYPES:
        _notify(
            wf.requested_by,
            wf,
            f'Tu solicitud #{wf.pk} ({wf.get_action_type_display()}) fue aprobada y ejecutada.',
        )
    return True


def _perform_action(wf, actor):
    """Dispatch the actual DB mutation for the approved workflow request."""
    if wf.action_type == 'update_registration' and wf.registration:
        import datetime
        from django.db.models import DateField
        reg = wf.registration
        payload = wf.payload or {}
        date_field_names = {
            f.name for f in reg._meta.get_fields() if isinstance(f, DateField)
        }
        for field, value in payload.items():
            if not hasattr(reg, field):
                continue
            if field in date_field_names and isinstance(value, str):
                try:
                    value = datetime.date.fromisoformat(value)
                except (ValueError, TypeError):
                    continue
            setattr(reg, field, value)
        reg.save()

        # Re-sign after update so the stored signature remains valid
        from .services import sign_registration
        from .models import MigrantRegistrationSignature
        sig_data = sign_registration(reg)
        updated = MigrantRegistrationSignature.objects.filter(registration=reg).update(
            message_hash=sig_data['message_hash'],
            signature_r=sig_data['signature_r'],
            signature_s=sig_data['signature_s'],
            public_key=sig_data['public_key'],
            curve_name=sig_data['curve_name'],
            signed_by=actor,
            signed_by_role=actor.access_level,
            signed_at=timezone.now(),
        )
        if not updated:
            MigrantRegistrationSignature.objects.create(
                registration=reg,
                signed_by=actor,
                signed_by_role=actor.access_level,
                **sig_data,
            )

    elif wf.action_type == 'create_registration':
        from .models import MigrantRegistration, Ticket, MigrantRegistrationSignature
        from .services import sign_registration

        payload = wf.payload or {}
        reg = MigrantRegistration()
        for field, value in payload.items():
            if not hasattr(reg, field):
                continue
            setattr(reg, field, value)

        reg.created_by = wf.requested_by
        reg.created_by_role = wf.requested_by_role
        if hasattr(reg, 'privacy_accepted_at') and isinstance(payload.get('privacy_accepted_at'), str):
            try:
                from datetime import datetime
                reg.privacy_accepted_at = datetime.fromisoformat(payload['privacy_accepted_at'])
            except ValueError:
                reg.privacy_accepted_at = timezone.now()
        reg.privacy_accepted_ip = payload.get('privacy_accepted_ip')
        reg.privacy_notice_version = payload.get('privacy_notice_version')
        reg.save()

        try:
            existing_ticket = wf.ticket
            existing_ticket.registration = reg
            existing_ticket.status = Ticket.STATUS_EN_PROCESO
            existing_ticket.save(update_fields=['registration', 'status', 'updated_at'])
        except Ticket.DoesNotExist:
            Ticket.create_for_registration(reg, wf.requested_by)

        sig_data = sign_registration(reg)
        MigrantRegistrationSignature.objects.create(
            registration=reg,
            signed_by=actor,
            signed_by_role=actor.access_level,
            **sig_data,
        )

    elif wf.action_type == 'delete_registration' and wf.registration:
        wf.registration.soft_delete(actor)


# ── Helpers ───────────────────────────────────────────────────────────────────

def pending_requests_for(user):
    """Return all WorkflowRequests currently waiting on the user's level."""
    from .models import WorkflowRequest
    return WorkflowRequest.objects.filter(
        state__in=[
            WorkflowRequest.STATE_SUBMITTED,
            WorkflowRequest.STATE_PENDING_REVIEW,
            WorkflowRequest.STATE_ESCALATED,
        ],
        current_approver_level=user.access_level,
    ).select_related('requested_by', 'registration')


def _notify(recipient, wf, message: str):
    """Create an in-app Notification for the recipient."""
    from .models import Notification
    Notification.objects.create(
        recipient=recipient,
        workflow_request=wf,
        message=message,
    )
