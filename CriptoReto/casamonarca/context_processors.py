def workflow_context(request):
    if not request.user.is_authenticated:
        return {}

    from registros.models import Notification
    from registros.workflow import pending_requests_for

    return {
        'pending_workflow_count': pending_requests_for(request.user).count(),
        'unread_notifications_count': Notification.objects.filter(
            recipient=request.user, is_read=False,
        ).count(),
    }
