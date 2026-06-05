def workflow_context(request):
    if not request.user.is_authenticated:
        return {}

    from registros.models import Notification
    from registros.workflow import pending_requests_for

    u = request.user
    st = u.onboarding_status
    cd = u.certificate_delivered_at
    nav_unlocked = (
        u.is_system_admin()
        or (st == 'approved' and bool(cd) and u.access_level != 2)
        or (st == 'approved' and bool(cd) and bool(request.session.get('cert_validated')))
    )

    all_unread = Notification.objects.filter(recipient=u, is_read=False)
    arco_unread = all_unread.filter(message__icontains='ARCO')
    non_arco_unread = all_unread.exclude(message__icontains='ARCO')

    # pending_requests_for already excludes ARCO action types
    return {
        'pending_workflow_count': pending_requests_for(u).count(),
        'unread_notifications_count': non_arco_unread.count(),
        'unread_arco_notifications_count': arco_unread.count(),
        'nav_unlocked': nav_unlocked,
    }
