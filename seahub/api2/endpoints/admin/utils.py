from seahub.base.models import UserLastLogin
from seahub.profile.models import Profile, DetailedProfile
from seahub.two_factor.models import default_device
from seahub.options.models import UserOptions
from seahub.constants import DEFAULT_ADMIN
from seahub.role_permissions.models import AdminRole
from seahub.utils import is_pro_version
from django.template.defaultfilters import filesizeformat
from seaserv import ccnet_api, seafile_api

from seahub.base.accounts import User
from seahub.base.templatetags.seahub_tags import email2nickname, email2contact_email
from seahub.group.utils import group_id_to_name
from seahub.utils.repo import normalize_repo_status_code
from seahub.utils.timeutils import timestamp_to_isoformat_timestr

from seahub.api2.endpoints.group_owned_libraries import get_group_id_by_repo_owner


def get_user_info(email):

    user = User.objects.get(email=email)
    d_profile = DetailedProfile.objects.get_detailed_profile_by_user(email)
    profile = Profile.objects.get_profile_by_user(email)

    info = {}
    info['email'] = email
    info['name'] = email2nickname(email)
    info['contact_email'] = profile.contact_email if profile and profile.contact_email else ''
    info['login_id'] = profile.login_id if profile and profile.login_id else ''

    info['is_staff'] = user.is_staff
    info['is_active'] = user.is_active
    info['create_time'] = user.ctime
    info['reference_id'] = user.reference_id if user.reference_id else ''

    info['department'] = d_profile.department if d_profile else ''

    info['quota_total'] = seafile_api.get_user_quota(email)
    info['quota_usage'] = seafile_api.get_user_self_usage(email)

    info['create_time'] = timestamp_to_isoformat_timestr(user.ctime)
    info['last_login'] = UserLastLogin.objects.get_by_username(email).last_login if UserLastLogin.objects.get_by_username(email) else ''

    info['has_default_device'] = True if default_device(user) else False
    info['is_force_2fa'] = UserOptions.objects.is_force_2fa(email)

    if user.is_staff:
        try:
            admin_role = AdminRole.objects.get_admin_role(user.email)
            info['admin_role'] = admin_role.role
        except AdminRole.DoesNotExist:
            info['admin_role'] = DEFAULT_ADMIN

    if is_pro_version():
        info['role'] = user.role

    return info


def get_repo_info(repo):

    repo_owner = seafile_api.get_repo_owner(repo.repo_id)
    if not repo_owner:
        try:
            org_repo_owner = seafile_api.get_org_repo_owner(repo.repo_id)
        except Exception:
            org_repo_owner = None

    owner = repo_owner or org_repo_owner or ''

    result = {}
    result['id'] = repo.repo_id
    result['name'] = repo.repo_name
    result['owner'] = owner
    result['owner_email'] = owner
    result['owner_name'] = email2nickname(owner)
    result['owner_contact_email'] = email2contact_email(owner)
    result['size'] = repo.size
    result['size_formatted'] = filesizeformat(repo.size)
    result['encrypted'] = repo.encrypted
    result['file_count'] = repo.file_count
    result['status'] = normalize_repo_status_code(repo.status)
    result['last_modify'] = timestamp_to_isoformat_timestr(repo.last_modify)

    if '@seafile_group' in owner:
        group_id = get_group_id_by_repo_owner(owner)
        result['group_name'] = group_id_to_name(group_id)

    return result