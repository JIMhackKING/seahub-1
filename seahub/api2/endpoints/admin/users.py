# Copyright (c) 2012-2016 Seafile Ltd.
import logging
from types import FunctionType
from constance import config


from rest_framework import status
from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAdminUser
from rest_framework.response import Response
from rest_framework.views import APIView
from django.core.cache import cache
from django.core.urlresolvers import reverse
from django.utils.translation import ugettext as _

from seaserv import seafile_api, ccnet_api

from seahub.api2.authentication import TokenAuthentication
from seahub.api2.throttling import UserRateThrottle
from seahub.api2.utils import api_error, to_python_boolean
from seahub.api2.endpoints.admin.utils import get_user_info

from seahub.settings import SEND_EMAIL_ON_ADDING_SYSTEM_MEMBER, INIT_PASSWD, \
    SEND_EMAIL_ON_RESETTING_USER_PASSWD

from seahub.base.accounts import User
from seahub.profile.models import Profile, DetailedProfile
from seahub.profile.settings import CONTACT_CACHE_TIMEOUT, CONTACT_CACHE_PREFIX
from seahub.utils import is_valid_username, is_org_context, \
        is_pro_version, normalize_cache_key, is_valid_email, \
        IS_EMAIL_CONFIGURED, send_html_email, get_site_name
from seahub.utils.file_size import get_file_size_unit
from seahub.constants import DEFAULT_ADMIN
from seahub.role_permissions.models import AdminRole
from seahub.role_permissions.utils import get_available_roles, get_available_admin_roles
from seahub.utils.licenseparse import user_number_over_limit
from seahub.options.models import UserOptions


logger = logging.getLogger(__name__)
json_content_type = 'application/json; charset=utf-8'

def update_user_info(request, user):

    # update basic user info
    password = request.data.get("password")
    if password:
        user.set_password(password)

    is_staff = request.data.get("is_staff")
    if is_staff:
        is_staff = to_python_boolean(is_staff)
        user.is_staff = is_staff

    is_active = request.data.get("is_active")
    if is_active:
        is_active = to_python_boolean(is_active)
        user.is_active = is_active
        if user.is_active:
            try:
                send_html_email(_(u'Your account on %s is activated') % get_site_name(),
                                'sysadmin/user_activation_email.html', {'username': user.email}, None, [user.email])
            except Exception as e:
                logger.error(e)

    # update user
    user.save()

    email = user.username

    # update additional user info
    if is_pro_version():
        role = request.data.get("role")
        if role:
            User.objects.update_role(email, role)

    nickname = request.data.get("name", None)
    if nickname is not None:
        Profile.objects.add_or_update(email, nickname)

    # update account login_id
    login_id = request.data.get("login_id", None)
    if login_id is not None:
        Profile.objects.add_or_update(email, login_id=login_id)

    # update account contact email
    contact_email = request.data.get('contact_email', None)
    if contact_email is not None:
        Profile.objects.add_or_update(email, contact_email=contact_email)
        key = normalize_cache_key(email, CONTACT_CACHE_PREFIX)
        cache.set(key, contact_email, CONTACT_CACHE_TIMEOUT)

    reference_id = request.data.get("reference_id", None)
    if reference_id is not None:
        if reference_id.strip():
            ccnet_api.set_reference_id(email, reference_id.strip())
        else:
            # remove reference id
            ccnet_api.set_reference_id(email, None)

    department = request.data.get("department")
    if department:
        d_profile = DetailedProfile.objects.get_detailed_profile_by_user(email)
        if d_profile is None:
            d_profile = DetailedProfile(user=email)

        d_profile.department = department
        d_profile.save()

    quota_total_mb = request.data.get("quota_total")
    if quota_total_mb:
        quota_total = int(quota_total_mb) * get_file_size_unit('MB')
        if is_org_context(request):
            org_id = request.user.org.org_id
            seafile_api.set_org_user_quota(org_id, email, quota_total)
        else:
            seafile_api.set_user_quota(email, quota_total)

class AdminAdminUsers(APIView):

    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAdminUser, )
    throttle_classes = (UserRateThrottle, )

    def get(self, request):
        """List all admins from database and ldap imported
        """
        try:
            db_users = ccnet_api.get_emailusers('DB', -1, -1)
            ldap_imported_users = ccnet_api.get_emailusers('LDAPImport', -1, -1)
        except Exception as e:
            logger.error(e)
            error_msg = 'Internal Server Error'
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        admin_users = []
        for user in db_users + ldap_imported_users:
            if user.is_staff is True:
                admin_users.append(user)

        admin_users_info = []
        for user in admin_users:
            user_info = get_user_info(user.email)
            try:
                admin_role = AdminRole.objects.get_admin_role(user.email)
                user_info['admin_role'] = admin_role.role
            except AdminRole.DoesNotExist:
                user_info['admin_role'] = DEFAULT_ADMIN
            admin_users_info.append(user_info)

        available_admin_roles = get_available_admin_roles()

        result = {
            'admin_users': admin_users_info,
            'available_admin_roles': available_admin_roles
        }
        return Response(result)

class AdminUsers(APIView):

    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAdminUser, )
    throttle_classes = (UserRateThrottle, )

    def get(self, request):

        try:
            page = int(request.GET.get('page', '1'))
            per_page = int(request.GET.get('per_page', '25'))
        except ValueError:
            page = 1
            per_page = 25

        start = (page - 1) * per_page
        end = page * per_page + 1
        users = ccnet_api.get_emailusers('DB', start, end)

        if len(users) == end - start:
            users = users[:per_page]
            has_next_page = True
        else:
            has_next_page = False

        data = []
        for user in users:
            user_info = get_user_info(user.email)
            data.append(user_info)
        page_info = {
            'has_next_page': has_next_page,
            'current_page': page
        }
        available_roles = get_available_roles()

        result = {
            'data': data,
            'page_info': page_info,
            'available_roles': available_roles
        }
        return Response(result)

    def post(self, request):

        if user_number_over_limit():
            error_msg = _("The number of users exceeds the limit.")
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        email = request.data.get('email', None)
        if not email or not is_valid_username(email):
            error_msg = 'email invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        # basic user info check
        is_staff = request.data.get("is_staff", None)
        if is_staff:
            try:
                is_staff = to_python_boolean(is_staff)
            except ValueError:
                error_msg = 'is_staff invalid.'
                return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        is_active = request.data.get("is_active", None)
        if is_active:
            try:
                is_active = to_python_boolean(is_active)
            except ValueError:
                error_msg = 'is_active invalid.'
                return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        # additional user info check
        role = request.data.get("role", None)
        if role:
            available_roles = get_available_roles()
            if role.lower() not in available_roles:
                error_msg = 'role must be in %s.' % str(available_roles)
                return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        name = request.data.get("name", None)
        if name:
            if len(name) > 64:
                error_msg = 'Name is too long (maximum is 64 characters).'
                return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

            if "/" in name:
                error_msg = "Name should not include '/'."
                return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        department = request.data.get("department", None)
        if department:
            if len(department) > 512:
                error_msg = "Department is too long (maximum is 512 characters)."
                return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        quota_total_mb = request.data.get("quota_total", None)
        if quota_total_mb:
            try:
                quota_total_mb = int(quota_total_mb)
            except ValueError:
                error_msg = "Must be an integer that is greater than or equal to 0."
                return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

            if quota_total_mb < 0:
                error_msg = "Space quota is too low (minimum value is 0)."
                return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

            if is_org_context(request):
                org_id = request.user.org.org_id
                org_quota_mb = seafile_api.get_org_quota(org_id) / \
                        get_file_size_unit('MB')

                if quota_total_mb > org_quota_mb:
                    error_msg = 'Failed to set quota: maximum quota is %d MB' % org_quota_mb
                    return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        try:
            User.objects.get(email=email)
            user_exist = True
        except User.DoesNotExist:
            user_exist = False

        if user_exist:
            error_msg = "User %s already exists." % email
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        password = request.data.get('password', None)
        if not password:
            error_msg = 'password required.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        # create user
        try:
            user_obj = User.objects.create_user(email)
            update_user_info(request, user_obj)
        except Exception as e:
            logger.error(e)
            error_msg = 'Internal Server Error'
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        if IS_EMAIL_CONFIGURED and SEND_EMAIL_ON_ADDING_SYSTEM_MEMBER:
            c = {'user': request.user.username, 'email': email, 'password': password}
            try:
                send_html_email(_(u'You are invited to join %s') % get_site_name(),
                        'sysadmin/user_add_email.html', c, None, [email])
            except Exception as e:
                logger.error(str(e))

        user_info = get_user_info(email)

        return Response(user_info)


class AdminUser(APIView):

    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAdminUser, )
    throttle_classes = (UserRateThrottle, )

    def get(self, request, email):

        try:
            User.objects.get(email=email)
        except User.DoesNotExist:
            error_msg = 'User %s not found.' % email
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        user_info = get_user_info(email)
        return Response(user_info)

    def put(self, request, email):

        # basic user info check
        is_staff = request.data.get("is_staff", None)
        if is_staff:
            try:
                is_staff = to_python_boolean(is_staff)
            except ValueError:
                error_msg = 'is_staff invalid.'
                return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        is_active = request.data.get("is_active", None)
        if is_active:
            try:
                is_active = to_python_boolean(is_active)
            except ValueError:
                error_msg = 'is_active invalid.'
                return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        # additional user info check
        role = request.data.get("role", None)
        if role:
            available_roles = get_available_roles()
            if role.lower() not in available_roles:
                error_msg = 'role must be in %s.' % str(available_roles)
                return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        name = request.data.get("name", None)
        if name:
            if len(name) > 64:
                error_msg = 'Name is too long (maximum is 64 characters).'
                return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

            if "/" in name:
                error_msg = "Name should not include '/'."
                return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        # argument check for login_id
        login_id = request.data.get("login_id", None)
        if login_id is not None:
            login_id = login_id.strip()
            username_by_login_id = Profile.objects.get_username_by_login_id(login_id)
            if username_by_login_id is not None:
                return api_error(status.HTTP_400_BAD_REQUEST, 
                                 _(u"Login id %s already exists." % login_id))

        contact_email = request.data.get("contact_email", None)
        if contact_email is not None and contact_email.strip() != '':
            if not is_valid_email(contact_email):
                error_msg = 'Contact email invalid.'
                return api_error(status.HTTP_400_BAD_REQUEST, error_msg)
            profile = Profile.objects.get_profile_by_contact_email(contact_email)
            if profile:
                error_msg = 'Contact email %s already exists.' % contact_email
                return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        reference_id = request.data.get("reference_id", "")
        if reference_id:
            if ' ' in reference_id:
                return api_error(status.HTTP_400_BAD_REQUEST, 'Reference ID can not contain spaces.')
            primary_id = ccnet_api.get_primary_id(reference_id)
            if primary_id:
                return api_error(status.HTTP_400_BAD_REQUEST, 'Reference ID %s already exists.' % reference_id)

        department = request.data.get("department", None)
        if department:
            if len(department) > 512:
                error_msg = "Department is too long (maximum is 512 characters)."
                return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        quota_total_mb = request.data.get("quota_total", None)
        if quota_total_mb:
            try:
                quota_total_mb = int(quota_total_mb)
            except ValueError:
                error_msg = "Must be an integer that is greater than or equal to 0."
                return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

            if quota_total_mb < 0:
                error_msg = "Space quota is too low (minimum value is 0)."
                return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

            if is_org_context(request):
                org_id = request.user.org.org_id
                org_quota_mb = seafile_api.get_org_quota(org_id) / \
                        get_file_size_unit('MB')

                if quota_total_mb > org_quota_mb:
                    error_msg = 'Failed to set quota: maximum quota is %d MB' % org_quota_mb
                    return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        # query user info
        try:
            user_obj = User.objects.get(email=email)
        except User.DoesNotExist:
            error_msg = 'User %s not found.' % email
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        try:
            update_user_info(request, user_obj)
        except Exception as e:
            logger.error(e)
            error_msg = 'Internal Server Error'
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        user_info = get_user_info(email)

        return Response(user_info)

    def delete(self, request, email):

        try:
            User.objects.get(email=email)
        except User.DoesNotExist:
            error_msg = 'User %s not found.' % email
            return api_error(status.HTTP_404_NOT_FOUND, error_msg)

        # delete user
        try:
            User.objects.get(email=email).delete()
        except Exception as e:
            logger.error(e)
            error_msg = 'Internal Server Error'
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        return Response({'success': True})


class AdminUserPassword(APIView):

    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAdminUser, )
    throttle_classes = (UserRateThrottle, )

    def put(self, request, email):
        """Reset password for user

        Permission checking:
        1. only admin can perform this action.
        """

        if not is_valid_username(email):
            error_msg = 'email invalid'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist as e:
            logger.error(e)
            error_msg = 'email invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        if isinstance(INIT_PASSWD, FunctionType):
            new_password = INIT_PASSWD()
        else:
            new_password = INIT_PASSWD
        user.set_password(new_password)
        user.save()

        if config.FORCE_PASSWORD_CHANGE:
            UserOptions.objects.set_force_passwd_change(user.username)

        if IS_EMAIL_CONFIGURED and SEND_EMAIL_ON_RESETTING_USER_PASSWD:
            c = {'email': email, 'password': new_password}
            try:
                send_html_email(_(u'Password has been reset on %s') % get_site_name(),
                                'sysadmin/user_reset_email.html', c, None, [email])
            except Exception, e:
                logger.error(e)
                error_msg = 'Internal Server Error'
                return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        return Response({'new_password': new_password})
