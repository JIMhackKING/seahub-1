# Copyright (c) 2012-2016 Seafile Ltd.
import logging

from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAdminUser
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status
from seaserv import ccnet_api, seafile_api

from seahub.api2.authentication import TokenAuthentication
from seahub.api2.throttling import UserRateThrottle
from seahub.api2.utils import api_error
from seahub.utils import is_valid_email

from seahub.api2.endpoints.admin.utils import get_repo_info

logger = logging.getLogger(__name__)


class AdminLibrariesShareIn(APIView):

    authentication_classes = (TokenAuthentication, SessionAuthentication)
    throttle_classes = (UserRateThrottle,)
    permission_classes = (IsAdminUser,)

    def get(self, request, format=None):
        """ List 'all' libraries shared to 'share_receiver'

        Permission checking:
        1. only admin can perform this action.
        """

        share_receiver = request.GET.get('share_receiver', '')
        if not is_valid_email(share_receiver):
            error_msg = 'share_receiver invalid.'
            return api_error(status.HTTP_400_BAD_REQUEST, error_msg)

        try:
            share_in_repos = seafile_api.get_share_in_repo_list(share_receiver, -1, -1)
        except Exception as e:
            logger.error(e)
            error_msg = 'Internal Server Error'
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, error_msg)

        repos_info = []
        for repo in share_in_repos:
            repo_info = get_repo_info(repo)
            repos_info.append(repo_info)

        return Response(repos_info)
