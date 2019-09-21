# -*- coding: utf-8 -*-
import os
import time
import logging
from urllib import request as requests
import jwt

from django.http import HttpResponseRedirect
from django.shortcuts import render
from django.utils.translation import ugettext as _
from seaserv import seafile_api

from seahub.dtable.models import Workspaces, DTables, DTableRowShares
from seahub.utils import normalize_file_path, render_error, render_permission_error, \
     gen_file_get_url, get_file_type_and_ext, gen_inner_file_get_url
from seahub.auth.decorators import login_required
from seahub.settings import DTABLE_SERVER_URL, SEAFILE_COLLAB_SERVER, MEDIA_URL, \
     DTABLE_PRIVATE_KEY
from seahub.dtable.utils import check_dtable_permission
from seahub.constants import PERMISSION_ADMIN, PERMISSION_READ_WRITE
from seahub.views.file import get_file_content

logger = logging.getLogger(__name__)

FILE_TYPE = '.dtable'
WRITE_PERMISSION_TUPLE = (PERMISSION_READ_WRITE, PERMISSION_ADMIN)


@login_required
def dtable_file_view(request, workspace_id, name):
    """

    Permission:
    1. owner
    2. group member
    3. shared user
    """
    # resource check
    workspace = Workspaces.objects.get_workspace_by_id(workspace_id)
    if not workspace:
        return render_error(request, 'Workspace does not exist.')

    repo_id = workspace.repo_id
    repo = seafile_api.get_repo(repo_id)
    if not repo:
        return render_error(request, 'Library does not exist.')

    dtable = DTables.objects.get_dtable(workspace, name)
    if not dtable:
        return render_error(request, 'DTable does not exist')

    # permission check
    username = request.user.username
    if not check_dtable_permission(username, workspace, dtable):
        return render_permission_error(request, _('Permission denied.'))

    return_dict = {
        'filename': name,
        'workspace_id': workspace_id,
        'dtable_uuid': dtable.uuid.hex,
        'media_url': MEDIA_URL,
        'dtable_server': DTABLE_SERVER_URL,
        'dtable_socket': SEAFILE_COLLAB_SERVER
    }

    return render(request, 'dtable_file_view_react.html', return_dict)


@login_required
def dtable_asset_access(request, workspace_id, dtable_id, path):
    """

    Permission:
    1. owner
    2. group member
    3. shared user with `rw` or `admin` permission
    """
    asset_name = os.path.basename(normalize_file_path(path))

    # resource check
    workspace = Workspaces.objects.get_workspace_by_id(workspace_id)
    if not workspace:
        return render_error(request, 'Workspace does not exist.')

    repo_id = workspace.repo_id
    repo = seafile_api.get_repo(repo_id)
    if not repo:
        return render_error(request, 'Library does not exist.')

    dtable = DTables.objects.get_dtable_by_uuid(dtable_id)
    if not dtable:
        return render_error(request, 'DTable does not exist.')

    asset_path = normalize_file_path(os.path.join('/asset', dtable_id, path))
    asset_id = seafile_api.get_file_id_by_path(repo_id, asset_path)
    if not asset_id:
        return render_error(request, 'Asset file does not exist.')

    # permission check
    username = request.user.username
    if check_dtable_permission(username, workspace, dtable) not in WRITE_PERMISSION_TUPLE:
        return render_permission_error(request, _('Permission denied.'))

    dl = request.GET.get('dl', '0') == '1'
    operation = 'download' if dl else 'view'

    token = seafile_api.get_fileserver_access_token(
        repo_id, asset_id, operation, '', use_onetime=False
    )

    url = gen_file_get_url(token, asset_name)

    return HttpResponseRedirect(url)


@login_required
def dtable_asset_file_view(request, workspace_id, dtable_id, path):

    # resource check
    workspace = Workspaces.objects.get_workspace_by_id(workspace_id)
    if not workspace:
        return render_error(request, 'Workspace does not exist.')

    repo_id = workspace.repo_id
    repo = seafile_api.get_repo(repo_id)
    if not repo:
        return render_error(request, 'Library does not exist.')

    dtable = DTables.objects.get_dtable_by_uuid(dtable_id)
    if not dtable:
        return render_error(request, 'DTable does not exist.')

    asset_path = normalize_file_path(os.path.join('/asset', dtable_id, path))
    asset_id = seafile_api.get_file_id_by_path(repo_id, asset_path)
    if not asset_id:
        return render_error(request, 'Asset file does not exist.')

    # permission check
    username = request.user.username
    if not check_dtable_permission(username, workspace, dtable):
        return render_permission_error(request, _('Permission denied.'))

    file_enc = request.GET.get('file_enc', 'auto')
    if file_enc not in FILE_ENCODING_LIST:
        file_enc = 'auto'

    token = seafile_api.get_fileserver_access_token(
        repo_id, asset_id, 'view', '', use_onetime=False
    )

    file_name = os.path.basename(normalize_file_path(path))
    file_type, file_ext = get_file_type_and_ext(file_name)

    inner_path = gen_inner_file_get_url(token, file_name)
    error_msg, file_content, encoding = get_file_content(file_type, inner_path, file_enc)

    raw_path = gen_file_get_url(token, file_name)

    return_dict = {
        'repo': repo,
        'filename': file_name,
        'file_path': asset_path,
        'file_type': file_type,
        'file_ext': file_ext,
        'raw_path': raw_path,
        'file_content': file_content,
        'err': 'File preview unsupported' if file_type == 'Unknown' else error_msg,
    }

    return render(request, 'dtable_asset_file_view_react.html', return_dict)


@login_required
def dtable_share_links(request, token):

    # resource check
    dtable_row_share = DTableRowShares.objects.get_dtable_row_share_by_token(token)
    if not dtable_row_share:
        return render_error(request, 'DTable row share link does not exist.')

    workspace_id = dtable_row_share.workspace_id
    workspace = Workspaces.objects.get_workspace_by_id(workspace_id)
    if not workspace:
        return render_error(request, 'Workspace does not exist.')

    repo_id = workspace.repo_id
    repo = seafile_api.get_repo(repo_id)
    if not repo:
        return render_error(request, 'Library does not exist.')

    dtable_uuid = dtable_row_share.dtable_uuid
    dtable = DTables.objects.get_dtable_by_uuid(dtable_uuid)
    if not dtable:
        return render_error(request, 'DTable %s does not exist' % dtable_uuid)

    # generate json web token
    username = request.user.username
    payload = {
        'exp': int(time.time()) + 86400 * 3,
        'dtable_uuid': dtable.uuid.hex,
        'username': username,
    }

    try:
        access_token = jwt.encode(
            payload, DTABLE_PRIVATE_KEY, algorithm='HS256'
        )
    except Exception as e:
        logger.error(e)
        return render_error(request, _('Internal Server Error'))

    url = '%s/api/v1/dtables/%s/tables/%s/rows/%s/' % \
          (DTABLE_SERVER_URL.strip('/'), dtable_uuid, dtable_row_share.table_id, dtable_row_share.row_id)
    req = requests.Request(url, headers={"Authorization": "Token %s" % access_token.decode()})

    try:
        res = requests.urlopen(req).read().decode()
    except Exception as e:
        logger.error(e)
        return render_error(request, _('Internal Server Error'))

    return_dict = {
        'file_content': res,
    }

    return render(request, 'shared_dtable_row_view_react.html', return_dict)
