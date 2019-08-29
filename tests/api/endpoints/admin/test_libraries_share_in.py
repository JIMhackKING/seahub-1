import json
from django.core.urlresolvers import reverse
from seahub.test_utils import BaseTestCase
from tests.common.utils import randstring
from seaserv import seafile_api

from seahub.share.models import FileShare, UploadLinkShare

class AdminLibrariesTest(BaseTestCase):

    def setUp(self):
        self.libraries_share_in_url = reverse('api-v2.1-admin-libraries-share-in')

        # create tmp user
        tmp_user = self.create_user(email='user@tmp.com')

        # create tmp repo
        tmp_user_repo_id = seafile_api.create_repo(name='test-repo', desc='',
            username=tmp_user.username, passwd=None)

        # share tmp repo to current user
        permission = 'r'
        seafile_api.share_repo(tmp_user_repo_id, tmp_user.username,
                self.user.username, permission)

    def tearDown(self):
        self.remove_repo()

    def test_can_get(self):
        self.login_as(self.admin)

        url = self.libraries_share_in_url + '?share_receiver=%s' % self.user.username
        resp = self.client.get(url)

        json_resp = json.loads(resp.content)
        assert len(json_resp) > 0

    def test_get_with_invalid_email(self):
        self.login_as(self.admin)
        url = self.libraries_share_in_url + '?share_receiver=%s' % 'I_am_invalid_email'
        resp = self.client.get(url)
        self.assertEqual(400, resp.status_code)

    def test_get_with_invalid_user_permission(self):
        self.login_as(self.user)
        resp = self.client.get(self.libraries_share_in_url)
        self.assertEqual(403, resp.status_code)