__author__ = 'schoksey'

from keystone import exception
from keystone import identity
from keystone.identity.backends import sql
from keystone.identity.backends import ldap
from keystone.openstack.common import log as logging
from oslo.config import cfg
from keystone import config as ks_cfg
from keystone.common.ldap import core
import uuid
import re

CONF = ks_cfg.CONF
ks_cfg.CONF.register_opt(cfg.ListOpt('builtin_users'), group='ldap')

DEFAULT_DOMAIN_ID = CONF.identity.default_domain_id
LDAP_BIND_USER = CONF.ldap.user
LDAP_BIND_PASSWORD = CONF.ldap.password
LDAP_CN_SUFFIX= CONF.ldap.user_suffix
LDAP_USER_OBJECT_CLASS = CONF.ldap.user_objectclass
LDAP_USER_ID_ATTRIBUTE = CONF.ldap.user_id_attribute
LDAP_USER_TREE_DN = CONF.ldap.user_tree_dn
LDAP_GENERIC_TREE_DN = CONF.ldap.generic_tree_dn
LDAP_BUILTIN_USERS = CONF.ldap.builtin_users

LOG = logging.getLogger(__name__)



class Identity(sql.Identity):

    def __init__(self):
        super(Identity, self).__init__()
        #TODO:: (schoksey) Inject as an additional driver from CONF file
        self.ldap_identity_api = ldap.Identity()

    def authenticate(self, user_id=None, password=None):
        """Authenticate based Cisco AD
        The tenant will be defaulted to the value in keystone.conf
        1. if user is any of the built-in Openstack users, then do sql authC
        2. if user is non-built-in type, then perform AD authentication
        3. check if non-built-in user type is already in ks db, if not then add to default admin tenant
        NOTE: Password is NEVER persisted in the keystone db
        """

        LOG.debug("Authenticating against HYBRID Driver")

        try:
            user_ref = self.get_user(user_id)
        except exception.UserNotFound:
            pass

        if self._is_built_in_user(user_ref=user_ref, username=None):
            return super(Identity, self).authenticate(user_ref.get('id'), password)

        try:
            conn = self.ldap_identity_api.user.get_connection(self._resolve_cn_suffix(user_ref.get('name')), password)
            if not conn:
                raise AssertionError('Invalid user / password')
        except Exception:
            raise AssertionError('Invalid user / password')

        if not (user_ref.get('enabled')):
            user = {}
            user['enabled'] = True
            self.update_user(user_id, user)

        return (identity.filter_user(self.get_user(user_id)))


    def get_user_by_name(self, user_name, domain_id):
        # do ldap look up on user validity
        # if valid, then create a record in mysql with enabled status = False and return reference
        # in subsequent calls to authentication,
        # this user_id will be passed to do final authentication against ldap, if passed, update the enabled flag to True
        try:
	    return identity.filter_user(super(Identity, self).get_user_by_name(user_name, domain_id))
        except exception.UserNotFound:
            if user_name != self._lookup_username_in_ad(user_name):
                raise exception.UserNotFound(user_id=user_name)

        new_user_dict = self._build_new_user_dict(user_name,
                                                  self._resolve_cn_suffix(user_name),
                                                  enabled=False)
        new_user_ref = self.create_user(new_user_dict['id'], new_user_dict)

        if 'tenantId' in new_user_dict and new_user_dict['tenantId'] is not None:
            self.add_user_to_project(new_user_dict['tenantId'], new_user_dict['id'])

        return new_user_ref


    def _build_new_user_dict(self, username, email, tenant=None, enabled=False, domain_id=DEFAULT_DOMAIN_ID):
        new_user_ref = {}
        if (tenant is not None):
            new_user_ref['tenantId'] = (self.get_project_by_name(tenant, domain_id)).get('id')
        new_user_ref['id'] = uuid.uuid4().hex
        new_user_ref['name'] = username
        new_user_ref['domain_id'] = domain_id
        new_user_ref['email'] = email
        new_user_ref['enabled'] = enabled

        LOG.debug("new_user_ref:****************** %s", new_user_ref)

        return new_user_ref


    def _is_built_in_user(self, user_ref, username):
        if user_ref is None and username is None:
            return False
        if username is None:
            username = user_ref.get('name')
        if username in LDAP_BUILTIN_USERS or re.search('-brokerWaitHandle-', username,  re.IGNORECASE):
            return True
        else:
            return False


    def _resolve_cn_suffix(self, user_id):
        return ''.join([user_id,LDAP_CN_SUFFIX]) if LDAP_CN_SUFFIX else user_id


    def _lookup_username_in_ad(self, username):
        conn = self.ldap_identity_api.user.get_connection(self._resolve_cn_suffix(LDAP_BIND_USER), LDAP_BIND_PASSWORD)
        baseDN = self._resolve_baseDN(username)
	query = "(&({}={})(objectClass={}))".format(LDAP_USER_ID_ATTRIBUTE,username,LDAP_USER_OBJECT_CLASS)
        attrlist = [LDAP_USER_ID_ATTRIBUTE]
        o = conn.search_s(baseDN, core.LDAP_SCOPES.get('one'), query, attrlist)
        return (o[0][1])[LDAP_USER_ID_ATTRIBUTE][0]


    def _resolve_baseDN(self, username):
        return LDAP_GENERIC_TREE_DN if re.search('\.gen$', username) else LDAP_USER_TREE_DN


    def create_user(self, user_id, user):
        try:
	    if not self._is_built_in_user(user_ref=None, username=user['name']):
                username = self._lookup_username_in_ad(user['name'])
                if user['name'] != self._lookup_username_in_ad(username):
                    raise exception.UserNotFound(user_id=username)
        except Exception:
            raise AssertionError('Invalid user / password')

        return super(Identity, self).create_user(user_id, user)
