'''
Created on Feb 1, 2013

@organization: cert.org
'''
import logging

logger = logging.getLogger(__name__)

_bool_attrs = ["grant_read_uri_permission",
              "grant_write_uri_permission", "debug_log_resolution",
              "exclude_stopped_packages", "include_stopped_packages",
              "activity_brought_to_front", "activity_clear_top",
              "activity_clear_when_task_reset",
              "activity_exclude_from_recents",
              "activity_launched_from_history",
              "activity_multiple_task", "activity_no_animation",
              "activity_no_history", "activity_no_user_action",
              "activity_previous_is_top", "activity_reorder_to_front",
              "activity_reset_task_if_needed", "activity_single_top",
              "activity_clear_task", "activity_task_on_home",
              "receiver_registered_only", "receiver_replace_pending",
              "selector",
              ]
_str_attrs = ["action", "data_uri", "mime_type", "component", "uri", "package"]
_list_attrs = ["categories", "extras", "flags"]
_dict_attrs = ["extra_strings", "extra_booleans", "extra_ints", "extra_longs",
               "extra_floats", "extra_uris", "extra_components",
               "extra_int_array", "extra_long_array", "extra_float_array"]
_loadable_attrs = _bool_attrs + _str_attrs + _list_attrs + _dict_attrs

def _attribute_to_option(a):
    # 'foo_bar_baz' -> '--foo-bar-baz'
    return '--%s' % a.replace('_', '-')

class Intent(object):
    '''
    Data object for constructing Intents (for use with activity manager)
    '''
#==============================================================================
# <INTENT> specifications include these flags and arguments:
#    [-a <ACTION>] [-d <DATA_URI>] [-t <MIME_TYPE>]
    action = None
    data_uri = None
    mime_type = None
#    [-c <CATEGORY> [-c <CATEGORY>] ...]
    categories = []
#    [-e|--es <EXTRA_KEY> <EXTRA_STRING_VALUE> ...]
    extra_strings = {}

#    [--esn <EXTRA_KEY> ...]
    extras = []

#    [--ez <EXTRA_KEY> <EXTRA_BOOLEAN_VALUE> ...]
    extra_booleans = {}

#    [--ei <EXTRA_KEY> <EXTRA_INT_VALUE> ...]
    extra_ints = {}

#    [--el <EXTRA_KEY> <EXTRA_LONG_VALUE> ...]
    extra_longs = {}

#    [--ef <EXTRA_KEY> <EXTRA_FLOAT_VALUE> ...]
    extra_floats = {}

#    [--eu <EXTRA_KEY> <EXTRA_URI_VALUE> ...]
    extra_uris = {}

#    [--ecn <EXTRA_KEY> <EXTRA_COMPONENT_NAME_VALUE>]
    extra_components = {}

#    [--eia <EXTRA_KEY> <EXTRA_INT_VALUE>[,<EXTRA_INT_VALUE...]]
    extra_int_array = {}

#    [--ela <EXTRA_KEY> <EXTRA_LONG_VALUE>[,<EXTRA_LONG_VALUE...]]
    extra_long_array = {}

#    [--efa <EXTRA_KEY> <EXTRA_FLOAT_VALUE>[,<EXTRA_FLOAT_VALUE...]]
    extra_float_array = {}

#    [-n <COMPONENT>] [-f <FLAGS>]
    component = None
    flags = []

#    [--grant-read-uri-permission] [--grant-write-uri-permission]
    grant_read_uri_permission = False
    grant_write_uri_permission = False
#    [--debug-log-resolution] [--exclude-stopped-packages]
    debug_log_resolution = False
    exclude_stopped_packages = False
#    [--include-stopped-packages]
    include_stopped_packages = False
#    [--activity-brought-to-front] [--activity-clear-top]
    activity_brought_to_front = False
    activity_clear_top = False
#    [--activity-clear-when-task-reset] [--activity-exclude-from-recents]
    activity_clear_when_task_reset = False
    activity_exclude_from_recents = False
#    [--activity-launched-from-history] [--activity-multiple-task]
    activity_launched_from_history = False
    activity_multiple_task = False
#    [--activity-no-animation] [--activity-no-history]
    activity_no_animation = False
    activity_no_history = False
#    [--activity-no-user-action] [--activity-previous-is-top]
    activity_no_user_action = False
    activity_previous_is_top = False
#    [--activity-reorder-to-front] [--activity-reset-task-if-needed]
    activity_reorder_to_front = False
    activity_reset_task_if_needed = False
#    [--activity-single-top] [--activity-clear-task]
    activity_single_top = False
    activity_clear_task = False
#    [--activity-task-on-home]
    activity_task_on_home = False
#    [--receiver-registered-only] [--receiver-replace-pending]
    receiver_registered_only = False
    receiver_replace_pending = False
#    [--selector]
    selector = False
#    [<URI> | <PACKAGE> | <COMPONENT>]
    uri = None
    package = None
#    component = None
#==============================================================================

    def load_yaml(self, yaml_path):
        '''
        Attempts to load data from a yaml file.

        :param yaml_path:
        '''
        import yaml
        try:
            with open(yaml_path, 'r') as f:
                d = yaml.safe_load(f.read())
                loaded_intent = d['intent']
        except IOError as e:
            logger.warning('Unable to open %s: %s', yaml_path, e)
            raise
        except KeyError as e:
            logger.warning('No intent found in %s: %s', yaml_path, e)
            raise

        for k in _loadable_attrs:
            try:
                setattr(self, k, loaded_intent[k])
            except KeyError, e:
                # missing attributes are ok
                pass

    def as_args(self):
        parts = []
        if self.action:
            parts.extend(['-a', self.action])

        if self.data_uri:
            parts.extend(['-d', self.data_uri])

        if self.mime_type:
            parts.extend(['-t', self.mime_type])

        def _l2list(pfx, inlist):
            l = []
            for x in inlist:
                l.extend([pfx, x])
            return l

        parts.extend(_l2list('-c', self.categories))

        def _d2list(pfx, d):
            l = []
            for k, v in d.iteritems():
                l.extend([pfx, k, str(v)])
            return l

        parts.extend(_d2list('--es', self.extra_strings))

        parts.extend(_l2list('--esn', self.extras))

        parts.extend(_d2list('--ez', self.extra_booleans))
        parts.extend(_d2list('--ei', self.extra_ints))
        parts.extend(_d2list('--el', self.extra_longs))
        parts.extend(_d2list('--ef', self.extra_floats))
        parts.extend(_d2list('--eu', self.extra_uris))
        parts.extend(_d2list('--ecn', self.extra_components))

        def _darray2list(pfx, d):
            l = []
            for k, v in d.iteritems():
                l.extend(pfx, k)
                l.append(', '.join([str(x) for x in v]))
            return l

        parts.extend(_darray2list('--eia', self.extra_int_array))
        parts.extend(_darray2list('--ela', self.extra_long_array))
        parts.extend(_darray2list('--efa', self.extra_float_array))

        if self.component:
            parts.extend(['-n', self.component])

        if self.flags:
            parts.extend(['-f', self.flags])

        for a in _bool_attrs:
            if hasattr(self, a):
                val = getattr(self, a)
                if val:
                    a_str = _attribute_to_option(a)
                    parts.append(a_str)

        if self.uri:
            parts.append(self.uri)
        elif self.package:
            parts.append(self.package)
#        elif self.component:
#            parts.append(self.component)

        return parts

    def __repr__(self, *args, **kwargs):
        return ' '.join(self.as_args())
