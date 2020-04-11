# Copyright (c), Michael DeHaan <michael.dehaan@gmail.com>, 2012-2013
# Copyright (c), Toshio Kuratomi <tkuratomi@ansible.com> 2016
# Simplified BSD License (see licenses/simplified_bsd.txt or https://opensource.org/licenses/BSD-2-Clause)

from __future__ import absolute_import, division, print_function

FILE_ATTRIBUTES = {
    'A': 'noatime',
    'a': 'append',
    'c': 'compressed',
    'C': 'nocow',
    'd': 'nodump',
    'D': 'dirsync',
    'e': 'extents',
    'E': 'encrypted',
    'h': 'blocksize',
    'i': 'immutable',
    'I': 'indexed',
    'j': 'journalled',
    'N': 'inline',
    's': 'zero',
    'S': 'synchronous',
    't': 'notail',
    'T': 'blockroot',
    'u': 'undelete',
    'X': 'compressedraw',
    'Z': 'compresseddirty',
}

# Ansible modules can be written in any language.
# The functions available here can be used to do many common tasks,
# to simplify development of Python modules.

import __main__
import atexit
import errno
import datetime
import grp
import fcntl
import locale
import os
import pwd
import platform
import re
import select
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import traceback
import types

from collections import deque
from itertools import chain, repeat

try:
    import syslog
    HAS_SYSLOG = True
except ImportError:
    HAS_SYSLOG = False

try:
    from systemd import journal
    has_journal = True
except ImportError:
    has_journal = False

# Python2 & 3 way to get NoneType
NoneType = type(None)

from ._text import to_native, to_bytes, to_text
from ansible.module_utils.common.text.converters import (
    jsonify,
    container_to_bytes as json_dict_unicode_to_bytes,
    container_to_text as json_dict_bytes_to_unicode,
)

from ansible.module_utils.common.text.formatters import (
    lenient_lowercase,
    bytes_to_human,
    human_to_bytes,
    SIZE_RANGES,
)

try:
    from ansible.module_utils.common._json_compat import json
except ImportError as e:
    print('\n{{"msg": "Error: ansible requires the stdlib json: {0}", "failed": true}}'.format(to_native(e)))
    sys.exit(1)


AVAILABLE_HASH_ALGORITHMS = dict()
try:
    import hashlib

    # python 2.7.9+ and 2.7.0+
    for attribute in ('available_algorithms', 'algorithms'):
        algorithms = getattr(hashlib, attribute, None)
        if algorithms:
            break
    if algorithms is None:
        # python 2.5+
        algorithms = ('md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512')
    for algorithm in algorithms:
        AVAILABLE_HASH_ALGORITHMS[algorithm] = getattr(hashlib, algorithm)

    # we may have been able to import md5 but it could still not be available
    try:
        hashlib.md5()
    except ValueError:
        AVAILABLE_HASH_ALGORITHMS.pop('md5', None)
except Exception:
    import sha
    AVAILABLE_HASH_ALGORITHMS = {'sha1': sha.sha}
    try:
        import md5
        AVAILABLE_HASH_ALGORITHMS['md5'] = md5.md5
    except Exception:
        pass

from ansible.module_utils.common._collections_compat import (
    KeysView,
    Mapping, MutableMapping,
    Sequence, MutableSequence,
    Set, MutableSet,
)
from ansible.module_utils.common.process import get_bin_path
from ansible.module_utils.common.file import (
    _PERM_BITS as PERM_BITS,
    _EXEC_PERM_BITS as EXEC_PERM_BITS,
    _DEFAULT_PERM as DEFAULT_PERM,
    is_executable,
    format_attributes,
    get_flags_from_attributes,
)
from ansible.module_utils.common.sys_info import (
    get_distribution,
    get_distribution_version,
    get_platform_subclass,
)
from ansible.module_utils.pycompat24 import get_exception, literal_eval
from ansible.module_utils.common.parameters import (
    handle_aliases,
    list_deprecations,
    list_no_log_values,
    PASS_VARS,
    PASS_BOOLS,
)

from ansible.module_utils.six import (
    PY2,
    PY3,
    b,
    binary_type,
    integer_types,
    iteritems,
    string_types,
    text_type,
)
from ansible.module_utils.six.moves import map, reduce, shlex_quote
from ansible.module_utils.common.validation import (
    check_missing_parameters,
    check_mutually_exclusive,
    check_required_arguments,
    check_required_by,
    check_required_if,
    check_required_one_of,
    check_required_together,
    count_terms,
    check_type_bool,
    check_type_bits,
    check_type_bytes,
    check_type_float,
    check_type_int,
    check_type_jsonarg,
    check_type_list,
    check_type_dict,
    check_type_path,
    check_type_raw,
    check_type_str,
    safe_eval,
)
from ansible.module_utils.common._utils import get_all_subclasses as _get_all_subclasses
from ansible.module_utils.parsing.convert_bool import BOOLEANS, BOOLEANS_FALSE, BOOLEANS_TRUE, boolean
from ansible.module_utils.common.warnings import (
    deprecate,
    get_deprecation_messages,
    get_warning_messages,
    warn,
)

# Note: When getting Sequence from collections, it matches with strings. If
# this matters, make sure to check for strings before checking for sequencetype
SEQUENCETYPE = frozenset, KeysView, Sequence

PASSWORD_MATCH = re.compile(r'^(?:.+[-_\s])?pass(?:[-_\s]?(?:word|phrase|wrd|wd)?)(?:[-_\s].+)?$', re.I)

imap = map

try:
    # Python 2
    unicode
except NameError:
    # Python 3
    unicode = text_type

try:
    # Python 2
    basestring
except NameError:
    # Python 3
    basestring = string_types

_literal_eval = literal_eval

# End of deprecated names

# Internal global holding passed in params.  This is consulted in case
# multiple AnsibleModules are created.  Otherwise each AnsibleModule would
# attempt to read from stdin.  Other code should not use this directly as it
# is an internal implementation detail
_ANSIBLE_ARGS = None

FILE_COMMON_ARGUMENTS = dict(
    # These are things we want. About setting metadata (mode, ownership, permissions in general) on
    # created files (these are used by set_fs_attributes_if_different and included in
    # load_file_common_arguments)
    mode=dict(type='raw'),
    owner=dict(type='str'),
    group=dict(type='str'),
    seuser=dict(type='str'),
    serole=dict(type='str'),
    selevel=dict(type='str'),
    setype=dict(type='str'),
    attributes=dict(type='str', aliases=['attr']),
    unsafe_writes=dict(type='bool', default=False),  # should be available to any module using atomic_move
)

PASSWD_ARG_RE = re.compile(r'^[-]{0,2}pass[-]?(word|wd)?')

# Used for parsing symbolic file perms
MODE_OPERATOR_RE = re.compile(r'[+=-]')
USERS_RE = re.compile(r'[^ugo]')
PERMS_RE = re.compile(r'[^rwxXstugo]')

# Used for determining if the system is running a new enough python version
# and should only restrict on our documented minimum versions
_PY3_MIN = sys.version_info[:2] >= (3, 5)
_PY2_MIN = (2, 6) <= sys.version_info[:2] < (3,)
_PY_MIN = _PY3_MIN or _PY2_MIN
if not _PY_MIN:
    print(
        '\n{"failed": true, '
        '"msg": "Ansible requires a minimum of Python2 version 2.6 or Python3 version 3.5. Current version: %s"}' % ''.join(sys.version.splitlines())
    )
    sys.exit(1)


#
# Deprecated functions
#

def get_platform():
    '''
    **Deprecated** Use :py:func:`platform.system` directly.

    :returns: Name of the platform the module is running on in a native string

    Returns a native string that labels the platform ("Linux", "Solaris", etc). Currently, this is
    the result of calling :py:func:`platform.system`.
    '''
    return platform.system()

# End deprecated functions


#
# Compat shims
#

def load_platform_subclass(cls, *args, **kwargs):
    """**Deprecated**: Use ansible.module_utils.common.sys_info.get_platform_subclass instead"""
    platform_cls = get_platform_subclass(cls)
    return super(cls, platform_cls).__new__(platform_cls)


def get_all_subclasses(cls):
    """**Deprecated**: Use ansible.module_utils.common._utils.get_all_subclasses instead"""
    return list(_get_all_subclasses(cls))


# End compat shims


def _remove_values_conditions(value, no_log_strings, deferred_removals):
    """
    Helper function for :meth:`remove_values`.

    :arg value: The value to check for strings that need to be stripped
    :arg no_log_strings: set of strings which must be stripped out of any values
    :arg deferred_removals: List which holds information about nested
        containers that have to be iterated for removals.  It is passed into
        this function so that more entries can be added to it if value is
        a container type.  The format of each entry is a 2-tuple where the first
        element is the ``value`` parameter and the second value is a new
        container to copy the elements of ``value`` into once iterated.
    :returns: if ``value`` is a scalar, returns ``value`` with two exceptions:
        1. :class:`~datetime.datetime` objects which are changed into a string representation.
        2. objects which are in no_log_strings are replaced with a placeholder
            so that no sensitive data is leaked.
        If ``value`` is a container type, returns a new empty container.

    ``deferred_removals`` is added to as a side-effect of this function.

    .. warning:: It is up to the caller to make sure the order in which value
        is passed in is correct.  For instance, higher level containers need
        to be passed in before lower level containers. For example, given
        ``{'level1': {'level2': 'level3': [True]} }`` first pass in the
        dictionary for ``level1``, then the dict for ``level2``, and finally
        the list for ``level3``.
    """
    if isinstance(value, (text_type, binary_type)):
        # Need native str type
        native_str_value = value
        if isinstance(value, text_type):
            value_is_text = True
            if PY2:
                native_str_value = to_bytes(value, errors='surrogate_or_strict')
        elif isinstance(value, binary_type):
            value_is_text = False
            if PY3:
                native_str_value = to_text(value, errors='surrogate_or_strict')

        if native_str_value in no_log_strings:
            return 'VALUE_SPECIFIED_IN_NO_LOG_PARAMETER'
        for omit_me in no_log_strings:
            native_str_value = native_str_value.replace(omit_me, '*' * 8)

        if value_is_text and isinstance(native_str_value, binary_type):
            value = to_text(native_str_value, encoding='utf-8', errors='surrogate_then_replace')
        elif not value_is_text and isinstance(native_str_value, text_type):
            value = to_bytes(native_str_value, encoding='utf-8', errors='surrogate_then_replace')
        else:
            value = native_str_value

    elif isinstance(value, Sequence):
        if isinstance(value, MutableSequence):
            new_value = type(value)()
        else:
            new_value = []  # Need a mutable value
        deferred_removals.append((value, new_value))
        value = new_value

    elif isinstance(value, Set):
        if isinstance(value, MutableSet):
            new_value = type(value)()
        else:
            new_value = set()  # Need a mutable value
        deferred_removals.append((value, new_value))
        value = new_value

    elif isinstance(value, Mapping):
        if isinstance(value, MutableMapping):
            new_value = type(value)()
        else:
            new_value = {}  # Need a mutable value
        deferred_removals.append((value, new_value))
        value = new_value

    elif isinstance(value, tuple(chain(integer_types, (float, bool, NoneType)))):
        stringy_value = to_native(value, encoding='utf-8', errors='surrogate_or_strict')
        if stringy_value in no_log_strings:
            return 'VALUE_SPECIFIED_IN_NO_LOG_PARAMETER'
        for omit_me in no_log_strings:
            if omit_me in stringy_value:
                return 'VALUE_SPECIFIED_IN_NO_LOG_PARAMETER'

    elif isinstance(value, datetime.datetime):
        value = value.isoformat()
    else:
        raise TypeError('Value of unknown type: %s, %s' % (type(value), value))

    return value


def remove_values(value, no_log_strings):
    """ Remove strings in no_log_strings from value.  If value is a container
    type, then remove a lot more"""
    deferred_removals = deque()

    no_log_strings = [to_native(s, errors='surrogate_or_strict') for s in no_log_strings]
    new_value = _remove_values_conditions(value, no_log_strings, deferred_removals)

    while deferred_removals:
        old_data, new_data = deferred_removals.popleft()
        if isinstance(new_data, Mapping):
            for old_key, old_elem in old_data.items():
                new_elem = _remove_values_conditions(old_elem, no_log_strings, deferred_removals)
                new_data[old_key] = new_elem
        else:
            for elem in old_data:
                new_elem = _remove_values_conditions(elem, no_log_strings, deferred_removals)
                if isinstance(new_data, MutableSequence):
                    new_data.append(new_elem)
                elif isinstance(new_data, MutableSet):
                    new_data.add(new_elem)
                else:
                    raise TypeError('Unknown container type encountered when removing private values from output')

    return new_value


def heuristic_log_sanitize(data, no_log_values=None):
    ''' Remove strings that look like passwords from log messages '''
    # Currently filters:
    # user:pass@foo/whatever and http://username:pass@wherever/foo
    # This code has false positives and consumes parts of logs that are
    # not passwds

    # begin: start of a passwd containing string
    # end: end of a passwd containing string
    # sep: char between user and passwd
    # prev_begin: where in the overall string to start a search for
    #   a passwd
    # sep_search_end: where in the string to end a search for the sep
    data = to_native(data)

    output = []
    begin = len(data)
    prev_begin = begin
    sep = 1
    while sep:
        # Find the potential end of a passwd
        try:
            end = data.rindex('@', 0, begin)
        except ValueError:
            # No passwd in the rest of the data
            output.insert(0, data[0:begin])
            break

        # Search for the beginning of a passwd
        sep = None
        sep_search_end = end
        while not sep:
            # URL-style username+password
            try:
                begin = data.rindex('://', 0, sep_search_end)
            except ValueError:
                # No url style in the data, check for ssh style in the
                # rest of the string
                begin = 0
            # Search for separator
            try:
                sep = data.index(':', begin + 3, end)
            except ValueError:
                # No separator; choices:
                if begin == 0:
                    # Searched the whole string so there's no password
                    # here.  Return the remaining data
                    output.insert(0, data[0:begin])
                    break
                # Search for a different beginning of the password field.
                sep_search_end = begin
                continue
        if sep:
            # Password was found; remove it.
            output.insert(0, data[end:prev_begin])
            output.insert(0, '********')
            output.insert(0, data[begin:sep + 1])
            prev_begin = begin

    output = ''.join(output)
    if no_log_values:
        output = remove_values(output, no_log_values)
    return output


def env_fallback(*args, **kwargs):
    ''' Load value from environment '''
    for arg in args:
        if arg in os.environ:
            return os.environ[arg]
    raise AnsibleFallbackNotFound


def missing_required_lib(library, reason=None, url=None):
    hostname = platform.node()
    msg = "Failed to import the required Python library (%s) on %s's Python %s." % (library, hostname, sys.executable)
    if reason:
        msg += " This is required %s." % reason
    if url:
        msg += " See %s for more info." % url

    msg += (" Please read the module documentation and install it in the appropriate location."
            " If the required library is installed, but Ansible is using the wrong Python interpreter,"
            " please consult the documentation on ansible_python_interpreter")
    return msg


def get_module_path():
    return os.path.dirname(os.path.realpath(__file__))


class AnsibleFallbackNotFound(Exception):
    pass
