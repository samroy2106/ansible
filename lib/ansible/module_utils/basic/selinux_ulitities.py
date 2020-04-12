'''Subclass to AnsibleModule class to use selinuc ulitily functions when required.
   These utility functions provide extendended capabilities to some out-of-the-box
   selinux package functions as well as some new utilities.'''
from ansible.module_utils.basic import AnsibleModule

class selinux_utilities(AnsibleModule):

    # Detect whether using selinux that is MLS-aware.
    # While this means you can set the level/range with
    # selinux.lsetfilecon(), it may or may not mean that you
    # will get the selevel as part of the context returned
    # by selinux.lgetfilecon().

    def selinux_mls_enabled(AnsibleModule):
        if not HAVE_SELINUX:
            return False
        if selinux.is_selinux_mls_enabled() == 1:
            return True
        else:
            return False

    def selinux_enabled(AnsibleModule):
        if not HAVE_SELINUX:
            seenabled = AnsibleModule.get_bin_path('selinuxenabled')
            if seenabled is not None:
                (rc, out, err) = AnsibleModule.run_command(seenabled)
                if rc == 0:
                    AnsibleModule.fail_json(msg="Aborting, target uses selinux but python bindings (libselinux-python) aren't installed!")
            return False
        if selinux.is_selinux_enabled() == 1:
            return True
        else:
            return False

    # Determine whether we need a placeholder for selevel/mls
    def selinux_initial_context(AnsibleModule):
        context = [None, None, None]
        if AnsibleModule.selinux_mls_enabled():
            context.append(None)
        return context

    # If selinux fails to find a default, return an array of None
    def selinux_default_context(AnsibleModule, path, mode=0):
        context = AnsibleModule.selinux_initial_context()
        if not HAVE_SELINUX or not AnsibleModule.selinux_enabled():
            return context
        try:
            ret = selinux.matchpathcon(to_native(path, errors='surrogate_or_strict'), mode)
        except OSError:
            return context
        if ret[0] == -1:
            return context
        # Limit split to 4 because the selevel, the last in the list,
        # may contain ':' characters
        context = ret[1].split(':', 3)
        return context

    def selinux_context(AnsibleModule, path):
        context = AnsibleModule.selinux_initial_context()
        if not HAVE_SELINUX or not AnsibleModule.selinux_enabled():
            return context
        try:
            ret = selinux.lgetfilecon_raw(to_native(path, errors='surrogate_or_strict'))
        except OSError as e:
            if e.errno == errno.ENOENT:
                AnsibleModule.fail_json(path=path, msg='path %s does not exist' % path)
            else:
                AnsibleModule.fail_json(path=path, msg='failed to retrieve selinux context')
        if ret[0] == -1:
            return context
        # Limit split to 4 because the selevel, the last in the list,
        # may contain ':' characters
        context = ret[1].split(':', 3)
        return context


    def is_special_selinux_path(AnsibleModule, path):
        """
        Returns a tuple containing (True, selinux_context) if the given path is on a
        NFS or other 'special' fs  mount point, otherwise the return will be (False, None).
        """
        try:
            f = open('/proc/mounts', 'r')
            mount_data = f.readlines()
            f.close()
        except Exception:
            return (False, None)
        path_mount_point = AnsibleModule.find_mount_point(path)
        for line in mount_data:
            (device, mount_point, fstype, options, rest) = line.split(' ', 4)

            if path_mount_point == mount_point:
                for fs in AnsibleModule._selinux_special_fs:
                    if fs in fstype:
                        special_context = AnsibleModule.selinux_context(path_mount_point)
                        return (True, special_context)

        return (False, None)

    def set_default_selinux_context(AnsibleModule, path, changed):
        if not HAVE_SELINUX or not AnsibleModule.selinux_enabled():
            return changed
        context = AnsibleModule.selinux_default_context(path)
        return AnsibleModule.set_context_if_different(path, context, False)
