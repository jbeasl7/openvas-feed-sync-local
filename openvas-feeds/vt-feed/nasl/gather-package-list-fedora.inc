# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# @brief This OS detection retrieves all release information it needs itself to detect Fedora.
#        On a successful detection the relevant info is set into the KB key and reported via
#        @ref log_message() and @ref os_register_and_report().
#
# @note It should be included in the appropriate section of gather-package-list.nasl with
#       `include("<this_files_name>")`.
#
# @note The OS detection method should be called also at the appropriate section in
#       gather-package-list.nasl.
#
# @param sock             The opened socket for the connection to the remote SSH service.
# @param port             The port for the connection to the remote SSH service.
# @param SCRIPT_DESC      The script name of the "caller" (defined within the caller itself)
# @param is_pfsense       Should be set to TRUE if the target is running pfSense as this requires
#                         some special handling.
# @param _unknown_os_info The "_unknown_os_info" variable filled in by the caller
#
# @return This function is either exiting directly on a successful detection or is returning the
#         info passed via the _unknown_os_info variable.

function detect_fedora( sock, port, SCRIPT_DESC, is_pfsense, _unknown_os_info ) {

  # nb: function parameters
  local_var sock, port, SCRIPT_DESC, is_pfsense, _unknown_os_info;

  # nb: variables from function body
  local_var cmd, rls, vers, oskey, notusoskey, cpe, os, buf, error, active_kernel_version, possible_kernel_packages;

  if( is_pfsense )
    return _unknown_os_info;

  cmd = "cat /etc/redhat-release";
  rls = ssh_cmd( socket:sock, cmd:cmd, return_errors:FALSE );

  if( rls =~ "fedora" && rls =~ "release" ) {
    oskey = "FC";
    notusoskey = "Fedora";
    if( rls =~ "fedora core" ) {
        cpe = "cpe:/o:fedoraproject:fedora_core";
        set_kb_item( name:"ssh/login/fedora_core", value:TRUE );
        os = "Fedora Core";
    } else {
        cpe = "cpe:/o:fedoraproject:fedora";
        set_kb_item( name:"ssh/login/fedora", value:TRUE );
        os = "Fedora";
    }

    buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'" );
    if( buf ) {
        if( ! register_rpms( buf:";" + buf ) )
            error = buf;
    }

    vers = eregmatch( pattern:"fedora( core | )release ([0-9]+)", string:rls, icase:TRUE );
    if( vers[2] ) {
        cpe += ":" + vers[2];
        oskey += vers[2];
        notusoskey += " " + vers[2];

        buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}-%{EVR}.%{ARCH}\n'" );
        if( buf ) {
            active_kernel_version = ssh_cmd( socket:sock, cmd:"uname -r" );
            possible_kernel_packages = make_list(
                # 43, 44 & 45
                "kernel", "kernel-core",
                "kernel-debug", "kernel-debug-core", "kernel-debug-devel",
                "kernel-debug-modules", "kernel-debug-modules-core", "kernel-debug-modules-extra", "kernel-debug-modules-internal",
                "kernel-debug-uki-virt", "kernel-debug-uki-virt-addons",
                "kernel-devel",
                "kernel-modules", "kernel-modules-core", "kernel-modules-extra", "kernel-modules-internal",
                "kernel-uki-virt", "kernel-uki-virt-addons"
            );
            buf = rpm_remove_inactive_kernels( rpm_buf:buf, active_kernel_version:active_kernel_version, possible_kernel_packages:possible_kernel_packages );

            if( ! register_notus( os_release:notusoskey, pkg_list:buf, rpms:TRUE ) )
                error = buf;
        }

        log_message( port:port, data:create_lsc_os_detection_report( detect_text:os + " release " + vers[2], rpm_access_error:error ) );
        os_register_and_report( os:os, version:vers[2], cpe:cpe, banner_type:"SSH login", desc:SCRIPT_DESC, runs_key:"unixoide", full_cpe:TRUE );
    } else {
        log_message( port:port, data:create_lsc_os_detection_report( detect_text:os, rpm_access_error:error ) );
        os_register_and_report( os:os, cpe:cpe, banner_type:"SSH login", desc:SCRIPT_DESC, runs_key:"unixoide" );
    }
    set_kb_item( name:"ssh/login/release", value:oskey );

    exit( 0 );
    }
}
