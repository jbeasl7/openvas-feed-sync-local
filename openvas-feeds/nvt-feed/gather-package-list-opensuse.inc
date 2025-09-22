# SPDX-License-Identifier: GPL-2.0-only
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-FileCopyrightText: 2025 Greenbone AG

# @brief This OS detection retrieves all release information it needs itself to detect openSUSE. On
#        a successful detection the relevant info is set into the KB key and reported via
#        @ref log_message() and @ref os_register_and_report().
#
# @note It should be included in the appropriate section of gather-package-list.nasl with
#       `include("<this_files_name>")`.
#
# @note The OS detection method should be called also at the appropriate section in
#       gather-package-list.nasl.
#
# @note Supported OS versions: openSUSE Leap 15.0 to openSUSE Leap 15.6, openSUSE Tumbleweed
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
#
function detect_opensuse( sock, port, SCRIPT_DESC, is_pfsense, _unknown_os_info ) {

  # nb: function parameters
  local_var sock, port, SCRIPT_DESC, is_pfsense, _unknown_os_info;

  # nb: variables from function body
  local_var cmd, rls, oskey, concluded, notusoskey, cpe, os, vers, kb_item_release, buf, error;

  if( is_pfsense )
    return _unknown_os_info;

  cmd = "cat /etc/os-release";
  rls = ssh_cmd( socket:sock, cmd:cmd, return_errors:FALSE );
  oskey = "openSUSE";

  if( ! rls || rls !~ 'NAME="openSUSE (Leap|Tumbleweed)"' ) {
    _unknown_os_info += cmd + ": " + rls + '\n\n';
    return _unknown_os_info;
  }

  concluded  = '\n  Used command: ' + cmd;
  concluded += '\n  Response:     ' + rls;

  if( rls =~ 'NAME="openSUSE (Leap|Tumbleweed)"' ) {

    set_kb_item( name:"ssh/login/opensuse", value:TRUE );

    # ssh/login/opensuse should be the default, but suse is also accepted
    set_kb_item( name:"ssh/login/suse", value:TRUE );

    if( rls =~ 'NAME="openSUSE Leap"' ) {
      notusoskey = "openSUSE Leap ";
      cpe = "cpe:/o:opensuse:leap";
      os = "openSUSE Leap";
      oskey += "Leap";

      vers = eregmatch( pattern:'VERSION_ID="([0-9.]+)"', string:rls, icase:TRUE );

      if( vers[1] ) {
        cpe += ":" + vers[1];
        notusoskey += vers[1];
        kb_item_release = "openSUSELeap" + vers[1];

        set_kb_item( name:"ssh/login/release", value:kb_item_release );

      } else {
        # nb: In case, an unknown/unsupported format is detected
        oskey += " Unknown Release";
        cpe += "_unknown_release";
      }
    } else if( rls =~ 'NAME="openSUSE Tumbleweed"' ) {
      notusoskey = "openSUSE Tumbleweed";
      oskey += "Tumbleweed";
      cpe = "cpe:/o:opensuse:tumbleweed";
      os = "openSUSE Tumbleweed";
    }

    buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'" );
    if( buf ) {
      if( ! register_rpms( buf:";" + buf ) )
        error = buf;
    }

    buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n'" );
    if( buf ) {
      if( ! register_notus( os_release:notusoskey, pkg_list:buf, rpms:TRUE ) )
        error = buf;
    }

    log_message( port:port, data:create_lsc_os_detection_report( rpm_access_error:error, detect_text:oskey ) );
    os_register_and_report( os:oskey, cpe:cpe, banner_type:"SSH login", banner:concluded, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else {
    log_message( port:port, data:create_lsc_os_detection_report( detect_text:os, rpm_access_error:error ) );
    os_register_and_report( os:os, cpe:cpe, banner_type:"SSH login", banner:concluded, desc:SCRIPT_DESC, runs_key:"unixoide" );
  }

  exit( 0 );
}
