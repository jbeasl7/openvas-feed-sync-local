# SPDX-License-Identifier: GPL-2.0-only
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-FileCopyrightText: 2025 Greenbone AG

# @brief This OS detection retrieves all release information it needs itself to detect Huawei
#        openEuler. On a successful detection the relevant info is set into the KB key and reported
#        via @ref log_message() and @ref os_register_and_report().
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
#
function detect_openeuler( sock, port, SCRIPT_DESC, is_pfsense, _unknown_os_info ) {

  # nb: function parameters
  local_var sock, port, SCRIPT_DESC, is_pfsense, _unknown_os_info;

  # nb: variables from function body
  local_var has_ssh_error, cmd, rls, os, concluded, cpe_base, vers, version, cpe, buf, error;

  if( is_pfsense )
    return _unknown_os_info;

  has_ssh_error = FALSE;
  cmd = "cat /etc/os-release";
  rls = ssh_cmd( socket:sock, cmd:cmd, return_errors:FALSE );
  if( ! rls ) {
    # openEuler containers 20.03-lts/-sp1/-sp3 require return_errors:TRUE
    # because of the containers ssh login script calling missing binaries
    rls = ssh_cmd( socket:sock, cmd:cmd, return_errors:TRUE );
    has_ssh_error = TRUE;
  }

  if( ! rls || 'NAME="openEuler"' >!< rls ) {
    _unknown_os_info += cmd + ": " + rls + '\n\n';
    return _unknown_os_info;
  }

  set_kb_item( name:"ssh/login/openeuler", value:TRUE );
  set_kb_item( name:"ssh/login/euleros_eulerosvirtual_openeuler", value:TRUE );
  set_kb_item( name:"ssh/login/euleros_eulerosvirtual_openeuler_hce", value:TRUE );
  os = "openEuler";
  # format in advisories: openEuler-22.03-LTS-SP4

  concluded  = '\n  Used command: ' + cmd;
  concluded += '\n  Response:     ' + rls;

  # cpe from nist - differs from content of /etc/system-release-cpe
  # cpe:/o:openatom:openeuler:20.03:sp2:lts
  cpe_base = "cpe:/o:openatom:openeuler";

  # Version examples from /etc/os-release:
  # VERSION="22.03 LTS"
  # VERSION="22.03 (LTS-SP4)"
  # VERSION="23.03"
  # VERSION="24.03 (LTS)"
  vers = eregmatch( pattern:"VERSION="+'"'+"([0-9]{2}\.[0-9]{2}) ?\(?(LTS)?-?(SP[0-9])?", string:rls, icase:TRUE );
  if( vers[1] ) {
    # 22.03
    version = vers[1];
    # cpe:/o:openatom:openeuler:22.03
    cpe = cpe_base + ":" + vers[1];

    if( vers[2] ) {
      # 22.03 LTS
      version += " " + vers[2];
      # cpe:/o:openatom:openeuler:22.03:lts
      cpe += ":" + vers[2];
    }

    if( vers[3] ) {
      # 22.03 LTS SP4
      version += " " + vers[3];
      # cpe:/o:openatom:openeuler:22.03:sp4:lts
      cpe = cpe_base + ":" + vers[1] + ":" + vers[3] + ":" + vers[2];
    }

    cpe = tolower( cpe );

    # openEuler 22.03 LTS SP4
    os += " " + version;

    buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n'", return_errors:has_ssh_error );
    if( has_ssh_error ) {
      # ssh errors need to be removed from the packages, example errors:
      # /etc/profile.d/system-info.sh: line 52: /sbin/ip: No such file or directory
      # /etc/profile.d/system-info.sh: line 26: bc: command not found
      buf = ereg_replace( string:buf, pattern:'/etc/profile\\.d/system-info\\.sh:[^\n]*\n', replace:"", icase:FALSE );
    }
    if( buf ) {
      if( ! register_notus( os_release:os, pkg_list:buf, rpms:TRUE ) )
        error = buf;
    }

    log_message( port:port, data:create_lsc_os_detection_report( detect_text:os, rpm_access_error:error ) );
    os_register_and_report( os:os, version:version, cpe:cpe, banner_type:"SSH login", banner:concluded, desc:SCRIPT_DESC, runs_key:"unixoide", full_cpe:TRUE );
  } else {
    log_message( port:port, data:create_lsc_os_detection_report( detect_text:os, rpm_access_error:error ) );
    os_register_and_report( os:os, cpe:cpe_base, banner_type:"SSH login", banner:concluded, desc:SCRIPT_DESC, runs_key:"unixoide" );
  }

  exit( 0 );
}
