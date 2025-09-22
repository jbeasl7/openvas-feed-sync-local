# SPDX-License-Identifier: GPL-2.0-only
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-FileCopyrightText: 2025 Greenbone AG

# @brief This OS detection retrieves all release information it needs itself to detect Rocky Linux.
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
#
function detect_rockylinux( sock, port, SCRIPT_DESC, is_pfsense, _unknown_os_info ) {

  # nb: function parameters
  local_var sock, port, SCRIPT_DESC, is_pfsense, _unknown_os_info;

  # nb: variables from function body
  local_var cmd, rls, oskey, os, notusoskey, concluded, cpe, buf, vers, version;

  if( is_pfsense )
    return _unknown_os_info;

  # The way ahead looks Rocky...
  cmd = "cat /etc/rocky-release";
  rls = ssh_cmd( socket:sock, cmd:cmd, return_errors:FALSE );

  # Rocky Linux release 8.4 (Green Obsidian)
  # Rocky Linux release 8.5 (Green Obsidian)
  if( ! rls || rls !~ "Rocky Linux release" ) {
    _unknown_os_info += cmd + ": " + rls + '\n\n';
    return _unknown_os_info;
  }

  oskey = "RL";
  os = "Rocky Linux";
  notusoskey = "Rocky Linux";
  concluded  = '\n  Used command: ' + cmd;
  concluded += '\n  Response:     ' + rls;

  # Used by the project in /etc/rocky-release but probably should be updated if a different CPE is
  # used within the NVD.
  cpe = "cpe:/o:rocky:rocky";

  set_kb_item( name:"ssh/login/rocky_linux", value:TRUE );

  buf = ssh_cmd( socket:sock, cmd:"rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'" );
  if( buf ) {
    if( ! register_rpms( buf:";" + buf ) )
      error = buf;
  }

  vers = eregmatch( pattern:"Rocky Linux release ([0-9]+)([0-9.]+)?", string:rls, icase:TRUE );
  if( vers[1] ) {

    version = vers[1];

    if( vers[2] )
      version += vers[2];

    cpe += ":" + version;

    # As of original implementation, Rocky Linux reports as version '8.4' or '8.5' in
    # '/etc/rocky-release'. Their advisories currently only report product 'Rocky Linux 8' so we
    # will stick with the major version in the oskey like e.g. RL8 (instead of RL8.5) for now.
    oskey += vers[1];
    # Notus scanner requires the release_notus key set further down, which needs to be exactly
    # matched against the product_name in notus product files,
    # which for Rocky requires "Rocky Linux <release>"
    notusoskey = os + " " + vers[1];

    buf = ssh_cmd( socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}-%{EVR}.%{ARCH}\n'" );
    if( buf ) {
      if( ! register_notus( os_release:notusoskey, pkg_list:buf, rpms:TRUE ) )
        error = buf;
    }

    log_message( port:port, data:create_lsc_os_detection_report( detect_text:os + " " + version, rpm_access_error:error ) );
    os_register_and_report( os:os, version:version, cpe:cpe, banner_type:"SSH login", banner:concluded, desc:SCRIPT_DESC, runs_key:"unixoide", full_cpe:TRUE );
  } else {
    log_message( port:port, data:create_lsc_os_detection_report( detect_text:os, rpm_access_error:error ) );
    os_register_and_report( os:os, cpe:cpe, banner_type:"SSH login", banner:concluded, desc:SCRIPT_DESC, runs_key:"unixoide" );
  }

  set_kb_item( name:"ssh/login/release", value:oskey );

  exit( 0 );
}
