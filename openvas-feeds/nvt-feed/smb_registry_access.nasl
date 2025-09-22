# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10400");
  script_version("2025-04-16T05:39:43+0000");
  script_tag(name:"last_modification", value:"2025-04-16 05:39:43 +0000 (Wed, 16 Apr 2025)");
  script_tag(name:"creation_date", value:"2008-09-10 10:22:48 +0200 (Wed, 10 Sep 2008)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_category(ACT_GATHER_INFO);
  script_family("Windows");
  script_name("Check for Accessible Registry (Windows SMB Login)");
  script_copyright("Copyright (C) 2008 Greenbone AG");
  # Don't add a dependency to os_detection.nasl. This will cause a dependency cycle.
  script_dependencies("netbios_name_get.nasl", "smb_login.nasl", "smb_nativelanman.nasl",
                      "gb_windows_services_start.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/transport", "SMB/name", "SMB/login", "SMB/password");
  script_exclude_keys("SMB/samba");

  script_xref(name:"URL", value:"https://docs.greenbone.net/GSM-Manual/gos-22.04/en/scanning.html#requirements-on-target-systems-with-microsoft-windows");

  script_tag(name:"summary", value:"This routine checks if the registry can be accessed remotely via
  SMB using the provided login/password credentials. If the access is failing a warning is shown.");

  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("smb_nt.inc");
include("host_details.inc");

if( kb_smb_is_samba() )
  exit( 0 );

port = kb_smb_transport();
if( ! port )
  port = 139;

if( ! get_port_state( port ) )
  exit( 0 );

if( ! name = kb_smb_name() )
  exit( 0 );

login = kb_smb_login();
pass  = kb_smb_password();
dom   = kb_smb_domain();

if( ! soc = open_sock_tcp( port ) )
  exit( 0 );

if( ! get_kb_item( "login/SMB/kerberos/success" ) ) {
  info = smb_login_and_get_tid_uid( soc:soc, name:name, login:login, passwd:pass, domain:dom, share:"IPC$" );
} else {
  kdc = kb_smb_kdc();
  host = kb_smb_hostname();
  info = smb_login_and_get_tid_uid( soc:soc, name:name, login:login, passwd:pass, domain:dom, share:"IPC$", kdc:kdc, host:host );
}

if( isnull( info ) ) {
  close( soc );
  exit( 0 );
}

uid = info["uid"];
tid = info["tid"];

message = 'It was not possible to connect to the PIPE\\winreg on the remote host. If you intend to use the Scanner to ' +
          'perform registry-based checks, the registry checks will not work because the \'Remote ' +
          'Registry\' service is not running or has been disabled on the remote host.' +
          '\n\nPlease either:\n' +
          '\n- configure the \'Startup Type\' of the \'Remote Registry\' service on the target host to \'Automatic\'.';

startErrors = get_kb_list( "RemoteRegistry/Win/Service/Manual/Failed" );
if( startErrors ) {
  message += '\n- check the below error which might provide additional info.';
  message += '\n\nThe scanner tried to start the \'Remote Registry\' service but received the following errors:\n';
  foreach startError( startErrors ) {
    # Clean-up the logs from the wmiexec.py before reporting it to the end user
    _startError = ereg_replace( string:startError, pattern:".*Impacket.*Core Security Technologies", replace:"" );
    # but only exchange the text if the string is not empty afterwards...
    if( _startError )
      startError = _startError;
    message += startError + '\n';
  }
}

message = chomp( message );

r = smbntcreatex( soc:soc, uid:uid, tid:tid, name:"\winreg" );
if( ! r ) {
  sleep( 3 ); # Makes sure that the service has enough time to start after the first request.
  # Second try as the remote service is not running after the first request if it
  # has the "Automatic (Trigger Start)" Startup Type set and the service wasn't running yet.
  r = smbntcreatex( soc:soc, uid:uid, tid:tid, name:"\winreg" );
  if( ! r ) {
    # Saved for later use in gb_authenticated_scan_lsc_smb_login_consolidation.nasl
    set_kb_item( name:"SMB/registry_access/error", value:message );
    log_message( port:0, data:message );
    close( soc );
    exit( 0 );
  }
}

pipe = smbntcreatex_extract_pipe( reply:r );
if( ! pipe ) {
  close( soc );
  exit( 0 );
}

r = pipe_accessible_registry( soc:soc, uid:uid, tid:tid, pipe:pipe );
close( soc );

if( ! r ) {
  # Saved for later use in gb_authenticated_scan_lsc_smb_login_consolidation.nasl
  set_kb_item( name:"SMB/registry_access/error", value:message );
  log_message( port:0, data:message );
} else {
  set_kb_item( name:"SMB/registry_access", value:TRUE );
  set_kb_item( name:"SMB_or_WMI/access_successful", value:TRUE );
}

exit( 0 );
