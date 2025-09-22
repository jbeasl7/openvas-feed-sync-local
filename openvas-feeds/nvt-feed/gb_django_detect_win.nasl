# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113345");
  script_version("2025-02-04T05:37:53+0000");
  script_tag(name:"last_modification", value:"2025-02-04 05:37:53 +0000 (Tue, 04 Feb 2025)");
  script_tag(name:"creation_date", value:"2019-02-27 10:15:22 +0100 (Wed, 27 Feb 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"package");

  script_name("Django Detection (Windows SMB Login)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl", "gb_wmi_access.nasl", "lsc_options.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion", "WMI/access_successful");
  script_exclude_keys("win/lsc/disable_win_cmd_exec");

  script_tag(name:"summary", value:"SMB login-based detection of Django.");

  script_xref(name:"URL", value:"https://www.djangoproject.com/");

  exit(0);
}

CPE = "cpe:/a:djangoproject:django:";

include( "host_details.inc" );
include( "smb_nt.inc" );
include( "cpe.inc" );
include( "win_cmd_func.inc" );

if( ! defined_func( "win_cmd_exec" ) )
  exit( 0 );

if( get_kb_item( "win/lsc/disable_win_cmd_exec" ) )
  exit( 0 );

function run_command( command ) {

  local_var command;
  local_var serQueryRes;

  serQueryRes = win_run_cmd( cmd: command );

  if( "Access is denied" >< serQueryRes ) {
    return;
  } else if( "The specified service does not exist" >< serQueryRes ) {
    return;
  } else if( "The service cannot be started" >< serQueryRes && "it is disabled" >< serQueryRes ) {
    return;
  } else if( "OpenService FAILED" >< serQueryRes && "specified service does not exist" >< serQueryRes ) {
    return;
  } else if( "StartService FAILED" >< serQueryRes ) {
    return;
  } else if( "An instance of the service is already running" >< serQueryRes ) {
    return;
  } else {
    return serQueryRes;
  }
}

cmd = "cmd /c django-admin --version";
result = run_command( command: cmd );
if( isnull( result ) || result =~ "not recognized" || result =~ "not found" )
  exit( 0 );

ver = eregmatch( string: result, pattern: '[0-9.]+' );
if( isnull( ver[0] ) )
  exit( 0 );

set_kb_item( name: "django/windows/detected", value: TRUE );
register_and_report_cpe( app: "Django",
                         ver: ver[0],
                         concluded: ver[0],
                         base: CPE,
                         expr: "([0-9.]+)",
                         regPort: 0,
                         regService: "smb-login" );
exit( 0 );
