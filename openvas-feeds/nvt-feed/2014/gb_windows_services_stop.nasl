# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804787");
  script_version("2025-02-04T05:37:53+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-02-04 05:37:53 +0000 (Tue, 04 Feb 2025)");
  script_tag(name:"creation_date", value:"2014-11-05 11:50:33 +0530 (Wed, 05 Nov 2014)");
  script_name("Windows Services Stop");
  # nb: Needs to run at the end of the scan because the services shouldn't be stopped before...
  script_category(ACT_END);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Windows");
  script_mandatory_keys("RemoteRegistry/Win/Service/Manual/Start");
  script_require_ports(139, 445);
  script_exclude_keys("win/lsc/disable_win_cmd_exec");

  script_tag(name:"summary", value:"If the Windows services got started manually by a VT then stop
  those services at the end of a scan.");

  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("smb_nt.inc");
include("win_cmd_func.inc");

if( ! defined_func( "win_cmd_exec" ) ) exit( 0 );

if( get_kb_item( "win/lsc/disable_win_cmd_exec" ) ) exit( 0 );

function run_command( command ) {

  local_var command, serQueryRes, serStat;

  ## Run the Command and get the Response
  serQueryRes = win_run_cmd( cmd:command );

  if( "Access is denied" >< serQueryRes ) {
    error_message( data:"SC Command Error: Access is denied." );
  }
  else if( "The specified service does not exist" >< serQueryRes ) {
    error_message( data:"SC Command Error: The specified service does not exist." );
  }
  else if( "The service cannot be started" >< serQueryRes && "it is disabled" >< serQueryRes ) {
    error_message( data:"SC Command Error: Unable to start the service, maybe it is set to 'Disabled'." );
  }
  else if( "OpenService FAILED" >< serQueryRes && "specified service does not exist" >< serQueryRes ) {
    error_message( data:"SC Command Error: The Specified Service does not Exit." );
  }
  else if( "StartService FAILED" >< serQueryRes ) {
    error_message( data:"SC Command Error: Failed to start the service." );
  }
  else if( "An instance of the service is already running" >< serQueryRes ) {
    error_message( data:"SC Command Error: An instance of the service is already running." );
  }
  else {
    if( "SERVICE_NAME" >< serQueryRes && "STATE" >< serQueryRes && "SERVICE_EXIT_CODE" >< serQueryRes ) {
      serStat = eregmatch( pattern:"STATE.*: [0-9]  ([a-zA-Z_]+)", string:serQueryRes );
      return serStat[1];
    }
  }
}

service_kb_list = get_kb_list( "*/Win/Service/Manual/Start" );
if( ! service_kb_list ) exit( 0 );

foreach service_kb( keys( service_kb_list ) ) {

  service = split( service_kb, sep:"/", keep:FALSE );

  if( service[0] ) {

    ## To get the status of the service
    cmd = "cmd /c sc query " + service[0];
    serQueryStat = run_command( command:cmd );

    if( "RUNNING" >< serQueryStat ) {
      ## To stop the service
      cmd = "cmd /c sc stop " + service[0];
      serQueryStat = run_command( command:cmd );

      if( "STOP_PENDING" >< serQueryStat ) {
        ## To get the status of the service
        cmd = "cmd /c sc query " + service[0];
        serQueryStat = run_command( command:cmd );

        if( "STOPPED" >!< serQueryStat ) {
          error_message( data:"SC Command Error: Failed to stop the service: " + service[0] );
        }
      }
    }
  }
}

exit( 0 );
