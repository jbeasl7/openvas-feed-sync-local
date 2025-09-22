# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114875");
  script_version("2024-12-06T15:41:14+0000");
  script_tag(name:"last_modification", value:"2024-12-06 15:41:14 +0000 (Fri, 06 Dec 2024)");
  script_tag(name:"creation_date", value:"2024-12-05 12:04:10 +0000 (Thu, 05 Dec 2024)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Jenkins CLI Subsystem Service Detection (TCP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Service detection");
  script_dependencies("find_service.nasl", "find_service6.nasl");
  script_require_ports("Services/jenkins_cli", 50000);

  script_tag(name:"summary", value:"TCP based detection of services supporting the Jenkins CLI
  subsystem.");

  # nb: While there is a redirect to a new documentation page the archive.org link here is expected
  # as newer Jenkins versions are not using this anymore and thus the new documentation doesn't
  # include the "old" Jenkins CLI version used here.
  script_xref(name:"URL", value:"https://web.archive.org/web/20220519152657/https://wiki.jenkins.io/display/JENKINS/Jenkins+CLI");

  exit(0);
}

include("host_details.inc");
include("port_service_func.inc");
include("byte_func.inc");

port = service_get_port( default:50000, proto:"jenkins_cli" );

# nb:
# - This was used initially in 2016/gb_jenkins_cli_rmi_java_deserialization_vulnerability.nasl
#   as a "full" raw_string()
# - Depending on the type/port we need to either use "CLI-connect" or "CLI2-connect"
# - Info has been collected by using jenkins-cli.jar against a "live" system
# - It seems jenkins-cli.jar is also able to extract the remote version but the used command
#   is unknown so far / wasn't able to be determined
# - First bytes in the request are the length of the following command
#
cmds = make_list(
  "Protocol:CLI-connect",
  "Protocol:CLI2-connect"
);

foreach cmd( cmds ) {

  if( ! soc = open_sock_tcp( port ) )
    continue;

  cmd_len = strlen( cmd );
  req = mkword( cmd_len ) + cmd;

  send( socket:soc, data:req );
  res = recv( socket:soc, length:512 );

  close( soc );

  # nb: Some trailing spaces are included
  res = chomp( res );

  if( ! res )
    continue;

  if( "JENKINS REMOTING CAPACITY" >!< res ) {
    unknown_banner_set( port:port, banner:res, set_oid_based:TRUE );
    continue;
  }

  version = "unknown";

  set_kb_item( name:"jenkins/detected", value:TRUE );
  set_kb_item( name:"jenkins/jenkins_cli/detected", value:TRUE );
  set_kb_item( name:"jenkins/jenkins_cli/tcp/detected", value:TRUE );
  set_kb_item( name:"jenkins/jenkins_cli/port", value:port );
  set_kb_item( name:"jenkins/jenkins_cli/" + port + "/version", value:version );
  set_kb_item( name:"jenkins/jenkins_cli/" + port + "/concluded", value:res );

  service_register( port:port, proto:"jenkins_cli" );

  report = "A Jenkins CLI subsystem service is running at this port.";
  report += '\n\nResponse:\n\n' + res;

  log_message( port:port, data:report );

  break; # nb: No need to run both commands if one was successful
}

exit( 0 );
