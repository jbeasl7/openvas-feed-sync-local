# SPDX-FileCopyrightText: 2005 J.Mlodzianowski
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.15405");
  script_version("2023-06-27T05:05:30+0000");
  script_tag(name:"last_modification", value:"2023-06-27 05:05:30 +0000 (Tue, 27 Jun 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("URCS Server Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 J.Mlodzianowski");
  script_family("Malware");
  script_dependencies("find_service2.nasl");
  script_require_ports("Services/unknown", 3360);

  script_xref(name:"URL", value:"http://urcs.unmanarc.com");
  script_xref(name:"URL", value:"http://securityresponse.symantec.com/avcenter/venc/data/backdoor.urcs.html");
  script_xref(name:"URL", value:"http://www.rapter.net/jm5.htm");

  script_tag(name:"solution", value:"See the references for more information.");

  script_tag(name:"impact", value:"An attacker may use it to steal files, passwords, or redirect ports on the
  remote system to launch other attacks.");

  script_tag(name:"summary", value:"This host appears to be running URCS Server. Unmanarc Remote Control Server
  can be used/installed silent as a 'backdoor' which may allow an intruder to gain remote access to files on
  the remote system. If this program was not installed for remote management then it means the remote host has
  been compromised.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_active");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");
include("port_service_func.inc");

# Default port for URCS Server is 3360
# Default port for URCS Client is 1980
port = unknownservice_get_port( default:3360 );

soc = open_sock_tcp( port );
if( soc ) {
  send( socket:soc, data:'iux' );
  r = recv( socket:soc, length:817 );
  if( "$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$" >< r ) {
    security_message( port:port );
    close( soc );
    exit( 0 );
  }
  close( soc );
}

exit( 99 );
