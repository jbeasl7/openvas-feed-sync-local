# SPDX-FileCopyrightText: 2005 Scott Shebby
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14687");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_name("psyBNC Server Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 Scott Shebby");
  script_family("Malware");
  script_dependencies("find_service2.nasl");
  script_require_ports("Services/psyBNC");

  script_xref(name:"URL", value:"http://www.psybnc.info/about.html");
  script_xref(name:"URL", value:"http://www.psychoid.net/start.html");

  script_tag(name:"solution", value:"Make sure the presence of this service is intended.");

  script_tag(name:"summary", value:"The remote host appears to be running psyBNC on this port.");

  script_tag(name:"impact", value:"The presence of this service indicates a high possibility that your server has been
  compromised by a remote attacker. The only sure fix is to reinstall from scratch.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("port_service_func.inc");

port = service_get_port( nodefault:TRUE, proto:"psyBNC" );

if( port ) {
  security_message( port:port );
  exit( 0 );
}

exit( 99 );
