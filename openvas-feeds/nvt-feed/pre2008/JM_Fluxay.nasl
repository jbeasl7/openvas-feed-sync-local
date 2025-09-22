# SPDX-FileCopyrightText: 2005 J.Mlødzianøwski
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11880");
  script_version("2023-10-12T05:05:32+0000");
  script_tag(name:"last_modification", value:"2023-10-12 05:05:32 +0000 (Thu, 12 Oct 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Fluxay Sensor Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 J.Mlødzianøwski");
  script_family("Malware");
  script_dependencies("find_service2.nasl");
  script_require_ports("Services/fluxay");

  script_xref(name:"URL", value:"http://www.rapter.net/jm3.htm");

  script_tag(name:"solution", value:"See the references for details on the removal.");
  script_tag(name:"summary", value:"This host appears to be running Fluxay Sensor on this port.

  Fluxay Sensor is a Backdoor which allows an intruder gain
  remote access to files on your computer. Similar to SubSeven
  This program is installs as a Service and is password protected.
  It protects itself so it is difficult to stop or remove.");
  script_tag(name:"impact", value:"An attacker may use it to steal your passwords, or use this
  computer in other attacks.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("port_service_func.inc");

port = service_get_port( nodefault:TRUE, proto:"fluxay" );

if( port ) {
  security_message( port:port );
  exit( 0 );
}

exit( 99 );
