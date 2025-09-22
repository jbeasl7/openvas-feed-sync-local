# SPDX-FileCopyrightText: 2005 Patrick Naubert
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10342");
  script_version("2025-03-19T05:38:35+0000");
  script_tag(name:"last_modification", value:"2025-03-19 05:38:35 +0000 (Wed, 19 Mar 2025)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("VNC Server and Protocol Version Detection (TCP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 Patrick Naubert");
  script_family("Service detection");
  script_dependencies("find_service2.nasl");
  script_require_ports("Services/vnc", 5900, 5901, 5902);

  script_xref(name:"URL", value:"https://datatracker.ietf.org/doc/html/rfc6143");
  script_xref(name:"URL", value:"https://datatracker.ietf.org/doc/html/rfc7869");

  script_tag(name:"summary", value:"TCP based detection of Virtual Network Computing (VNC) services
  and the underlying Remote Framebuffer Protocol (RFB) version.");

  script_tag(name:"insight", value:"The remote host is running a remote display software (VNC) which
  permits a console to be displayed remotely.

  This allows authenticated users of the remote host to take its control remotely.");

  script_tag(name:"solution", value:"Make sure the use of this software is done in accordance with
  your corporate security policy, filter incoming traffic to this port.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("port_service_func.inc");

report = "A VNC server seems to be running on this port.";

ports = service_get_ports( default_port_list:make_list( 5900, 5901, 5902 ), proto:"vnc" );
foreach port ( ports ) {
  soc = open_sock_tcp( port );
  if( soc ) {

    send( socket:soc, data:"TEST\r\n" );

    buf = recv( socket:soc, length:4096 );
    close( soc );

    if( ereg( pattern:"^RFB [0-9]", string:buf ) ) {
      set_kb_item( name:"vnc/detected", value:TRUE );
      replace_kb_item( name:"vnc/banner/" + port , value:buf );
      version = egrep( pattern:"^RFB 00[0-9]\.00[0-9]", string:buf );
      if( version ) {
        ver_report = '\n\nThe version of the VNC protocol is : ' + version;
      }
      log_message( port:port, data:report + ver_report );
      service_register( port:port, proto:"vnc", message:report + ver_report );
    }
  }
}

exit( 0 );
