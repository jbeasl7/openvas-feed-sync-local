# SPDX-FileCopyrightText: 2005 SecuriTeam
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10379");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_name("LCDproc server detection");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 SecuriTeam");
  script_family("Service detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/unknown", 13666);

  script_tag(name:"summary", value:"LCDproc is a system that is used to display system information and other data
  on an LCD display (or any supported display device, including curses or text).");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("port_service_func.inc");

port = unknownservice_get_port( default:13666 );

soc = open_sock_tcp( port );

if( soc ) {
  req = string( "hello" );

  send(socket:soc, data:req);
  result = recv(socket:soc, length:4096);

  if( "connect LCDproc" >< result ) {
    resultrecv = strstr( result, "connect LCDproc " );
    resultsub = strstr( resultrecv, string( "lcd " ) );
    resultrecv = resultrecv - resultsub;
    resultrecv = resultrecv - "connect LCDproc ";
    resultrecv = resultrecv - "lcd ";

    banner = "LCDproc (";
    banner = banner + resultrecv;
    banner = banner + ') was found running on the target.\n';

    set_kb_item( name:"lcdproc/detected", value:TRUE );
    service_register( port:port, proto:"lcdproc" );
    log_message( port:port, data:banner );
    exit( 0 );
  }
}

exit( 0 );
