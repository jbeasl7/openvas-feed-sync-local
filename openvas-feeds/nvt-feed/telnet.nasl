# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100074");
  script_version("2023-07-28T16:09:08+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:08 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-03-24 15:43:44 +0100 (Tue, 24 Mar 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Telnet Service Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Service detection");
  script_dependencies("find_service6.nasl", "secpod_open_tcp_ports.nasl");
  # nb: The non-23 ports are from various Telnet-VTs, TCP/PORTS is used because find_service.nasl
  # is sometimes not reporting a Services/telnet at all (not even a Services/unknown) and we're
  # missing the Telnet Service detection.
  script_require_ports(23, 992, 1953, 2323, 5000, 9999, 41795, "TCP/PORTS");

  script_xref(name:"URL", value:"https://tools.ietf.org/html/rfc854");

  script_tag(name:"summary", value:"This scripts tries to detect a Telnet service running
  at the remote host.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("telnet_func.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("http_func.inc");
include("dump.inc");
include("misc_func.inc");

# nb: See the note on script_require_ports above...
default_ports = make_list(23, 992, 1953, 2323, 5000, 9999, 41795);
all_tcp_ports = tcp_get_all_ports();
if( all_tcp_ports )
  ports = make_list( default_ports, all_tcp_ports );
else
  ports = default_ports;

# nb: Using telnet_get_ports() here to always report the "A Telnet" message
# to be able to e.g. identify all Telnet Services by the OID of this VT.
telnet_ports = telnet_get_ports();
ports = make_list_unique( ports, telnet_ports );

unknown_ports = unknownservice_get_ports( nodefault:TRUE );
if( ! unknown_ports || ! is_array( unknown_ports ) )
  unknown_ports = make_list();

foreach port( ports ) {

  if( ! get_port_state( port ) )
    continue;

  # nb: We continue for already known services as long as
  # it is not Telnet.
 if( ! service_verify( port:port, proto:"telnet" ) &&
     ! service_is_unknown( port:port ) )
  continue;

  # nb: If its marked as "unknown" we mostly know that it isn't a Telnet service
  # but we also want to always check the default ports list from above because
  # nasl_builtin_find_service.c is currently only checking for the commands between
  # 251 and 254 where RFC 854 has defined them between 240 and 254.
  if( ! in_array( search:port, array:default_ports, part_match:FALSE ) &&
        in_array( search:port, array:unknown_ports, part_match:FALSE ) )
    continue;

  # nb: Try to open a socket two times for fragile Telnet services
  soc = open_sock_tcp( port );
  if( ! soc ) {
    sleep( 2 );
    soc = open_sock_tcp( port );
    if( ! soc )
      continue;
  }

  banner = "";
  max_retry  = 2;
  curr_retry = 0;
  while( TRUE ) {
    n++;
    res = recv( socket:soc, length:1, timeout:10 );
    if( ! res ) {
      if( curr_retry > max_retry )
        break;
      curr_retry++;
      continue;
    }
    banner += res;
    if( n > 50 ) # We don't need to grab more data...
      break;
  }

  close( soc );

  if( ! banner || strlen( banner ) < 3 )
    continue;

  if( ord( banner[0] ) != 255 || # nb: "Interpret as Command" (IAC) escape character
      ord( banner[1] ) < 240 || ord( banner[1] ) > 254 ) # nb: code for the command between 240 and 254
    continue;

  # nb: This is a workaround as these devices are often quite fragile and doesn't answer
  # to the telnet_get_banner() call of telnetserver_detect_type_nd_version.nasl anymore.
  if( "VxWorks login:" >< banner )
    telnet_set_banner( port:port, banner:bin2string( ddata:banner, noprint_replacement:" " ) );

  log_message( port:port, data:"A Telnet server seems to be running on this port" );
  if( service_is_unknown( port:port ) )
    service_register( port:port, proto:"telnet", message:"A Telnet server seems to be running on this port" );
}

exit( 0 );
