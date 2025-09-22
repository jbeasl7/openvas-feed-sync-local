# SPDX-FileCopyrightText: 2005 StrongHoldNet
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113757");
  script_version("2025-01-17T15:39:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 15:39:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  # nb: It seems the discard service can get falsely detected due to e.g. SonicWall firewalls
  # activity, in some cases
  script_tag(name:"qod_type", value:"remote_analysis");

  script_name("discard Service Detection (TCP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2005 StrongHoldNet");
  script_family("Product detection");
  script_dependencies("find_service.nasl");
  script_require_ports(9);

  script_tag(name:"summary", value:"Checks whether the discard service is running
  on the target host.");

  script_tag(name:"insight", value:"The discard service sets up a listening socket
  and then ignores all data it receives.

  Notes:

  Some firewall devices are known to discard packets on the checked port 9/tcp or mimic such a
  service via other means. Scanning through a firewall should be generally avoided (Please see
  references).

  If the target was scanned through a firewall and it was determined / has been verified that no
  such service is running on the target please either:

  - create an override for this result

  - configure the firewall in a way that port 9/tcp is not reported as being open during the port
  scanning phase / it is not allowed to open a TCP connection to port 9/tcp on the target");

  script_xref(name:"URL", value:"https://datatracker.ietf.org/doc/html/rfc863");
  script_xref(name:"URL", value:"https://docs.greenbone.net/GSM-Manual/gos-22.04/en/read-before-use.html#scanning-through-network-equipment");

  exit(0);
}

include("host_details.inc");
include("port_service_func.inc");

port = 9; # nb: Discard is not supposed to run on any other port.
if( ! service_is_unknown( port: port ) )
  exit( 0 );

# nb: We send between 17 and 210 bytes of random data.
# If the service is still listening without any output, we assume
# that 9/tcp is running 'discard'.
function check_discard( soc ) {

  local_var soc;
  local_var n, res;

  if( ! soc ) return( 0 );

  n = send( socket: soc, data: string( crap( length: ( rand() % 193 + 17 ), data: string( rand() ) ), "\r\n\r\n" ) );
  if( n < 0 ) return( 0 );

  res = recv( socket: soc, length: 1024, timeout: 5 );
  if( strlen( res ) > 0 ) return( 0 );

  return( 1 );
}

if( get_port_state( port ) ) {

  soc = open_sock_tcp( port );
  if( check_discard( soc: soc ) ) {

    cpe = "cpe:/a:postel:discard";

    set_kb_item( name: "discard/tcp/port", value: port );
    set_kb_item( name: "discard/detected", value: TRUE );

    service_register( port: port, proto: "discard" );

    register_product( cpe: cpe, location: port + "/tcp", port: port, service: "discard" );
    report = build_detection_report( app: "discard", cpe: cpe, skip_version: TRUE );

    log_message( port: port, data: report );
  }

  if( soc )
    close( soc );

}

exit( 0 );
