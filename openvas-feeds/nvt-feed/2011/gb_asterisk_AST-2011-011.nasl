# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:digium:asterisk";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900293");
  script_version("2023-12-20T12:22:41+0000");
  script_tag(name:"last_modification", value:"2023-12-20 12:22:41 +0000 (Wed, 20 Dec 2023)");
  script_tag(name:"creation_date", value:"2011-07-27 09:16:39 +0200 (Wed, 27 Jul 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2011-2536");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Asterisk SIP REGISTER Response Username Enumeration Vulnerability (AST-2011-011)");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("General");
  script_dependencies("gb_digium_asterisk_sip_detect.nasl");
  script_mandatory_keys("digium/asterisk/detected");

  script_tag(name:"summary", value:"Asterisk Server is prone to username enumeration vulnerability.");

  script_tag(name:"insight", value:"The problem is that different responses are being sent when using
  a valid or an invalid username in REGISTER messages. This can be exploited to determine valid
  usernames by sending specially crafted REGISTER messages.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to obtain valid
  username that could aid in further attacks.");

  script_tag(name:"affected", value:"Asterisk Business Edition versions C.3.x and Asterisk Open Source
  versions 1.4.x, 1.6.2.x, 1.8.x.");

  script_tag(name:"solution", value:"Updates are available. Please see the referenced AST advisory for
  more information.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/44707");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/101720");
  script_xref(name:"URL", value:"http://downloads.asterisk.org/pub/security/AST-2011-011.html");

  exit(0);
}

include("sip.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! infos = get_app_location_and_proto( cpe:CPE, port:port ) ) exit( 0 );

proto = infos["proto"];

req = string(
  "REGISTER sip:", get_host_name(), " SIP/2.0", "\r\n",
  "CSeq: 123 REGISTER", "\r\n",
  "Via: SIP/2.0/", toupper( proto ), " ", this_host(), ":", port ,
  " ;branch=z9hG4bK78adb2cd-0671-e011-81a1-a1816009ca7a;rport", "\r\n",
  "User-Agent: BSTest", "\r\n",
  "From: <sip:bstestenumtest@", get_host_name(), ">;tag=642d29cd-0671-e011-81a1-a1816009ca7a", "\r\n",
  "Call-ID: 2e2f07e0499cec3abf7045ef3610f0f2", "\r\n",
  "To: <sip:bstestenumtest@", get_host_name(), ">", "\r\n",
  "Refer-To: sip:bstestenumtest@", get_host_name(), "\r\n",
  "Contact: <sip:bstestenumtest@", this_host(), " >;q=1\r\n",
  "Allow: INVITE,ACK,OPTIONS,BYE,CANCEL,SUBSCRIBE,NOTIFY,REFER,MESSAGE,INFO,PING", "\r\n",
  "Expires: 3600", "\r\n",
  "Content-Length: 28000", "\r\n",
  "Max-Forwards: 70", "\r\n",
  "\r\n" );
res = sip_send_recv( port:port, data:req, proto:proto );

if( res =~ "SIP\/[0-9].[0-9] 100 Trying" ) {
  security_message( port:port, proto:proto );
  exit( 0 );
}

exit( 99 );
