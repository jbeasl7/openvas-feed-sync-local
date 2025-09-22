# SPDX-FileCopyrightText: 2002 Michel Arboi
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11075");
  script_version("2023-07-21T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/5384");
  script_cve_id("CVE-1999-1417");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("dwhttpd format string");
  script_category(ACT_MIXED_ATTACK);
  script_copyright("Copyright (C) 2002 Michel Arboi");
  script_family("Gain a shell remotely");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("dwhttp/banner");
  script_require_ports("Services/www", 8888);
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade your software or protect it with a filtering reverse proxy.");

  script_tag(name:"summary", value:"The remote web server is vulnerable to a format string attack.");

  script_tag(name:"impact", value:"A cracker may exploit this vulnerability to make your web server
  crash continually or even execute arbirtray code on your system.");

  script_tag(name:"affected", value:"dwhttp/4.0.2a7a and dwhttpd/4.1a6 are known to be affected. Other
  versions might be affected as well.");

  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");

port = http_get_port( default:8888 );

banner = http_get_remote_headers( port:port );
if( "dwhttp/" >!< banner ) exit( 0 );

if( safe_checks() ) {
  if( egrep( string:banner, pattern:"^Server: *dwhttp/4.(0|1[^0-9])" ) ) {
    security_message( port:port );
  }
  exit( 0 );
}

if( http_is_dead( port:port ) ) exit( 0 );

url = string( "/", crap( data:"%n", length:100 ) );
req = http_get( item:url, port:port );
res = http_send_recv( port:port, data:req );

if( http_is_dead( port:port, retry:2 ) ) {
  security_message( port:port );
  exit( 0 );
}

exit( 99 );
