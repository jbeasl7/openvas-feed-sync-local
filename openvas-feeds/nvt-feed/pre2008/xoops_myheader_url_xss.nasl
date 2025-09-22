# SPDX-FileCopyrightText: 2003 Noam Rathaus
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:xoops:xoops";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11962");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("XOOPS 2.0.5.1 myheader.php URL XSS Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2003 Noam Rathaus");
  script_family("Web application abuses");
  script_dependencies("secpod_xoops_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("XOOPS/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/9269");

  script_tag(name:"summary", value:"XOOPS is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The weblinks module of XOOPS contains a file named
  'myheader.php' in /modules/mylinks/ directory. The code of the module insufficiently filters out
  user provided data.");

  script_tag(name:"impact", value:"The URL parameter used by 'myheader.php' can be used to insert
  malicious HTML and/or JavaScript in to the web page.");

  script_tag(name:"affected", value:"XOOPS 2.0.5.1 is known to be affected.");

  script_tag(name:"solution", value:"Update to the latest version of XOOPS.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

check = raw_string( 0x22 );
check = string( "href=", check, "javascript:foo", check );

url = dir + "/modules/mylinks/myheader.php?url=javascript:foo";
req = http_get( item:url, port:port );
res = http_keepalive_send_recv( port:port, data:req );

if( res =~ "^HTTP/1\.[01] 200" && check >< res ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
