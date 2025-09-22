# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:vbulletin:vbulletin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804144");
  script_version("2025-05-29T05:40:25+0000");
  script_cve_id("CVE-2013-6129");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-05-29 05:40:25 +0000 (Thu, 29 May 2025)");
  script_tag(name:"creation_date", value:"2013-11-15 12:55:00 +0530 (Fri, 15 Nov 2013)");
  script_name("vBulletin 4.1.x, 5.x Authentication Bypass Vulnerability - Active Check");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("vbulletin_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("vbulletin/http/detected");

  script_tag(name:"summary", value:"vBulletin is prone to a security bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The flaw is due to the 'upgrade.php' script which does not
  require authentication, which allows to create administrative accounts via the customerid,
  htmldata[password], htmldata[confirmpassword], and htmldata[email] parameters.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to bypass
  security restrictions.");

  script_tag(name:"affected", value:"vBulletin version 4.1.x and 5.x are affected.");

  script_tag(name:"solution", value:"Update to version 4.2.2, 5.0.5 or later.");

  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/123811");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/62909");
  script_xref(name:"URL", value:"http://www.net-security.org/secworld.php?id=15743");

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

foreach dir2( make_list("", "/core" ) ) {

  url = dir + dir2 + "/install/upgrade.php";

  req = http_get( item:url, port:port );
  res = http_keepalive_send_recv( port:port, data:req );

  if( res && res =~ "^HTTP/1\.[01] 200" &&
      "vBulletin" >< res && "Customer Number<" >< res ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
