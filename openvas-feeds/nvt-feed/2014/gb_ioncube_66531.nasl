# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103932");
  script_version("2025-08-01T15:45:48+0000");
  script_tag(name:"last_modification", value:"2025-08-01 15:45:48 +0000 (Fri, 01 Aug 2025)");
  script_tag(name:"creation_date", value:"2014-04-01 13:11:55 +0200 (Tue, 01 Apr 2014)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ionCube Loader < 2.46 Multiple Vulnerabilities - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl",
                      "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"ionCube Loader is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The following flaws exist:

  - Xross-site scripting (XSS)

  - Multiple information disclosures

  - Arbitrary file disclosure");

  script_tag(name:"impact", value:"An attacker can exploit these issues to obtain potentially
  sensitive information, to view arbitrary files from the local filesystem and to execute arbitrary
  script code in the browser of an unsuspecting user in the context of the affected site. This may
  allow the attacker to steal cookie-based authentication credentials to launch other attacks.");

  script_tag(name:"affected", value:"ionCube Loader prior to version 2.46.");

  script_tag(name:"solution", value:"Update to version 2.46 or later.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66531");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("port_service_func.inc");

port = http_get_port( default:80 );

if( ! http_can_host_php( port:port ) )
  exit( 0 );

foreach dir( make_list_unique( "/ioncube", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" )
    dir = "";

  res = http_get_cache( port:port, item:dir + "/loader-wizard.php" );

  if( ! res || res !~ "^HTTP/1\.[01] 200" )
    continue;

  url = dir + "/loader-wizard.php?page=phpinfo";

  req = http_get( port:port, item:url );
  res = http_keepalive_send_recv( port:port, data:req );

  if( http_check_for_phpinfo_output( data:res ) ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
