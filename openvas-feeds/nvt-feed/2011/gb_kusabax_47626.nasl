# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103155");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2011-05-02 15:13:22 +0200 (Mon, 02 May 2011)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_name("Kusaba X Multiple Cross Site Scripting Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47626");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"Kusaba X is prone to multiple cross-site scripting vulnerabilities
  because it fails to sufficiently sanitize user-supplied data.");

  script_tag(name:"impact", value:"An attacker may leverage these issues to execute arbitrary script code
  in the browser of an unsuspecting user in the context of the affected site. This may allow the attacker
  to steal cookie-based authentication credentials and to launch other attacks.");

  script_tag(name:"affected", value:"Versions prior to Kusaba X 0.9.2 are vulnerable.");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("host_details.inc");
include("misc_func.inc");

port = http_get_port(default:80);
if(!http_can_host_php(port:port))exit(0);

vt_strings = get_vt_strings();

foreach dir( make_list_unique( "/kusabax", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  buf = http_get_cache(item:dir + "/", port:port);
  if(!buf || buf !~ "^HTTP/1\.[01] 200" || ('src="menu.php"' >!< buf && 'src="news.php"' >!< buf))
    continue;

  url = string(dir,'/animation.php?board=b&id=1"><script>alert(/', vt_strings["lowercase"], '/)</script>');

  if(http_vuln_check(port:port, url:url, pattern:"<script>alert\(/" + vt_strings["lowercase"] + "/\)</script>", check_header:TRUE, extra_check:"<title>View Animation")) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
