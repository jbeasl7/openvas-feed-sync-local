# SPDX-FileCopyrightText: 2005 Josh Zlatin-Amishav
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.18410");
  script_version("2024-05-07T05:05:33+0000");
  script_tag(name:"last_modification", value:"2024-05-07 05:05:33 +0000 (Tue, 07 May 2024)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2005-1864", "CVE-2005-1865", "CVE-2005-1866");
  script_name("Calendarix Advanced <= 1.5 Multiple Vulnerabilities - Active Check");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2005 Josh Zlatin-Amishav");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl",
                      "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.swp-scene.org/?q=node/62");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210128045203/http://www.securityfocus.com/bid/13825");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210206160403/http://www.securityfocus.com/bid/13826/");

  script_tag(name:"summary", value:"Calendarix is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The remote version of this software is prone to a remote file
  include vulnerability as well as multiple cross-site scripting (XSS) and SQL injection (SQLi)
  vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation could result in execution of arbitrary
  PHP code on the remote site, a compromise of the application, disclosure or modification of data,
  or may permit an attacker to exploit vulnerabilities in the underlying database implementation.");

  script_tag(name:"affected", value:"Calendarix Advanced versions 1.5 and prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"qod_type", value:"remote_active");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port( default:80 );

if( ! http_can_host_php( port:port ) )
  exit( 0 );

foreach dir( make_list_unique( "/", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" )
    dir = "";

  url = dir + "/cal_week.php";
  res = http_get_cache( item:url, port:port );
  if( ! res || res !~ "^HTTP/1\.[01] 200" )
    continue;

  url = dir + "/cal_week.php?op=week&catview=999'";

  if( http_vuln_check( port:port, url:url, pattern:"mysql_num_rows\(\): supplied argument is not a valid MySQL result" ) ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
