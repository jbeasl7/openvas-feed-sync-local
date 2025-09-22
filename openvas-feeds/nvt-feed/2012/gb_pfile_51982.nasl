# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103435");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2012-02-23 12:58:18 +0100 (Thu, 23 Feb 2012)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2012-1210", "CVE-2012-1211");

  script_tag(name:"qod_type", value:"remote_probe");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("pfile <= 1.02 Multiple Vulnerabilities - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"pfile is prone to a cross-site scripting (XSS) vulnerability
  and an SQL injection (SQLi) vulnerability because it fails to properly sanitize user-supplied
  input.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"Exploiting these issues could allow an attacker to steal
  cookie-based authentication credentials, compromise the application, access or modify data, or
  exploit latent vulnerabilities in the underlying database.");

  script_tag(name:"affected", value:"pfile version 1.02 and probably prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51982");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("port_service_func.inc");

port = http_get_port( default:80 );

if( ! http_can_host_php( port:port ) )
  exit( 0 );

foreach dir( make_list_unique( "/pfile", http_cgi_dirs( port:port ) ) ) {
  if( dir == "/" )
    dir = "";

  res = http_get_cache( port:port, item:dir + "/kommentar.php" );
  if( res !~ "^HTTP/1\.[01] 200" )
    continue;

  url = dir + '/kommentar.php?filecat="><script>alert(/xss-test/)</script>&fileid=0';

  if( http_vuln_check( port:port, url:url, check_header:TRUE,
                       pattern:'ACTION="kommentar\\.php\\?fileid=.&filecat="><script>alert\\(/xss-test/\\)</script>' ) ) {
    report = http_report_vuln_url( port:port, url:url  );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
