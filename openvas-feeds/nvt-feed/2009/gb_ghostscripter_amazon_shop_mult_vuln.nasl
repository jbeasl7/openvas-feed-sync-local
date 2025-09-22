# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100024");
  script_version("2023-12-22T16:09:03+0000");
  script_tag(name:"last_modification", value:"2023-12-22 16:09:03 +0000 (Fri, 22 Dec 2023)");
  script_tag(name:"creation_date", value:"2009-03-10 08:40:52 +0100 (Tue, 10 Mar 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_probe");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("GhostScripter Amazon Shop Multiple Vulnerabilities (Mar 2009) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Amazon Shop is prone to multiple vulnerabilities, including a
  cross-site scripting issue, a directory-traversal issue, and multiple remote file-include issues,
  because it fails to sufficiently sanitize user-supplied data.");

  script_tag(name:"impact", value:"An attacker can exploit these issues to run malicious PHP code
  in the context of the webserver process, run script code in an unsuspecting user's browser, steal
  cookie-based authentication credentials, or obtain sensitive information, other attacks are also
  possible.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/33994");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("port_service_func.inc");

port = http_get_port( default:80 );

if( ! http_can_host_php( port:port ) )
  exit( 0 );

foreach dir( make_list_unique("/amazon", http_cgi_dirs( port:port ) ) ) {
  if( dir == "/" )
    dir = "";

  res = http_get_cache( port:port, item:dir + "/search.php" );
  if (! res || res !~ "^HTTP/1\.[01] 200" )
    continue;

  url = dir + "/search.php?query=1<script>alert(document.cookie);</script>&mode=all";

  if( http_vuln_check( port:port, url:url, pattern:"<script>alert\(document.cookie\);</script>",
                       check_header:TRUE ) ) {
    report = http_report_vuln_url( port:port, url:url  );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
