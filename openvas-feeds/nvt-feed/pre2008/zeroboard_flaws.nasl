# SPDX-FileCopyrightText: 2004 David Maciejak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.16059");
  script_version("2024-01-19T16:09:33+0000");
  script_tag(name:"last_modification", value:"2024-01-19 16:09:33 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2004-1419", "CVE-2004-2738");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Zeroboard < 4.1pl5 Multiple Vulnerabilities - Active Check");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2004 David Maciejak");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "cross_site_scripting.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://marc.info/?l=bugtraq&m=110391024404947&w=2");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/12103");

  script_tag(name:"summary", value:"Zeroboard is prone to arbitrary PHP code execution and
  cross-site scripting (XSS) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The remote version of this software is vulnerable to XSS and
  remote script injection due to a lack of sanitization of user-supplied data.");

  script_tag(name:"impact", value:"Successful exploitation of this issue may allow an attacker to
  execute arbitrary code on the remote host or to use it to perform an attack against third-party
  users.");

  script_tag(name:"affected", value:"Zeroboard prior to version 4.1pl5.");

  script_tag(name:"solution", value:"Update to version 4.1pl5 or later.");

  script_tag(name:"qod_type", value:"remote_vul"); # nb: No need to use remote_analysis as we have an additional response check below
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port( default:80 );
if( ! http_can_host_php( port:port ) )
  exit( 0 );

host = http_host_name( dont_add_port:TRUE );
if( http_get_has_generic_xss( port:port, host:host ) )
  exit( 0 );

foreach dir( make_list_unique( "/bbs", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" )
    dir = "";

  res = http_get_cache( port:port, item:dir + "/zboard.php?id=cgi_about" );

  # e.g.:
  #
  # - >Zeroboard</a> / skin by
  # - http://zeroboard.com
  # - ZEROBOARD.COM
  #
  # as seen on e.g.:
  #
  # - view-source:https://web.archive.org/web/20041206155143/http://www.nzeo.com/bbs/zboard.php?id=cgi_about
  # - view-source:https://web.archive.org/web/20060510163404/http://www.nzeo.com/bbs/zboard.php?id=cgi_about
  #
  if( ! res || res !~ "(zeroboard\.com|>Zeroboard</a>)" )
    continue;

  url = dir + "/check_user_id.php?user_id=<script>foo</script>";

  req = http_get( item:url, port:port );
  res = http_keepalive_send_recv( port:port, data:req );
  if( ! res )
    continue;

  if( res =~ "^HTTP/1\.[01] 200" && "ZEROBOARD.COM" >< res && "<script>foo</script>" >< res ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
