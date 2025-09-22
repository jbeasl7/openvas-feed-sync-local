# SPDX-FileCopyrightText: 2005 David Maciejak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

#  Ref: aLMaSTeR HacKeR

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.19749");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_cve_id("CVE-2007-3627");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/14504");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/14505");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Calendar Express Multiple Flaws");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2005 David Maciejak");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "cross_site_scripting.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Upgrade to the latest version of this software.");

  script_tag(name:"summary", value:"The remote web server is using Calendar Express which is vulnerable to a cross
  site scripting and SQL injection vulnerability.");

  script_tag(name:"impact", value:"A vulnerability exists in this version which may allow an attacker to
  execute arbitrary HTML and script code in the context of the user's browser, and SQL injection.

  An attacker may exploit these flaws to use the remote host to perform attacks
  against third-party users, or to execute arbitrary SQL statements on the remote
  SQL database.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:80);
if ( ! http_can_host_php(port:port) ) exit(0);

host = http_host_name( dont_add_port:TRUE );
if( http_get_has_generic_xss( port:port, host:host ) ) exit( 0 );

foreach dir( make_list_unique( "/calendarexpress", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = string(dir, "/search.php?allwords=<br><script>foo</script>&cid=0&title=1&desc=1");
  req = http_get(item:url, port:port);
  r = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
  if( isnull( r ) ) continue;

  if (r =~ "^HTTP/1\.[01] 200" &&  "<script>foo</script>" >< r && egrep(string:r, pattern:"Calendar Express [0-9].+ \[Powered by Phplite\.com\]") ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
