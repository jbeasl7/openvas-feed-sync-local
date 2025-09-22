# SPDX-FileCopyrightText: 2005 Noam Rathaus
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# Interspire ArticleLive 2005 (php version) XSS vulnerability
# mircia <mircia@security.talte.net>
# 2005-03-24 14:54

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.17612");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2005-0881");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/12879");
  script_name("Interspire ArticleLive 2005 XSS Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2005 Noam Rathaus");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "cross_site_scripting.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Upgrade to the newest version of this software");

  script_tag(name:"summary", value:"The remote web server is running ArticleLive, a set of CGIs designed to simplify
  the management of a news site which is vulnerable to a cross site scripting issue.");

  script_tag(name:"impact", value:"Due to improper filtering done by the script 'newcomment' remote attacker
  can cause the ArticleLive product to include arbitrary HTML and/or JavaScript, and therefore use the
  remote host to perform cross-site scripting attacks.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port( default:80 );

host = http_host_name( dont_add_port:TRUE );
if( http_get_has_generic_xss( port:port, host:host ) ) exit( 0 );

foreach dir( make_list_unique( "/", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = dir + '/newcomment/?ArticleId="><script>foo</script>';

  if( http_vuln_check( port:port, url:url, check_header:TRUE, pattern:'value=""><script>foo</script>"' ) ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
