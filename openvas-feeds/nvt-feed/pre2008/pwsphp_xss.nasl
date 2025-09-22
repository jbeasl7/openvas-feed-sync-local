# SPDX-FileCopyrightText: 2005 David Maciejak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# Ref: SecuBox fRoGGz <unsecure@writeme.com>

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.18216");
  script_version("2023-12-13T05:05:23+0000");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/13561");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/13563");
  script_cve_id("CVE-2005-1508");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("PWSPHP XSS");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2005 David Maciejak");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "cross_site_scripting.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Upgrade to version 1.2.3 or newer");

  script_tag(name:"summary", value:"The remote host runs PWSPHP (Portail Web System) a CMS written in PHP.

  The remote version  of this software is vulnerable to cross-site
  scripting attack due to a lack of sanity checks on the 'skin' parameter
  in the script SettingsBase.php.

  With a specially crafted URL, an attacker could use the remote server
  to set up a cross site script attack.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port( default:80 );
if( ! http_can_host_php( port:port ) ) exit( 0 );

host = http_host_name( dont_add_port:TRUE );
if( http_get_has_generic_xss( port:port, host:host ) ) exit( 0 );

foreach dir( make_list_unique( "/", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = string( dir, "/profil.php?id=1%20<script>foo</script>" );

  if( http_vuln_check( port:port, url:url, pattern:"<script>foo</script>", extra_check:"title>PwsPHP ", check_header:TRUE ) ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
