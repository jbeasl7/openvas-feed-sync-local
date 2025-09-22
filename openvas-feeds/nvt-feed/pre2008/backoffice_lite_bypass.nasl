# SPDX-FileCopyrightText: 2005 Noam Rathaus
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# Subject: bug report comersus Back Office Lite 6.0 and 6.0.1
# From: "raf somers" <beltech2bugtraq@hotmail.com>
# Date: 2005-01-21 18:07

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.16227");
  script_version("2024-06-13T05:05:46+0000");
  script_cve_id("CVE-2005-0301");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/12362");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-06-13 05:05:46 +0000 (Thu, 13 Jun 2024)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_name("Comersus BackOffice Lite Administrative Bypass");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 Noam Rathaus");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "global_settings.nasl",
                      "gb_microsoft_iis_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Delete the file '/comersus_backoffice_install10.asp' from the
  server as it is not needed after the installation process has been completed.");

  script_tag(name:"summary", value:"Comersus ASP shopping cart is a set of ASP scripts creating an online
  shoppingcart. It works on a database of your own choosing, default is msaccess, and includes online
  administration tools.");

  script_tag(name:"impact", value:"By accessing the /comersus_backoffice_install10.asp file it is possible
  to bypass the need to authenticate as an administrative user.");

  script_tag(name:"qod_type", value:"remote_app");

  script_tag(name:"solution_type", value:"Workaround");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port( default:80 );
if( ! http_can_host_asp( port:port ) ) exit( 0 );

host = http_host_name( port:port );

foreach dir( make_list_unique( "/comersus/backofficeLite", "/comersus", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";

  url = dir + "/comersus_backoffice_install10.asp";
  req = http_get( item:url, port:port );
  r = http_keepalive_send_recv( port:port, data:req );
  if( isnull(  r ) ) continue;
  if( 'Installation complete' >< r && 'Final Step' >< r && 'Installation Wizard' >< r ) {

    v = eregmatch( pattern:"Set-Cookie[0-9]?: *([^; ]+)", string:r );

    if( ! isnull( v ) ) {
      cookie = v[1];
      req = string( "GET ", dir, "/comersus_backoffice_settingsModifyForm.asp HTTP/1.1\r\n",
                    "Host: ", host, "\r\n",
                    "Cookie: ", cookie, "\r\n",
                    "\r\n" );
      r = http_keepalive_send_recv( port:port, data:req );
      if( isnull( r ) ) continue;
      if( 'Modify Store Settings' >< r && 'Basic Admin Utility' >< r ) {
        report = http_report_vuln_url( port:port, url:url );
        security_message( port:port, data:report );
        exit( 0 );
      }
    }
  }
}

exit( 99 );
