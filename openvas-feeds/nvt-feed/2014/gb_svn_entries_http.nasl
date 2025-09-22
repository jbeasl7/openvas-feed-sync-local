# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105099");
  script_version("2025-08-21T05:40:06+0000");
  script_tag(name:"last_modification", value:"2025-08-21 05:40:06 +0000 (Thu, 21 Aug 2025)");
  script_tag(name:"creation_date", value:"2014-10-28 14:27:24 +0100 (Tue, 28 Oct 2014)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("Apache Subversion Module Metadata Accessible - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Apache Subversion Module Metadata accessible via HTTP.");

  script_tag(name:"vuldetect", value:"Try to read '.svn/entries'.");

  script_tag(name:"solution", value:"Restrict access to the .svn directories.");

  script_xref(name:"URL", value:"http://techcrunch.com/2009/09/23/basic-flaw-reveals-source-code-to-3300-popular-websites/");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("port_service_func.inc");

port = http_get_port( default:80 );

report = 'It was possible to retrieve the contents of ".svn/entries" using the following URLs : \n\n';
x = 0;
VULN = FALSE;

foreach dir( make_list_unique( "/", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" )
    dir = "";
  x++;

  url = dir + "/.svn/entries";

  req = http_get( port:port, item:url );
  res = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );

  if( ! res )
    continue;

  if( "has-props"      >< res ||
      "has-prop-mods"  >< res ||
      "committed-rev=" >< res ||
      'prop-time="'    >< res ||
      egrep( pattern:"svn:(special|needs-lock)", string:res ) ) {
    VULN = TRUE;
    report += http_report_vuln_url( port:port, url:url, url_only:TRUE ) + '\n';
  }

  if( x > 25 )
    break;
}

if( VULN ) {
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
