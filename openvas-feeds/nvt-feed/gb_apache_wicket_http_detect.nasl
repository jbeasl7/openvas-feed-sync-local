# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807584");
  script_version("2025-04-01T05:39:41+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-04-01 05:39:41 +0000 (Tue, 01 Apr 2025)");
  script_tag(name:"creation_date", value:"2016-05-10 15:16:04 +0530 (Tue, 10 May 2016)");

  script_name("Apache Wicket Detection (HTTP)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Apache Wicket.");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port( default:8080 );

found = FALSE;
concludedurl = "";
host = http_host_name( dont_add_port:TRUE );

foreach dir( make_list_unique( "/", "/wicket-examples", "/wicket/wicket-examples", "/apache-wicket", http_cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" )
    dir = "";

  url = dir + "/index.html";

  res = http_get_cache( item:url, port:port );

  if( res =~ "^HTTP/(1\.[01]|2) 200" &&
      ( concl = eregmatch( string:res, pattern:'(<title>Wicket Examples</title>|> Wicket|mappers">Wicket)', icase:FALSE ) )
    ) {

    concluded = "  " + concl[0];
    version = "unknown";

    # <div id="header"><div class="version"> Wicket Version: <span>7.19.0-SNAPSHOT</span></div></div>
    vers = eregmatch( pattern:'class="version">\\s*Wicket Version:.*>([0-9.A-Z-]+)</span>', string:res );
    if( vers[1] ) {
      version = vers[1];
      version = ereg_replace( pattern:"-", string:version, replace:"." );
      concluded += '\n  ' + vers[0];
    }

    found = TRUE;
    concludedurl = "  " + http_report_vuln_url( port:port, url:url, url_only:TRUE );
    break;
  }
}

if( ! found ) {
  if( get_kb_item( "www/apache/wicket/" + host + "/" + port + "/detected" ) ) {
    found = TRUE;
    concludedurl = get_kb_item( "www/apache/wicket/" + host + "/" + port + "/concludedurl" );
    concluded = get_kb_item( "www/apache/wicket/" + host + "/" + port + "/concluded" );
    install = get_kb_item( "www/apache/wicket/" + host + "/" + port + "/install" );
  }
}

if( found ) {

  set_kb_item( name:"apache/wicket/detected", value:TRUE );
  set_kb_item( name:"apache/wicket/http/detected", value:TRUE );

  set_kb_item( name:"apache/wicket/http/" + port + "/installs", value:port + "#---#" + install + "#---#" +
               version + "#---#" + concluded );
}

exit( 0 );
