# SPDX-FileCopyrightText: 2015 SCHUTZWERK GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.111055");
  script_version("2025-05-06T05:40:10+0000");
  script_tag(name:"last_modification", value:"2025-05-06 05:40:10 +0000 (Tue, 06 May 2025)");
  script_tag(name:"creation_date", value:"2015-11-21 19:00:00 +0100 (Sat, 21 Nov 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Icinga Web 2 Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2015 SCHUTZWERK GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl",
                      "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Icinga Web 2.");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = http_get_port( default:80 );
if( ! http_can_host_php( port:port ) )
  exit ( 0 );

detection_patterns = make_list(
  "<title>Icinga Web 2 Login",
  "Icinga Web 2 &copy;",
  "var icinga = new Icinga"
);

foreach dir( make_list_unique( "/", "/icinga", "/icingaweb2", http_cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" )
    dir = "";

  url = dir + "/authentication/login";
  req = http_get_req( port:port, url:url, add_headers:make_array( "Cookie", "_chc=1" ) );
  res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );
  if( ! res || res !~ "^HTTP/1\.[01] 200" )
    continue;

  found = 0;
  concluded = ""; # nb: To make openvas-nasl-lint happy...

  foreach pattern( detection_patterns ) {

    concl = egrep( string:res, pattern:pattern, icase:FALSE );
    if( concl ) {

      found++;

      if( concluded )
        concluded += '\n';

      # nb: Minor formatting change for the reporting.
      concl = chomp( concl );
      concl = ereg_replace( string:concl, pattern:"^(\s+)", replace:"" );
      concluded += "  " + concl;
    }
  }

  if( found > 0 ) {

    version = "unknown";
    concludedUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );

    set_kb_item( name:"icinga/icingaweb2/detected", value:TRUE );
    set_kb_item( name:"icinga/icingaweb2/http/detected", value:TRUE );
    set_kb_item( name:"icinga/icingaweb2/http/port", value:port );
    set_kb_item( name:"icinga/icingaweb2/http/" + port + "/installs",
                 value:port + "#---#" + install + "#---#" + version + "#---#" + concluded + "#---#" + concludedUrl );
  }
}

exit( 0 );
