# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108317");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2018-01-13 07:00:00 +0100 (Sat, 13 Jan 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Matomo Analytics Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://matomo.org/");

  script_tag(name:"summary", value:"The script sends a HTTP request to the server
  and attempts to identify Matomo (formerly Piwik) and its version from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("host_details.inc");
#include("cpe.inc");

port = http_get_port( default:80 );
if( ! http_can_host_php( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/", "/piwik", "/matomo", "/analytics", http_cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  buf = http_get_cache( item:dir + "/index.php", port:port );

  if( buf =~ "^HTTP/1\.[01] 200" && ( eregmatch( pattern:'<title>.*Matomo.*</title>', string:buf, icase:TRUE ) ||
      ( "https://matomo.org" >< buf && "piwik.piwik_url" >< buf ) ) ) { # nb: 3.3.0 still has the piwik.pwik_url in the response

    version = "unknown";

    # TODO: Implement getting the version from the API via getMatomoVersion: https://developer.matomo.org/api-reference/reporting-api#API
    # This requires new script_add_preference for a user/password combination as the API is protected by credentials.

    # nb: This isn't necessarily the "real" version, see https://github.com/matomo-org/matomo/issues/13827
    url = dir + "/CHANGELOG.md";
    buf = http_get_cache( item:url, port:port );

    ver = eregmatch( pattern:'## Matomo ([0-9.]+)', string:buf );
    if( ! isnull( ver[1] ) ) {
      #version  = ver[1];
      conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
      extra    = "Possible version gathered from the developers CHANGELOG.md: " + ver[1] + '\n';
      extra   += "NOTE: This version is not necessarily matching the running version and currently not used.";
    }

    #cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:matomo:matomo:");
    #if( isnull( cpe ) )
      cpe = "cpe:/a:matomo:matomo";

    set_kb_item( name:"www/" + port + "/matomo", value:version );
    set_kb_item( name:"matomo/installed", value:TRUE );

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    log_message( data:build_detection_report( app:"Matomo",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              extra:extra,
                                              concludedUrl:conclUrl,
                                              concluded:ver[0] ),
                                              port:port );
  }
}

exit( 0 );
