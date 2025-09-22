# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140066");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2025-09-18T05:38:39+0000");
  script_tag(name:"last_modification", value:"2025-09-18 05:38:39 +0000 (Thu, 18 Sep 2025)");
  script_tag(name:"creation_date", value:"2016-11-17 10:30:27 +0100 (Thu, 17 Nov 2016)");
  script_name("Keycloak Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.keycloak.org/");

  script_tag(name:"summary", value:"HTTP based detection of Keycloak.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");

port = http_get_port( default:80 );

detection_patterns = make_list(

  # <title>Welcome to Keycloak</title>
  "<title>Welcome to Keycloak</title>",

  # <h1>Welcome to <strong>Keycloak</strong></h1>
  "<h[0-9]>Welcome to <strong>Keycloak</strong></h[0-9]>",

  # <h3><a href="admin/"><img src="welcome-content/user.png">Administration Console <i class="fa fa-angle-right link" aria-hidden="true"></i></a></h3>
  # <p><a href="http://www.keycloak.org/docs">Documentation</a> | <a href="admin/">Administration Console</a> </p>
  ">Administration Console[^<]*<",

  # <div class="description">
  #   Centrally manage all aspects of the Keycloak server
  # </div>
  "^\s*Centrally manage all aspects of the Keycloak server"
);

url = "/auth/";
buf = http_get_cache( item:url, port:port );

found = 0;
concluded = ""; # nb: To make openvas-nasl-lint happy...

foreach pattern( detection_patterns ) {

  concl = egrep( string:buf, pattern:pattern, icase:FALSE );
  if( concl ) {
    if( concluded )
      concluded += '\n';

    # nb: Minor formatting change for the reporting.
    concl = chomp( concl );
    concl = ereg_replace( string:concl, pattern:"^(\s+)", replace:"" );
    concluded += "  " + concl;

    found++;
  }
}

if( found > 1 ) {

  install = "/";
  version = "unknown";
  rep_version = "unknown";
  conclurl = "  " + http_report_vuln_url( port:port, url:url, url_only:TRUE );

  set_kb_item( name:"keycloak/detected", value:TRUE );
  set_kb_item( name:"keycloak/http/detected", value:TRUE );

  cpe = "cpe:/a:redhat:keycloak";
  # nb: Some older CVEs are still using this one within the NVD
  cpe2 = "cpe:/a:keycloak:keycloak";

  url = "/auth/admin/master/console/";
  buf = http_get_cache( item:url, port:port );

  # e.g.:
  # <script src="http://localhost:8080/auth/resources/2.3.0.final/admin/keycloak/lib/angular/angular.js"></script>
  # <script src="/auth/resources/3.4.1.final/admin/keycloak/node_modules/angular/angular.min.js"></script>
  # <script src="/auth/resources/4.8.3.final/admin/keycloak/node_modules/jquery/dist/jquery.min.js" type="text/javascript"></script>
  # <script src="/auth/resources/6.0.1/admin/keycloak/node_modules/jquery/dist/jquery.min.js" type="text/javascript"></script>
  # <script src="/auth/resources/7.0.1/admin/keycloak/node_modules/angular/angular.min.js"></script>
  #
  # newer versions just have something like e.g. this:
  #
  # <script src="/auth/resources/ady3m/common/keycloak/node_modules/jquery/dist/jquery.min.js" type="text/javascript"></script>
  #
  # or:
  #
  # <script type="module" crossorigin src="/resources/0ktxb/admin/keycloak.v2/assets/index-f33eb656.js"></script>
  vers_nd_type = eregmatch( pattern:"/auth/resources/([0-9.]+)\.([a-z]+[^/]+)/admin/", string:buf );

  if( isnull( vers_nd_type[1] ) )
    # nb:
    # - We need to make this a little bit more strict to not match something "wrongly"
    # - It seems never versions doesn't have the strings like ".final"
    # - Don't add a second matching group here without verifying that it is correctly handled for
    #   the "type" reporting below
    vers_nd_type = eregmatch( pattern:"/auth/resources/([0-9]+\.[0-9]+\.[0-9.]+)/admin/", string:buf );

  if( ! isnull( vers_nd_type[1] ) ) {
    conclurl += '\n  ' + http_report_vuln_url( port:port, url:url, url_only:TRUE );
    version = vers_nd_type[1];
    cpe += ":" + version;
    cpe2 += ":" + version;
    rep_version = version;
    concluded += '\n  ' + vers_nd_type[0];
  }

  if( ! isnull( vers_nd_type[2] ) ) {
    set_kb_item( name:"keycloak/release_type", value:vers_nd_type[2] );
    rep_version += " (" + vers_nd_type[2] + ")";
  }

  register_product( cpe:cpe, location:install, port:port, service:"www" );
  register_product( cpe:cpe2, location:install, port:port, service:"www" );

  report = build_detection_report( app:"Keycloak", version:rep_version, install:install, cpe:cpe, concluded:concluded, concludedUrl:conclurl );

  log_message( port:port, data:report );
}

exit( 0 );
