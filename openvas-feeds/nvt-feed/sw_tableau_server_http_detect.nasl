# SPDX-FileCopyrightText: 2015 SCHUTZWERK GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.111048");
  script_version("2025-07-30T05:45:23+0000");
  script_tag(name:"last_modification", value:"2025-07-30 05:45:23 +0000 (Wed, 30 Jul 2025)");
  script_tag(name:"creation_date", value:"2015-11-09 12:00:00 +0100 (Mon, 09 Nov 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Tableau Server Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2015 SCHUTZWERK GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of a Tableau Server.");

  script_xref(name:"URL", value:"https://www.tableau.com/products/server");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port( default:443 );

banner = http_get_remote_headers( port:port );

url = "/";

# X-Tableau: Tableau Server
# Server: Tableau
if( concl = egrep( string:banner, pattern:"^(Server|X-Tableau)\s*:\s*Tableau", icase:TRUE ) ) {
  found = TRUE;
  concluded = "  " + chomp( concl );
  concludedUrl = "  " + http_report_vuln_url( port:port, url:url, url_only:TRUE );
}

res = http_get_cache( port:port, item:url );
# nb: No egrep() as a few strings are longer and the concluded reporting might explode...
# <meta name="vizportal-config" data-buildId="2020_2_139_nu9qhmse1oe"
# <div class="tb-app" ng-app="VizPortalRun" id="ng-app" tb-window-resize>
# ><script type="text/javascript" src="/javascripts/api/tableau-2.min.js?27a602c5cf7c24d95a3a"></script><
# ><script src="/javascripts/api/tableau-2.0.1.min.js?3e2ck308xtv86w29">
# VizPortal.BuildId = '3e2ck308xtv86w29';
if( concl = eregmatch( string:res, pattern:'(VizPortal\\.BuildId[^;]+;|vizportal-config" data-buildId\\s*=\\s*"[^"]+|/javascripts/api/tableau-[^>]+>|ng-app="VizPortalRun")', icase:FALSE ) ) {
  if( concluded )
    concluded += '\n';
  concluded += "  " + concl[0];

  # nb: Only add the URL if product was not already detected from the banner
  if( ! found )
    concludedUrl = "  " + http_report_vuln_url( port:port, url:url, url_only:TRUE );

  found = TRUE;
}

url = "/auth";
res = http_get_cache( port:port, item:url );

# window.top.postMessage("tableau.loadIndicatorsLoaded", "*");
# tableau_assets = {
if( concl = eregmatch( string:res, pattern:'("tableau\\.loadIndicatorsLoaded"|^\\s*tableau_assets =)', icase:FALSE ) ) {
  found = TRUE;
  if( concluded )
    concluded += '\n';
  concluded += "  " + concl[0];

  if( concludedUrl )
    concludedUrl += '\n  ';
  concludedUrl += http_report_vuln_url( port:port, url:url, url_only:TRUE );

  # nb: For later version grabbing from this specific response
  auth_res = res;
}

if( ! found )
  exit( 0 );

version = "unknown";
install = "/";

# <!--      <div class="versionText">
#         <b id="version">Version&nbsp;8.0.0
# <br />(Build&nbsp;8000.13.0319.1225)
# </b>
if( vers = eregmatch( string:auth_res, pattern:">Version&nbsp;([0-9.]+)", icase:FALSE ) ) {
  version = vers[1];
  concluded += '\n  ' + vers[0];
  # nb: No need to add the concludedUrl here as it was already added above...
}

if( version == "unknown" ) {

  url = "/api/3.0/serverinfo";
  res = http_get_cache( port:port, item:url );

  # <productVersion build="20181.18.0706.1237">2018.1.3</productVersion>
  # <productVersion build="20221.22.0415.1144">2022.1.1</productVersion>
  if( vers = eregmatch( string:res, pattern:"<productVersion[^>]*>([^<]+)</productVersion>" ) ) {
    version = vers[1];
    concluded += '\n  ' + vers[0];
    concludedUrl += '\n  ' + http_report_vuln_url( port:port, url:url, url_only:TRUE );
  }
}

set_kb_item( name:"tableau_server/detected", value:TRUE );
set_kb_item( name:"tableau_server/http/detected", value:TRUE );

# nb: One CVE from 2014 is still using the second CPE in the NVD so we're currently registering / keeping both.
cpe1 = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:tableau:tableau_server:" );
cpe2 = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:tableausoftware:tableau_server:" );
if( ! cpe1 ) {
  cpe1 = "cpe:/a:tableau:tableau_server";
  cpe2 = "cpe:/a:tableausoftware:tableau_server";
}

register_product( cpe:cpe1, location:install, port:port, service:"www" );
register_product( cpe:cpe2, location:install, port:port, service:"www" );

log_message( data:build_detection_report( app:"Tableau Server",
                                          version:version,
                                          install:install,
                                          cpe:cpe1,
                                          concludedUrl:concludedUrl,
                                          concluded:concluded ),
             port:port );

exit( 0 );
