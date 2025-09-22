# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105148");
  script_version("2024-09-03T06:26:22+0000");
  script_tag(name:"last_modification", value:"2024-09-03 06:26:22 +0000 (Tue, 03 Sep 2024)");
  script_tag(name:"creation_date", value:"2014-12-19 14:59:27 +0100 (Fri, 19 Dec 2014)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Micro Focus / NetIQ Access Manager Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Micro Focus / NetIQ Access Manager.");

  script_xref(name:"URL", value:"https://www.microfocus.com/en-us/cyberres/identity-access-management/access-manager");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("os_func.inc");
include("port_service_func.inc");

port = http_get_port( default:443 );

url = "/nidp/app";

res = http_get_cache( port:port, item:url );
# nb: Some host redirect to SSO which we still can detect if follow the redirect
if( res =~ "^HTTP/1\.[01] 30[0-9]" ) {
  loc = http_extract_location_from_redirect( port:port, data:res, current_dir:"/" );
  if( loc ) {
    url = loc;
    res = http_get_cache( port:port, item:url );
  }
}

if( ! res || ( res !~ "<title>(NetIQ )?Access Manager" && "/nidp/app/login?id=" >!< res &&
               "UrnNovellNidpClusterMemberId" >!< res ) ) {
  url = "/nps/servlet/portal";

  res = http_get_cache( port:port, item:url );

  if( res !~ "<title>(NetIQ )?Access Manager" && 'name="Login_Key"' >!< res ) {
    url = "/portal/";

    res = http_get_cache( port:port, item:url );

    if( res !~ "<title>(NetIQ )?Access Manager" && 'title="Administration Console"' >!< res )
      exit( 0 );
  }
}

version = "unknown";
location = "/";
conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );

set_kb_item( name:"netiq/access_manager/detected", value:TRUE );
set_kb_item( name:"netiq/access_manager/http/detected", value:TRUE );

url = "/nidp/html/help/en/bookinfo.html";

res = http_get_cache( port:port, item:url );
# nb: This is just the major version
vers = eregmatch( pattern:"Access Manager ([0-9.]+) User Portal Help", string:res );
if( ! isnull( vers[1] ) ) {
  version = vers[1];
  conclUrl += '\n' + http_report_vuln_url( port:port, url:url, url_only:TRUE );
} else {
  url = "/roma/help/doc/solutionguide/bookinfo.html";

  res = http_get_cache( port:port, item:url );

  # nb: As well only the major version
  vers = eregmatch( pattern:"NetIQ Access Manager Appliance ([0-9.]+)", string:res );
  if( ! isnull( vers[1] ) ) {
    version = vers[1];
  conclUrl += '\n' + http_report_vuln_url( port:port, url:url, url_only:TRUE );
  }
}

os_register_and_report( os:"Linux", cpe:"cpe:/o:linux:kernel", port:port, runs_key:"unixoide",
                       desc:"Micro Focus / NetIQ Access Manager Detection (HTTP)" );

cpe1 = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:microfocus:access_manager:" );
cpe2 = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:netiq:access_manager:" );
if( ! cpe1 ) {
  cpe1 = "cpe:/a:microfocus:access_manager";
  cpe2 = "cpe:/a:netiq:access_manager";
}

register_product( cpe:cpe1, location:location, port:port, service:"www" );
register_product( cpe:cpe2, location:location, port:port, service:"www" );

log_message( data:build_detection_report( app:"Micro Focus / NetIQ Access Manager", version: version, cpe:cpe1,
                                          install:location, concluded:vers[0], concludedUrl:conclUrl ),
             port:port );

exit( 0 );
