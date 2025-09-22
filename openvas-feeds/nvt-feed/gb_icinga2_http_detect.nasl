# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113120");
  script_version("2024-11-15T05:05:36+0000");
  script_tag(name:"last_modification", value:"2024-11-15 05:05:36 +0000 (Fri, 15 Nov 2024)");
  script_tag(name:"creation_date", value:"2018-03-01 13:53:44 +0100 (Thu, 01 Mar 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Icinga 2 Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 5665);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Icinga 2.

  Note: Providing Icinga2 API Credentials can lead to better results.");

  script_add_preference(name:"Icinga 2 API Username", value:"", type:"entry", id:1);
  script_add_preference(name:"Icinga 2 API Password", value:"", type:"password", id:2);

  script_xref(name:"URL", value:"https://www.icinga.com/products/icinga-2/");
  script_xref(name:"URL", value:"https://www.icinga.com/docs/icinga2/latest/doc/12-icinga2-api/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("misc_func.inc");

port = http_get_port( default: 5665 );

banner = http_get_remote_headers( port: port );

detected = FALSE;

# Server: Icinga/r2.8.1-1
# Server: Icinga/r2.7.1-1
if( banner =~ "erver\s*:\s*Icinga" || 'Basic realm="Icinga 2"' >< banner ) {
  install  = "/";
  version  = "unknown";
  detected = TRUE;
  conclUrl = http_report_vuln_url( port: port, url: install, url_only: TRUE );

  vers = eregmatch( string: banner, pattern: "Icinga/[rv]?([0-9.-]+)" );
  if( ! isnull( vers[1] ) )
    version = vers[1];
} else {
  url = "/events";

  res = http_get_cache( port: port, item: url );

  if( res =~ '"title"\\s*:\\s*"Icinga 2' && "icinga-host-meter" >< res ) {
    detected = TRUE;
    install = "/";
    version = "unknown";
    conclUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );

    vers = eregmatch( pattern: '"title"\\s*:\\s*"Icinga ([0-9.-]+)"', string: res );
    if( ! isnull( vers[1] ) )
      version = vers[1];
  }
}

if( detected && version == "unknown" ) {

  user = script_get_preference( "Icinga 2 API Username" );
  pass = script_get_preference( "Icinga 2 API Password" );

  if( ! user && ! pass ) {
    extra = "Incinga 2 Detected but version unknown. Providing API credentials to this VT might allow to gather the version.";
  } else if( ! user && pass ) {
    extra = "Password provided but Username is missing.";
  } else if( user && ! pass ) {
    extra = "Username provided but Password is missing.";
  } else if( user && pass ) {
    url = "/v1/status/IcingaApplication";

    add_headers = make_array( "Authorization", "Basic " + base64( str: user + ":" + pass ) );

    req = http_get_req( port: port, url: url, add_headers: add_headers, accept_header: "*/*");
    res = http_keepalive_send_recv( port: port, data: req );

    if( res =~ "^HTTP/1\.[01] 200" && '{"results":' >< res ) {
      vers = eregmatch( string: res, pattern: '"version":"[rv]?([0-9.-]+)"' );
      if( ! isnull( vers[1] ) ) {
        version  = vers[1];
        conclUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
      }
    } else {
      extra = 'Username and Password provided but login to the API failed with the following response:\n\n' +
              res;
    }
  }
}

if( ! detected )
  exit( 0 );

set_kb_item( name: "icinga2/detected", value: TRUE );
set_kb_item( name: "icinga2/http/detected", value: TRUE );

cpe = build_cpe( value: version, exp: "^([0-9.-]+)", base: "cpe:/a:icinga:icinga2:" );
if( ! cpe )
  cpe = "cpe:/a:icinga:icinga2";

register_product( cpe: cpe, location: install, port: port, service: "www" );

log_message( data: build_detection_report( app: "Icinga 2", version: version, install: install, cpe: cpe,
                                           concluded: vers[0], concludedUrl: conclUrl, extra: extra ),
             port: port );

exit( 0 );
