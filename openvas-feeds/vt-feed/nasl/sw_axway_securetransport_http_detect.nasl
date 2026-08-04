# SPDX-FileCopyrightText: 2015 SCHUTZWERK GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.111019");
  script_version("2026-07-31T16:15:30+0000");
  script_tag(name:"last_modification", value:"2026-07-31 16:15:30 +0000 (Fri, 31 Jul 2026)");
  script_tag(name:"creation_date", value:"2015-04-22 08:00:00 +0200 (Wed, 22 Apr 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Axway SecureTransport MFT Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2015 SCHUTZWERK GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 443);

  script_tag(name:"summary", value:"HTTP based detection of Axway SecureTransport MFT.");

  script_xref(name:"URL", value:"https://www.axway.com/en/products/managed-file-transfer/securetransport");

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

# Server: SecureTransport 5.2.1 (build: 1327)
# Server: SecureTransport 5.5-20240530 (build: 3209) - Linux
if( ! egrep( string:banner, pattern:"Server\s*:\s*SecureTransport[/ ]?[0-9.]+", icase:TRUE ) ) {
  res = http_get_cache( port:port, item:url );

  if( !res || res !~ "<title>Axway SecureTransport (| )?Login" >!< res )
    exit(0);
}

version = "unknown";
location = "/";
conclUrl = "  " + http_report_vuln_url( port:port, url:url, url_only:TRUE );

set_kb_item( name:"axway/securetransport/detected", value:TRUE );
set_kb_item( name:"axway/securetransport/http/detected", value:TRUE );

vers = eregmatch( pattern:"Server: SecureTransport[/ ]?([0-9.-]+)", string:banner, icase:TRUE );
if ( isnull( vers[1] ) )
  # PrintServerInfo("SecureTransport", "5.1",
  # PrintServerInfo("SecureTransport", "5.2.1",
  vers = eregmatch( pattern:'"SecureTransport",\\s*"([0-9.]+)"', string:res );

if( ! isnull( vers[1] ) )
  version = vers[1];

cpe = build_cpe( value:version, exp:"^([0-9.-]+)", base:"cpe:/a:axway:securetransport:" );
if( ! cpe )
  cpe = "cpe:/a:axway:securetransport";

register_product( cpe:cpe, location:location, port:port, service:"www" );

log_message( data:build_detection_report( app:"Axway SecureTransport MFT", version:version, install:location,
                                          cpe:cpe, concluded:vers[0], concludedUrl:conclUrl ),
             port:port );

exit(0);
