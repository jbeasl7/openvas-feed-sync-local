# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107232");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-08-25 11:19:19 +0700 (Fri, 25 Aug 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("JetBrains IDE Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of JetBrains IDE products.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 8090);
  script_mandatory_keys("JetBrainsIDEs/banner");

  script_xref(name:"URL", value:"https://www.jetbrains.com/");

  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("misc_func.inc" );
include("host_details.inc");

port = http_get_port( default: 8090 );

banner = http_get_remote_headers( port: port );
if( ! banner )
  exit( 0 );

if( ! concl = egrep( string: banner, pattern:"server\s*:\s*(PyCharm|WebStorm|CLion|DataGrip|IntelliJ IDEA|JetBrains MPS|jetBrains Rider|RubyMine)", icase: TRUE ) )
  exit( 0 );

concl = chomp( concl );
set_kb_item( name: "jetBrains/installed", value: TRUE);
set_kb_item( name: "jetbrains/product/detected", value: TRUE);
set_kb_item( name: "jetbrains/product/http/detected", value: TRUE);

random = rand_str( length: 13, charset: "0123456789" );
url = "/api/about?more-true?a=" + random;

req = http_get_req( port: port, url: url, add_headers: make_array( 'Content-Type', 'application/xml' ) );
res = http_keepalive_send_recv( port: port, data: req );

ide_version = "unknown";

name = eregmatch( pattern: 'name": "(PyCharm|WebStorm|CLion|DataGrip|IntelliJ|JetBrains|JetBrains|jetBrains|RubyMine).*([0-9.]+)",', string: res );
if (!isnull(name)) {
  ide_name = name[1];
  ide_version = name[2];
  concl = name[0];
  set_kb_item( name: "jetBrains/ide", value: ide_name );
}

configPath = eregmatch( pattern: 'configPath": "(.*)config",', string: res);
if (!isnull(configPath[1])) {
  configPath = configPath[1] + "config";
  set_kb_item( name: "jetBrains/configpath", value: configPath );
}

homePath = eregmatch( pattern: 'homePath": "(.*)"', string: res);
if (!isnull(homePath[1])) {
  homePath = homePath[1];
  set_kb_item( name: "jetBrains/homepath", value: homePath);
}

cpe = build_cpe( value: ide_version, exp: "^([0-9.]+)", base: "cpe:/a:jetbrains:jetbrains:" );
if (!cpe)
  cpe = "cpe:/a:jetbrains:jetbrains";

register_product( cpe: cpe, port: port, location: "/", service: "www" );

log_message(data: build_detection_report( app: "JetBrains " + ide_name , version: ide_version, install: "/",
                                          cpe: cpe, concluded: concl, concludedUrl: url),
            port: port );

exit( 0 );
