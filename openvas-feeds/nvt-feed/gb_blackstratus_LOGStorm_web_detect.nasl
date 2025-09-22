# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140091");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-12-05 15:30:53 +0100 (Mon, 05 Dec 2016)");
  script_name("BlackStratus LOGStorm Detection");

  script_tag(name:"summary", value:"The script sends a connection request to the server and attempts to extract the version number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");

port = http_get_port( default:443 );

url = '/tvs/Start.do';
req = http_get( item:url, port:port );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( "<title>BlackStratus LOGStorm" >!< buf || ">Appliance Administration" >!< buf ) exit( 0 );

cpe = 'cpe:/a:blackstratus:logstorm';
set_kb_item( name:'blackstratus/logstorm/detected', value:TRUE );

v = eregmatch( pattern:'>BlackStratus LOGStorm[ ]+v([0-9.]+) -', string:buf );

if( ! isnull( v[1] ) )
{
  version = v[1];
  cpe += ':' + version;
  set_kb_item( name:'blackstratus/logstorm/version', value:version );
}

register_product( cpe:cpe, location:url, port:port, service:"www" );

report = build_detection_report( app:"BlackStratus LOGStorm", version:version, install:url, cpe:cpe, concluded:v[0], concludedUrl:url);

log_message( port:port, data:report );

exit( 0 );

