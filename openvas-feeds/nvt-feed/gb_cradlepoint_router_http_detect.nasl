# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112451");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-12-06 10:55:11 +0100 (Thu, 06 Dec 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Cradlepoint Routers Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This script performs HTTP based detection of Cradlepoint routers.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port( default:8080 );
buf  = http_get_cache( item:"/login/", port:port );

if( buf =~ "^HTTP/1\.[01] 200" &&
    ( 'manufacturer: "Cradlepoint Inc."' >< buf ||
    ( "cplogin = window.cplogin" >< buf && 'cplogin.state' >< buf ) )
  ) {

  model      = "unknown";
  fw_version = "unknown";

  mod = eregmatch( pattern:'cplogin.model = "([A-Za-z0-9-]+)";', string:buf, icase:TRUE );
  if( mod[1] ) {
    model = mod[1];
    set_kb_item( name:"cradlepoint/router/http/" + port + "/concluded", value:mod[0] );
  }

  fw = eregmatch( pattern:'cplogin.version = "([0-9.]+) ', string:buf );
  if( fw[1] ) {
    fw_version = fw[1];
  }

  set_kb_item( name:"cradlepoint/router/http/" + port + "/model", value:model );
  set_kb_item( name:"cradlepoint/router/http/" + port + "/fw_version", value:fw_version );
  set_kb_item( name:"cradlepoint/router/http/detected", value:TRUE );
  set_kb_item( name:"cradlepoint/router/http/port", value:port );
  set_kb_item( name:"cradlepoint/router/detected", value:TRUE );
}

exit( 0 );
