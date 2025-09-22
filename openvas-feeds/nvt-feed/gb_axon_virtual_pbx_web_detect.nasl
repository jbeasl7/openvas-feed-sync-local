# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108033");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-01-02 10:00:00 +0100 (Mon, 02 Jan 2017)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Axon Virtual PBX Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 81);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Axon Virtual PBX.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("cpe.inc");
include("host_details.inc");

port = http_get_port( default:81 );

res = http_get_cache( item:"/", port:port );

if( "title>Axon - Login" >< res || "Main Page'>Axon</td>" >< res || "target=_blank>www.nch.com.au</a>" >< res ) {

  version = "unknown";

  ver = eregmatch( pattern:"v&.+([0-9]\.[0-9]+)", string:res );

  if( ! isnull( ver[1] ) ) version = ver[1];

  set_kb_item( name:"Axon-Virtual-PBX/installed", value:TRUE );
  set_kb_item( name:"Axon-Virtual-PBX/www/" + port + "/ver", value:version );
  set_kb_item( name:"Axon-Virtual-PBX/www/installed", value:TRUE );

  cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:nch:axon_virtual_pbx:" );
  if( ! cpe )
    cpe = "cpe:/a:nch:axon_virtual_pbx";

  location = "/";

  register_product( cpe:cpe, port:port, location:location, service:"www" );
  log_message( data:build_detection_report( app:"Axon Virtual PBX",
                                            version:version,
                                            install:location,
                                            cpe:cpe,
                                            concluded:ver[0] ),
                                            port:port );
}

exit( 0 );
