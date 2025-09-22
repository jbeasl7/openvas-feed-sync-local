# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113094");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-01-26 12:39:40 +0100 (Fri, 26 Jan 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Reservo Image Hosting Detection");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Product detection for Reservo Image Hosting Server.");

  script_xref(name:"URL", value:"https://reservo.co/");

  exit(0);
}

CPE = "cpe:/a:reservo:image_hosting";

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");

install = "/";
port = http_get_port( default: 80 );

buf = http_get_cache( item: install, port: port );

if( "themes/reservo/frontend" >< buf ) {
  set_kb_item( name: "reservo/installed", value: TRUE );

  register_product( cpe: CPE, location: install, port: port, service: "www" );
  log_message( data:build_detection_report( app:"Reservo Image Hosting",
                                            install: install,
                                            cpe: CPE ),
                                            port: port);
}

exit( 0 );
