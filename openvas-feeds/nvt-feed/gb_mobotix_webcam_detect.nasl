# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113232");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-07-18 09:55:45 +0200 (Wed, 18 Jul 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Mobotix Webcam Detection");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Mobotix Webcam devices.");

  script_xref(name:"URL", value:"https://www.mobotix.com");

  exit(0);
}

CPE = "cpe:/h:mobotix:webcam:";

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("cpe.inc");

port = http_get_port( default: 8080 );

buf = http_get_cache( port: port, item: "/" );

if( buf =~ 'content="MOBOTIX AG, Germany"' &&
  ( buf =~ '/control/camerainfo'  || buf =~ 'title=\'Show Camera info\'' ) ) {
  set_kb_item( name: "mobotix/webcam/detected", value: TRUE );
  set_kb_item( name: "mobotix/webcam/http_port", value: port );

  model = "unknown";
  mod = eregmatch( string: buf, pattern: '<b>MOBOTIX ([A-Za-z0-9]+)</b>' );
  if( ! isnull( mod[1] ) ) {
    model = mod[1];
  }
  set_kb_item( name: "mobotix/webcam/model", value: model );

  register_and_report_cpe( app: "Mobotix Webcam",
                           base: CPE,
                           expr: '([0-9]+)',
                           insloc: '/',
                           regPort: port );
}
exit( 0 );
