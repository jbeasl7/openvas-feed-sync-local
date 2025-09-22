# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140105");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-12-28 14:32:35 +0100 (Wed, 28 Dec 2016)");
  script_name("EasyIO Detection");

  script_tag(name:"summary", value:"The script performs HTTP based detection of EasyIO");

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

port = http_get_port( default:80 );

url = '/sdcard/cpt/app/signin.php';
req = http_get( item:url, port:port );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( "<title>Signin CPT Graphics</title>" >!< buf ) exit( 0 );

cpe = 'cpe:/a:easyio:easyio';
set_kb_item( name:"easyio/installed", value:TRUE );

register_product( cpe:cpe, location:"/sdcard/cpt/app/", port:port, service:"www" );

report = build_detection_report( app:"EasyIO", version:"unknown", install:"/sdcard/cpt/app/",  cpe:cpe );

log_message( port:port, data:report );

exit( 0 );


