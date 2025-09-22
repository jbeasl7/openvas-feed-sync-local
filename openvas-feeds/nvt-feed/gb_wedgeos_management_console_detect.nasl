# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105310");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2025-01-30T05:38:01+0000");
  script_tag(name:"last_modification", value:"2025-01-30 05:38:01 +0000 (Thu, 30 Jan 2025)");
  script_tag(name:"creation_date", value:"2015-07-02 11:20:01 +0200 (Thu, 02 Jul 2015)");
  script_name("Wedge Networks wedgeOS Management Console Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of the Wedge Networks wedgeOS Management
  Console.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");

port = http_get_port( default:443 );

host = http_host_name( dont_add_port:TRUE );

url = "/ssgmanager/about.jsf";
buf = http_get_cache( item:url, port:port );

if( "Management Console" >< buf && ">About<" >< buf && "Wedge Networks" >< buf && "wedgeOS" >< buf ) {

  # nb: For JavaServer Faces active checks (See "about.jsf" above)
  set_kb_item( name:"www/javaserver_faces/detected", value:TRUE );
  set_kb_item( name:"www/javaserver_faces/" + host + "/" + port + "/detected", value:TRUE );

  set_kb_item( name:"wedgeOS/management_console/installed", value:TRUE );

  install = "/ssgmanager";
  vers = "unknown";
  cpe = "cpe:/a:wedge_networks:wedgeos";

  version = eregmatch( pattern:'>VERSION ([0-9.-]+)', string:buf );
  if( ! isnull( version[1] ) ) {
    vers = version[1];
    cpe += ":" + vers;
  }

  register_product( cpe:cpe, location:install, port:port, service:"www" );

  log_message( data:build_detection_report( app:"Wedge Networks wedgeOS",
                                            version:vers,
                                            install:install,
                                            cpe:cpe,
                                            concluded: version[0] ),
               port:port );
  exit( 0 );
}

exit(0);

