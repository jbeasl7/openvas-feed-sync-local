# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900200");
  script_version("2023-07-12T05:05:05+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:05 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-02-06 06:53:35 +0100 (Fri, 06 Feb 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Sun Java System/ONE Application Server Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of the Sun Java System/ONE Application Server.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("cpe.inc");
include("host_details.inc");

port = http_get_port( default:8080 );
res = http_get_cache( item:"/", port:port );
if( ! res )
  exit( 0 );

## Sun Java System Application Server Formerly known as
## Sun ONE Application Server and now it is known as
## Sun GlassFish Enterprise Server
## http://www.sun.com/software/products/appsrvr/index.jsp

## Server: Sun-ONE-Application-Server/7.0.0_11
## Server: Sun-Java-System-Application-Server/7 2004Q2UR6
## Sun Java System Application Server Platform Edition 9.0_01

vers = eregmatch( pattern:"Server: Sun[- a-zA-Z]+Application[- ]Server/?([a-zA-Z0-9._ ]+)", string:res );
if( vers[1] ) {
  version = vers[1] - " Platform Edition ";
  version = chomp( version );
  found = TRUE;
} else if( egrep( pattern:"Sun Java System Application Server .*", string:res ) ) {

  vers = eregmatch( pattern:"Platform Edition ([0-9.]+)", string:res );
  if( vers[1] ) {
    version = vers[1];
    found = TRUE;
  }
}

if( found ) {
  set_kb_item( name:"sun_java_appserver/installed", value:TRUE );
  set_kb_item( name:"sun_java_appserver/detected", value:TRUE );
  set_kb_item( name:"sun_java_appserver/http/detected", value:TRUE );
  set_kb_item( name:"glassfish_or_sun_java_appserver/installed", value:TRUE );

  register_and_report_cpe( app:"Sun Java Application Server", ver:version, concluded:vers[0],
                           base:"cpe:/a:sun:java_system_application_server:",
                           expr:"^([0-9.]+)", insloc:"/", regService:"www" );
}

exit( 0 );
