# SPDX-FileCopyrightText: 2006 Ferdy Riphagen
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.20225");
  script_version("2023-07-12T05:05:05+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:05 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Kerio WinRoute Firewall Management Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2006 Ferdy Riphagen");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 4080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Kerio WinRoute Firewall application
  management interface.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port( default:4080 );

res = http_get_cache( item:"/", port:port );
if( ! res ) exit( 0 );

if( "Kerio WinRoute Firewall" >< res && line = egrep( pattern:"Kerio WinRoute Firewall [0-9.]+", string:res ) ) {

  version = ereg_replace( pattern:".*Kerio WinRoute Firewall ([0-9.]+).*", string:line, replace:"\1" );
  if( version == line )
    version = "unknown";

  if( version != "unknown" )
    set_kb_item( name:"www/" + port + "/kerio_wrf", value:version );

  register_and_report_cpe( app:"Kerio WinRoute Firewall Management Webserver", ver:version, concluded:line, regService:"www", regPort:port, base:"cpe:/a:kerio:winroute_firewall:", expr:"^([0-9.]+)", insloc:"/" );
}

exit( 0 );
