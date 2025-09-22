# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800988");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-03-05 10:09:57 +0100 (Fri, 05 Mar 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Zenoss Server Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Zenoss Server.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("cpe.inc");
include("host_details.inc");

port = http_get_port( default:8080 );

url = "/zport/acl_users/cookieAuthHelper/login_form";
res = http_get_cache( item:url, port:port );
if( "Zenoss Login" >!< res ) exit( 0 );

install = "/";
version = "unknown";

vers = eregmatch( pattern:"<span>([0-9.]+)" ,string:res );
if( ! isnull( vers[1] ) ) version = vers[1];

set_kb_item( name:"www/" + port + "/Zenoss", value:version );
set_kb_item( name:"ZenossServer/detected", value:TRUE );
set_kb_item( name:"zenoss/server/detected", value:TRUE );
set_kb_item( name:"zenoss/server/http/detected", value:TRUE );
register_and_report_cpe( app:"Zenoss Server", ver:version, concluded:vers[0], base:"cpe:/a:zenoss:zenoss:", expr:"^([0-9.]+)", insloc:install, regPort:port );

exit( 0 );
