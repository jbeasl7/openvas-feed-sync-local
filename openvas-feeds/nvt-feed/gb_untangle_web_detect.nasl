# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105813");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-07-18 15:32:04 +0200 (Mon, 18 Jul 2016)");
  script_name("Untangle NG Firewall Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This script performs HTTP based detection of Untangle NG Firewall.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");

port = http_get_port( default:80 );

url = "/auth/login";
buf = http_get_cache( item:url, port:port );

if( "<title>Untangle Administrator Login</title>" >< buf && "username" >< buf && "password" >< buf )
{
  cpe = 'cpe:/a:untangle:ng-firewall';
  set_kb_item( name:"untangle/installed", value:TRUE );

  register_product( cpe:cpe, location:'/', port:port, service:'www' );
  log_message( port:port, data:'The Untangle NG Firewall Webinterface is running at this port.\nCPE: cpe:/a:untangle:ng-firewall');
}

exit( 0 );
