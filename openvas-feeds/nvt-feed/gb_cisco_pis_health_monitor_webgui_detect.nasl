# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105840");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-08-01 09:56:19 +0200 (Mon, 01 Aug 2016)");
  script_name("Cisco Prime Infrastructure Health Monitor Detection");

  script_tag(name:"summary", value:"The script sends a connection request to the server and attempts to extract the version number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8082);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");

port = http_get_port( default:8082 );

buf = http_get_cache( port:port, item:"/login.jsp" );

if( "Cisco Prime Infrastructure" >!< buf || "Health Monitor Login Page" >!< buf ) exit( 0 );

set_kb_item( name:"ciscp_prime_infrastructure/health_monitor/installed", value:TRUE );
set_kb_item( name:"ciscp_prime_infrastructure/health_monitor/port", value:port );

version = eregmatch( pattern:'productVersion">[\r\n]*\\s*Version: ([0-9.]+)', string:buf );
if( ! isnull( version[1] ) )
{
  vers = version[1];
  set_kb_item( name:"ciscp_prime_infrastructure/health_monitor/version", value:vers );
}

report = "Cisco Prime Infrastructure Health Monitor Login Page is running at this port.";
if( vers ) report += '\nVersion: '+ vers +'\nCPE: cpe:/a:cisco:prime_infrastructure\n';

log_message( port:port, data:report );
exit( 0 );
