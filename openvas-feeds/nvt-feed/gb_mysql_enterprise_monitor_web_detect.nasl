# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140128");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2025-09-05T15:40:40+0000");
  script_tag(name:"last_modification", value:"2025-09-05 15:40:40 +0000 (Fri, 05 Sep 2025)");
  script_tag(name:"creation_date", value:"2017-01-27 09:22:48 +0100 (Fri, 27 Jan 2017)");
  script_name("MySQL Enterprise Monitor Detection");

  script_tag(name:"summary", value:"This script performs detection of the MySQL Enterprise Monitor Webinterface.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");

port = http_get_port( default:18443 );

url = "/Auth.action";
req = http_get( item:url, port:port );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( "<title>Log In : MySQL Enterprise Dashboard</title>" >< buf ) {

  CPE = "cpe:/a:mysql:enterprise_monitor";

  register_product( cpe:CPE, location:"/", port:port, service:"www" );

  report = build_detection_report( app:"MySQL Enterprise Monitor", install:"/", cpe:CPE );
  log_message( port:port, data:report );

  exit( 0 );
}

exit( 0 );

