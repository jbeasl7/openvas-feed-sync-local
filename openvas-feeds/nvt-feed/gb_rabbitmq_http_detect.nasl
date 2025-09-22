# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105178");
  script_version("2025-03-27T05:38:50+0000");
  script_tag(name:"last_modification", value:"2025-03-27 05:38:50 +0000 (Thu, 27 Mar 2025)");
  script_tag(name:"creation_date", value:"2015-01-22 17:22:26 +0100 (Thu, 22 Jan 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("RabbitMQ Server Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of RabbitMQ Server.");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port( default:443 );

url = "/";

res = http_get_cache( port:port, item:url );

if( "<title>RabbitMQ Management</title>" >!< res )
  exit( 0 );

version = "unknown";
conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );

set_kb_item( name:"rabbitmq/detected", value:TRUE );
set_kb_item( name:"rabbitmq/http/detected", value:TRUE );
set_kb_item( name:"rabbitmq/http/port", value:port );
set_kb_item( name:"rabbitmq/http/" + port + "/concludedUrl", value:conclUrl );

set_kb_item( name:"rabbitmq/http/" + port + "/version", value:version );

exit(0);
