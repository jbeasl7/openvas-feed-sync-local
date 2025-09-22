# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140137");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-01-31 15:41:36 +0100 (Tue, 31 Jan 2017)");
  script_name("EMC Secure Remote Services Webinterface Detection");

  script_tag(name:"summary", value:"This script performs HTTP based detection of EMC Secure Remote Services Webinterface");
  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 9443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");

port = http_get_port( default:9443);

url = '/esrs/html/about.html';
req = http_get( item:url, port:port );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( "<h2>About EMC Secure Remote Services" >< buf )
{
  cpe = 'cpe:/a:emc:secure_remote_services';

  register_product( cpe:cpe, location:"/esrs", port:port, service:"www" );
  log_message( port:port, data:'The EMC Secure Remote Services Webinterface is running at this port.\nCPE: ' + cpe + '\n' );
  exit( 0 );
}

exit( 0 );
