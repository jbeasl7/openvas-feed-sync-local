# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812363");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-12-26 17:43:03 +0530 (Tue, 26 Dec 2017)");
  script_name("Western Digital ShareSpace WEB GUI Detect");

  script_tag(name:"summary", value:"Detects the installed version of
  Western Digital ShareSpace.

  This script sends an HTTP GET request and tries to ensure the presence of
  Western Digital ShareSpace");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");

wdPort = http_get_port(default:80);

rcvRes = http_get_cache(port:wdPort, item:"/");
if(rcvRes =~ "<title>WD ShareSpace.*ShareSpace<" && rcvRes =~ "Copyright.*Western Digital Technologies"
   && ">Login<" >< rcvRes)
{
  version = "Unknown";
  set_kb_item( name:"WD/ShareSpace/detected", value:TRUE);
  cpe = 'cpe:/a:western_digital:sharespace';
  location = "/";

  register_product( cpe:cpe, port:wdPort, location:location, service:"www");
  log_message( data:build_detection_report( app:"Western Digital ShareSpace",
                                            version:version,
                                            install:location,
                                            cpe:cpe),
                                            port:wdPort);
}

exit(0);
