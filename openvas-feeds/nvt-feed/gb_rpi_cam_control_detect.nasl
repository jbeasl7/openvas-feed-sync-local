# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812361");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-12-26 12:43:03 +0530 (Tue, 26 Dec 2017)");
  script_name("RPi Cam Control Detection");

  script_tag(name:"summary", value:"Detects the installed version of
  RPi Cam Control.

  This script sends an HTTP GET request and tries to ensure the presence of
  RPi Cam Control");

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
include("cpe.inc");

ripPort = http_get_port(default:80);

rcvRes = http_get_cache(port:ripPort, item:"/");
if('<title>RPi Cam Control' >< rcvRes)
{
  version = "unknown";

  ripVer = eregmatch(pattern:">RPi Cam Control v([0-9.]+):", string:rcvRes);
  if(ripVer[1]){
    version = ripVer[1];
  }

  set_kb_item(name:"RPi/Cam/Control/Installed", value:TRUE);

  cpe = build_cpe(value:version, exp:"([0-9.]+)", base:"cpe:/a:rpi:cam_control:");
  if(!cpe){
    cpe= "cpe:/a:rpi:cam_control";
  }

  register_product(cpe:cpe, location:"/", port:ripPort, service:"www");

  log_message(data: build_detection_report( app:"RPi Cam Control",
                                            version:version,
                                            install:"/",
                                            cpe:cpe,
                                            concluded:ripVer),
                                            port:ripPort);
}

exit(0);
