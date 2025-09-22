# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808659");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-08-23 15:56:59 +0530 (Tue, 23 Aug 2016)");
  script_name("Honeywell IP-Camera Detection");

  script_tag(name:"summary", value:"Detects the installed version of
  Honeywell IP-Cameras.

  This script sends an HTTP GET request and tries to ensure the presence of
  Honeywell IP-Cameras.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("host_details.inc");

achPort = http_get_port(default:80);

foreach dir(make_list_unique("/", "/cgi-bin", http_cgi_dirs(port:achPort)))
{
  install = dir;
  if(dir == "/") dir = "";

  sndReq = http_get(item: dir + "/chksession.cgi", port:achPort);
  rcvRes = http_send_recv(port:achPort, data:sndReq);

  if('<title>Honeywell IP-Camera login</title>' >< rcvRes && 'password' >< rcvRes)
  {
    version = "unknown";

    set_kb_item(name:"Honeywell/IP_Camera/Installed", value:TRUE);

    ## Created new cpe
    cpe = "cpe:/a:honeywell:honeywell_ip_camera";

    register_product(cpe:cpe, location:install, port:achPort, service:"www");

    log_message( data:build_detection_report( app:"Honeywell IP-Camera",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concluded:version),
                                              port:achPort);
  }
}
exit(0);
