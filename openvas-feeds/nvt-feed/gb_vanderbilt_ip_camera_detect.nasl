# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808661");
  script_version("2023-07-27T05:05:09+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:09 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-08-23 15:56:59 +0530 (Tue, 23 Aug 2016)");
  script_name("Vanderbilt IP-Camera Detection");

  script_tag(name:"summary", value:"Detects the installed version of
  Vanderbilt IP-Cameras.

  This script sends an HTTP GET request and tries to ensure the presence of
  Vanderbilt IP-Cameras.");

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

vanPort = http_get_port(default:80);

foreach dir(make_list_unique("/", "/cgi-bin", http_cgi_dirs(port:vanPort)))
{
  install = dir;
  if(dir == "/") dir = "";

  sndReq = http_get(item: dir + "/chklogin.cgi", port:vanPort);
  rcvRes = http_send_recv(port:vanPort, data:sndReq);

  if('<title>Vanderbilt IP-Camera login</title>' >< rcvRes && 'password' >< rcvRes)
  {
    version = "unknown";

    set_kb_item(name:"Vanderbilt/IP_Camera/Installed", value:TRUE);

    ## Created new cpe
    cpe = "cpe:/a:vanderbilt:vanderbilt_ip_camera";

    register_product(cpe:cpe, location:install, port:vanPort, service:"www");

    log_message(data:build_detection_report(app:"Vanderbilt IP-Camera",
                                            version:version,
                                            install:install,
                                            cpe:cpe,
                                            concluded:version),
                                            port:vanPort);
  }
}
exit(0);
