# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807894");
  script_version("2024-06-13T05:05:46+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-06-13 05:05:46 +0000 (Thu, 13 Jun 2024)");
  script_tag(name:"creation_date", value:"2016-10-05 16:18:47 +0530 (Wed, 05 Oct 2016)");
  script_name("Serimux SSH Console Switch Detection");

  script_tag(name:"summary", value:"Detects the installed version of
  Serimux SSH Console Switch.

  This script sends an HTTP GET request and tries to ensure the presence of
  Serimux SSH Console Switch.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "global_settings.nasl",
                      "gb_microsoft_iis_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("host_details.inc");

serPort = http_get_port( default:80 );
if( ! http_can_host_asp( port:serPort ) ) exit( 0 );

foreach dir(make_list_unique("/", "/cgi_dir", http_cgi_dirs(port:serPort))) {

  install = dir;
  if(dir == "/") dir = "";

  sndReq = http_get(item: dir + "/nti/login.asp", port:serPort);
  rcvRes = http_send_recv(port:serPort, data:sndReq);

  if(">SERIMUX-S-x Console Switch" >< rcvRes && ">Welcome, please log in" >< rcvRes)
  {
    version = "unknown";

    set_kb_item(name:"Serimux/Console/Switch/Installed", value:TRUE);

    ## Created new cpe
    cpe = "cpe:/a:serimux:serimux_console_switch";

    register_product(cpe:cpe, location:install, port:serPort, service:"www");

    log_message(data:build_detection_report( app:"Serimux SSH Console Switch",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concluded:version),
                                              port:serPort);
    exit(0);
  }
}
exit(0);
