# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807645");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2016-04-06 16:25:00 +0530 (Wed, 06 Apr 2016)");
  script_name("Achievo Detection");

  script_tag(name:"summary", value:"Detection of Achievo application.

  This script sends an HTTP GET request and tries to get the version from the
  response.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("host_details.inc");

achPort = http_get_port(default:80);

if(!http_can_host_php(port:achPort)) exit(0);

foreach dir(make_list_unique("/", "/achievo", "/cms", http_cgi_dirs(port:achPort)))
{
  install = dir;
  if(dir == "/") dir = "";

  rcvRes = http_get_cache(item: dir + "/index.php", port:achPort);

  if('<title>Achievo</title>' >< rcvRes && 'login' >< rcvRes)
  {
    version = "unknown";

    set_kb_item(name:"www/" + achPort + "/achievo", value:version);
    set_kb_item(name:"Achievo/Installed", value:TRUE);

    cpe = "cpe:/a:achievo:achievo";

    register_product(cpe:cpe, location:install, port:achPort, service:"www");

    log_message( data:build_detection_report( app:"Achievo",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concluded:version),
                                              port:achPort);
  }
}
exit(0);
