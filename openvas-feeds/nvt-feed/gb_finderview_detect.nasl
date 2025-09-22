# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808096");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2016-06-27 13:22:53 +0530 (Mon, 27 Jun 2016)");
  script_name("FinderView Version Detection");

  script_tag(name:"summary", value:"Detects the installed version of
  FinderView.

  This script sends an HTTP GET request and tries to ensure the presence of FinderView
  from the response.");

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

find_port = http_get_port(default:80);
if(! http_can_host_php(port:find_port)) exit(0);

foreach dir(make_list_unique("/", "/FinderView-master", "/FinderView", http_cgi_dirs(port:find_port)))
{

  install = dir;
  if( dir == "/" ) dir = "";

  url = dir + '/index.html';
  rcvRes = http_get_cache(item:url, port:find_port);

  if(">Finder View<" >< rcvRes && rcvRes =~ "^HTTP/1\.[01] 200" && "<th>Folder<" >< rcvRes)
  {
    version = "unknown";

    set_kb_item(name:"FinderView/Installed", value:TRUE);

    cpe = "cpe:/a:finderview:finderview";

    register_product(cpe:cpe, location:install, port:find_port, service:"www");

    log_message(data:build_detection_report(app:"FinderView",
                                            version:version,
                                            install:install,
                                            cpe:cpe,
                                            concluded:version),
                                            port:find_port);
    exit(0);
  }
}
