# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807553");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2016-04-25 12:39:59 +0530 (Mon, 25 Apr 2016)");
  script_name("PHPmongoDB Remote Version Detection");

  script_tag(name:"summary", value:"Detects the installed version of
  PHPmongoDB.

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

include("cpe.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("host_details.inc");

mongoPort = http_get_port(default:80);
if(!http_can_host_php(port:mongoPort))
  exit(0);

foreach dir (make_list_unique("/", "/phpmongodb", "/PHPmongoDB", http_cgi_dirs(port:mongoPort))) {

  install = dir;
  if( dir == "/" ) dir = "";

  url = dir + "/index.php";
  rcvRes = http_get_cache(item:url, port:mongoPort);

  if('<title>PHPmongoDB </title>' ><  rcvRes && 'content="mongoDB' >< rcvRes &&
     rcvRes =~ 'copy.*PHPmongoDB.org' && '>Sign In' >< rcvRes)
  {
    url = dir + '/README.md';

    sndReq = http_get(item:url, port:mongoPort);
    rcvRes = http_keepalive_send_recv(port:mongoPort, data:sndReq, bodyonly:TRUE);

    version = eregmatch(pattern:'version ([0-9.]+)', string:rcvRes);
    if(version[1]){
      phpmongoVer = version[1];
    } else {
      phpmongoVer = "Unknown";
    }

    set_kb_item(name:"PHPmongoDB/Installed", value:TRUE);

    ## cpe is not available. so created new
    cpe = build_cpe(value:phpmongoVer, exp:"^([0-9.]+)", base:"cpe:/a:php:mongodb:");
    if(!cpe)
      cpe = "cpe:/a:php:mongodb";

    register_product(cpe:cpe, location:install, port:mongoPort, service:"www");

    log_message(data: build_detection_report(app: "PHPmongoDB",
                                             version: phpmongoVer,
                                             install: install,
                                             cpe: cpe,
                                             concluded: phpmongoVer),
                                             port: mongoPort);
  }
}
