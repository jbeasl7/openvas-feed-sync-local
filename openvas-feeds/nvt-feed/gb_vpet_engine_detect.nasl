# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808173");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2016-06-27 12:38:20 +0530 (Mon, 27 Jun 2016)");
  script_name("VPet Engine Version Detection");

  script_tag(name:"summary", value:"Detects the installed version of VPet Engine.

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

vpet_Port = http_get_port(default:80);
if(!http_can_host_php(port:vpet_Port)) exit(0);

foreach dir(make_list_unique("/", "/vpet", "/vPetEngine", http_cgi_dirs(port:vpet_Port))) {

  install = dir;
  if(dir == "/") dir = "";

  rcvRes = http_get_cache(item: dir + "/index.php", port:vpet_Port);

  if(rcvRes =~ "^HTTP/1\.[01] 200" && '<TITLE>vPetOnline - Home</TITLE>' >< rcvRes &&
     '>Login<' >< rcvRes)
  {
    ver = eregmatch(pattern:'vPet Engine V.([0-9.]+)<', string:rcvRes);
    if(ver[1]){
      version = ver[1];
    } else {
      version = "Unknown";
    }

    set_kb_item(name:"www/" + vpet_Port + install, value:version);
    set_kb_item(name:"vPet/Engine/Installed", value:TRUE);

    cpe = build_cpe(value: version, exp:"([0-9.]+)", base:"cpe:/a:vpet:vpet_engine:");
    if(!cpe)
    cpe = "cpe:/a:vpet:vpet_engine";

    register_product(cpe:cpe, location:install, port:vpet_Port, service:"www");

    log_message( data:build_detection_report( app:"vPet Engine",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concluded:version),
                                              port:vpet_Port);
  }
}

exit(0);
