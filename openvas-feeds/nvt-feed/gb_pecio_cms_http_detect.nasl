# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801443");
  script_version("2024-11-22T15:40:47+0000");
  script_tag(name:"last_modification", value:"2024-11-22 15:40:47 +0000 (Fri, 22 Nov 2024)");
  script_tag(name:"creation_date", value:"2010-09-10 16:37:50 +0200 (Fri, 10 Sep 2010)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Pecio CMS Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl",
                      "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Pecio CMS.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("cpe.inc");
include("host_details.inc");

port = http_get_port(default:80);
if(!http_can_host_php(port:port))
  exit(0);

foreach dir(make_list_unique("/pecio", "/pecio_cms", "/pecio-cms", http_cgi_dirs(port:port))) {

  install = dir;
  if(dir == "/")
    dir = "";

  url = dir + "/index.php";
  res = http_get_cache(item:url, port:port);
  if(!res || res !~ "^HTTP/1\.[01] 200")
    continue;

  if('content="pecio cms'>< res || ">pecio homepage</" >< res) {

    version = "unknown";

    vers = eregmatch(pattern:"pecio cms ([0-9.]+)", string:res);
    if(vers[1])
      version = vers[1];

    set_kb_item(name:"pecio_cms/detected", value:TRUE);
    set_kb_item(name:"pecio_cms/http/detected", value:TRUE);

    cpe = build_cpe(value:version, exp:"^([0-9.]+)", base:"cpe:/a:pecio-cms:pecio_cms:");
    if(!cpe)
      cpe = "cpe:/a:pecio-cms:pecio_cms";

    register_product(cpe:cpe, location:install, port:port, service:"www");

    log_message(data:build_detection_report(app:"Pecio CMS", version:version, install:install,
                                            cpe:cpe, concluded:vers[0]),
                port:port);
  }
}

exit(0);
