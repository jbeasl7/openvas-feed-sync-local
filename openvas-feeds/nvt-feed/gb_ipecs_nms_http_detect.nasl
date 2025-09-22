# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141022");
  script_version("2025-06-26T05:40:52+0000");
  script_tag(name:"last_modification", value:"2025-06-26 05:40:52 +0000 (Thu, 26 Jun 2025)");
  script_tag(name:"creation_date", value:"2018-04-25 12:19:41 +0700 (Wed, 25 Apr 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("iPECS (Ericsson-LG) NMS Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of iPECS (an Ericsson-LG brand) NMS.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.ipecs.com/");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

res = http_get_cache(port: port, item: "/");

if ("<title>iPECS NMS</title>" >< res && "images/ipecs.png" >< res) {
  version = "unknown";
  install = "/";

  set_kb_item(name: "ipecs/nms/detected", value: TRUE);
  set_kb_item(name: "ipecs/nms/http/detected", value: TRUE);
  set_kb_item(name: "ipecs/product/detected", value: TRUE);
  set_kb_item(name: "ipecs/product/http/detected", value: TRUE);

  cpe = "cpe:/a:ericssonlg:ipecs_nms";

  register_product(cpe: cpe, location: install, port: port, service: "www");

  log_message(data: build_detection_report(app: "iPECS (Ericsson-LG) NMS", version: version, install: install, cpe: cpe),
              port: port);
  exit(0);
}

exit(0);
