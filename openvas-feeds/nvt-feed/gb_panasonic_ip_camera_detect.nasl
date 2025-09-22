# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114044");
  script_version("2023-07-27T05:05:09+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:09 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-11-05 22:37:25 +0100 (Mon, 05 Nov 2018)");
  script_name("Panasonic IP Camera Remote Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detects the installation of Panasonic's
  IP camera software.

  This script sends an HTTP GET request and tries to ensure the presence of
  Panasonic's IP camera software.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

url = "/admin/index.html?Language=0";
res = http_get_cache(port: port, item: url);

if(res =~ 'Basic realm="Panasonic [nN]etwork [dD]evice"') {

  #Only available after a successful login
  version = "unknown";
  model = "unknown";

  url2 = "/";
  res2 = http_get_cache(port: port, item: url2);

  #<title>WV-SPW631L Network Camera</title>
  #<title>WV-SPW631L Netzwerk-Kamera</title>
  mod = eregmatch(pattern: "(WV-[a-zA-Z0-9]+) (Network Camera|Netzwerk-Kamera)", string: res2);
  if(!isnull(mod[1])) model = mod[1];

  set_kb_item(name: "panasonic/ip_camera/detected", value: TRUE);
  set_kb_item(name: "panasonic/ip_camera/" + port + "/detected", value: TRUE);
  set_kb_item(name: "panasonic/ip_camera/model", value: model);
  cpe = "cpe:/a:panasonic:ip_camera:";

  conclUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);

  register_and_report_cpe(app: "Panasonic IP Camera",
                          ver: version,
                          base: cpe,
                          expr: "^([0-9.]+)",
                          insloc: "/",
                          regPort: port,
                          conclUrl: conclUrl,
                          extra: "Model: " + model + "; Note: Login required for version detection.");
}

exit(0);
