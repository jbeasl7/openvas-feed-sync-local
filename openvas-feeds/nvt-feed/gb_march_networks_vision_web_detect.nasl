# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114042");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-11-05 18:28:04 +0100 (Mon, 05 Nov 2018)");
  script_name("March Networks VisionWEB Remote Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8001);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detects the installation of March
  Networks VisionWEB.

  This script sends an HTTP GET request and tries to ensure the presence of
  March Networks VisionWEB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 8001);

url = "/visionweb/index2.html";
res = http_get_cache(port: port, item: url);

if('<meta name="DESCRIPTION" content="VisionWEB. March Networks SpA' >< res && 'March Networks S.p.A."' >< res) {

  version = "unknown";

  set_kb_item(name: "march_networks/visionweb/detected", value: TRUE);
  set_kb_item(name: "march_networks/visonweb/" + port + "/detected", value: TRUE);

  #codebase="NettunoVisionWEB.cab#version=2,9,3814,1008"
  vers = eregmatch(pattern: 'codebase="NettunoVisionWEB.cab#version=([0-9]+),([0-9]+),([0-9]+),([0-9]+)"', string: res);
  if(!isnull(vers[1]) && !isnull(vers[2]) && !isnull(vers[3]) && !isnull(vers[4]))
    version = vers[1] + "." + vers[2] + "." + vers[3] + "." + vers[4];

  set_kb_item(name: "march_networks/visonweb/version", value: version);

  cpe = "cpe:/a:march_networks:visionweb:";

  conclUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);

  register_and_report_cpe(app: "March Networks VisionWEB",
                          ver: version,
                          base: cpe,
                          expr: "^([0-9.]+)",
                          insloc: "/",
                          regPort: port,
                          conclUrl: conclUrl);
}

exit(0);
