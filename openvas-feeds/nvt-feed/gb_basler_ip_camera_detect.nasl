# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114029");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-09-10 12:17:48 +0200 (Mon, 10 Sep 2018)");
  script_name("Basler IP Camera Remote Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detects the installed version of
  Basler IP Camera.

  This script sends an HTTP GET request and tries to ensure the presence of
  Basler IP Camera.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

url = "/about.html";
res = http_get_cache(port: port, item: url);

if(res =~ "(Surveillance|IP Camera) Web Client \(c\) [0-9]+ Basler AG" && res =~ "Copyright [0-9]+ by Basler AG") {

  version = "unknown";

  set_kb_item(name: "basler/ip_camera/detected", value: TRUE);

  #<td id="info-firmware">3.5.1</td>
  ver = eregmatch(pattern: '<td id="info-firmware">([0-9.a-zA-Z-]+)</td>', string: res);
  if(ver[1]) version = ver[1];

  set_kb_item(name: "basler/ip_Camera/version", value: version);

  #<td id="info-model">BIP2-1920c-dn</td>
  model = eregmatch(pattern: '<td id="info-model">([a-zA-Z0-9-]+)</td>', string: res);
  if(model[1]) set_kb_item(name: "basler/ip_camera/model", value: model[1]);

  cpe = "cpe:/a:basler:ip_camera:";

  conclUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);

  register_and_report_cpe(app: "Basler IP Camera",
                          ver: version,
                          base: cpe,
                          expr: "^([0-9.]+)",
                          insloc: "/",
                          regPort: port,
                          conclUrl: conclUrl);
}

exit(0);
