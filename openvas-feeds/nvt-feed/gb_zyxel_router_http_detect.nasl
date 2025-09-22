# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.149029");
  script_version("2025-01-31T05:37:27+0000");
  script_tag(name:"last_modification", value:"2025-01-31 05:37:27 +0000 (Fri, 31 Jan 2025)");
  script_tag(name:"creation_date", value:"2022-12-19 05:32:09 +0000 (Mon, 19 Dec 2022)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Zyxel Router / Gateway Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Zyxel Router / Gateway devices.");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

url = "/";

res = http_get_cache(port: port, item: url);

if (res !~ "'?title'?>\.::Welcome to the Web-Based Configurator::\." || res !~ "zyxel(help)?\.js") {
  url = "/login/login.html";

  res = http_get_cache(port: port, item: url);

  if (res !~ "'?title'?>\.::Welcome to [^:]+::\." || 'name="AuthPassword"' >!< res)
    exit(0);
}

model = "unknown";
version = "unknown";
conclUrl = "    " + http_report_vuln_url(port: port, url: url, url_only: TRUE);

# nb: Some generic KB keys for active checks covering multiple devices
set_kb_item(name: "zyxel/device/detected", value: TRUE);
set_kb_item(name: "zyxel/device/http/detected", value: TRUE);

set_kb_item(name: "zyxel/router/detected", value: TRUE);
set_kb_item(name: "zyxel/router/http/detected", value: TRUE);
set_kb_item(name: "zyxel/router/http/port", value: port);

# id="MODEL_NAME" value="VMG1312-T20B"
# id="MODEL_NAME" value="PMG5317-T20A"
mod = eregmatch(pattern: 'id="MODEL_NAME"\\s+value="([^"]+)"', string: res);
if (isnull(mod[1])) {
  # <title>.::Welcome to SBG3300::.</title>
  mod = eregmatch(pattern: "Welcome to (SBG[0-9]+)", string: res);
  if (isnull(mod[1])) {
    url = "/getBasicInformation";
    info_res = http_get_cache(port: port, item: url);

    if (info_res && info_res =~ "^HTTP/1\.[01] [0-9]+") {
      # {"result":"ZCFG_SUCCESS","ModelName":"EX5501-B0","SoftwareVersion":"V5.15(ABRY.1)C0","CurrentLanguage":"en","AvailableLanguages":"en","RememberPassword":0}
      mod = eregmatch(pattern: '"ModelName"\\s*:\\s*"([^"]+)"', string: info_res);
    }
  }
}

if (!isnull(mod[1])) {
  model = mod[1];
  concluded = "    Model:   " + mod[0];
  if (url >!< conclUrl)
    conclUrl += '\n    ' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
}

# id="FIRMWARE_VIRSION" value="V5.30(ABUA.0)b6"
# id="FIRMWARE_VIRSION" value="V5.21(ABCI.6)C0"
vers = eregmatch(pattern: 'id="FIRMWARE_VIRSION"\\s+value="V([^"]+)"', string: res);
if (isnull(vers[1]) && info_res && info_res =~ "^HTTP/1\.[01] [0-9]+")
  # "SoftwareVersion":"V1.00(ABUV.6)b2_E0"
  # "SoftwareVersion":"1.00(ABQY.3)C0"
  vers = eregmatch(pattern: '"SoftwareVersion"\\s*:\\s*"V?([^"]+)"', string: info_res);

if (!isnull(vers[1])) {
  version = vers[1];
  concluded += '\n    Version: ' + vers[0];
  if (url >!< conclUrl)
    concUrl += '\n    ' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
}

set_kb_item(name: "zyxel/router/http/" + port + "/version", value: version);
set_kb_item(name: "zyxel/router/http/" + port + "/model", value: model);
set_kb_item(name: "zyxel/router/http/" + port + "/concludedUrl", value: conclUrl);
if (concluded)
  set_kb_item(name: "zyxel/router/http/" + port + "/concluded", value: concluded);

exit(0);
